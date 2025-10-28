package common

import (
	"context"
	"crypto/ecdsa"
	"math/rand"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
	mvdsnode "github.com/status-im/mvds/node"
	"go.uber.org/zap"

	"github.com/ethereum/go-ethereum/common/hexutil"

	gocommon "github.com/status-im/status-go/common"
	utils "github.com/status-im/status-go/common"
	"github.com/status-im/status-go/crypto"
	cryptotypes "github.com/status-im/status-go/crypto/types"
	ethtypes "github.com/status-im/status-go/eth-node/types"
	"github.com/status-im/status-go/messaging/adapters"
	"github.com/status-im/status-go/messaging/controllers"
	messagingevents "github.com/status-im/status-go/messaging/events"
	"github.com/status-im/status-go/messaging/layers/encryption"
	"github.com/status-im/status-go/messaging/layers/encryption/sharedsecret"
	"github.com/status-im/status-go/messaging/layers/reliability"
	"github.com/status-im/status-go/messaging/layers/segmentation"
	"github.com/status-im/status-go/messaging/layers/transport"
	messagingtypes "github.com/status-im/status-go/messaging/types"
	"github.com/status-im/status-go/pkg/pubsub"
	"github.com/status-im/status-go/protocol/protobuf"
	v1protocol "github.com/status-im/status-go/protocol/v1"
)

// Whisper message properties.
const (
	maxMessageSenderEphemeralKeys = 3
)

type MessageSender struct {
	identity    *ecdsa.PrivateKey
	transport   *transport.Transport
	segmenter   *segmentation.Segmenter
	protocol    *encryption.Protocol
	reliability *reliability.Reliability
	logger      *zap.Logger
	persistence messagingtypes.MessageSenderPersistence
	publisher   *pubsub.Publisher

	// ephemeralKeys is a map that contains the ephemeral keys of the client, used
	// to decrypt messages
	ephemeralKeys      map[string]*ecdsa.PrivateKey
	ephemeralKeysMutex sync.Mutex

	csender *controllers.Sender

	wg   sync.WaitGroup
	quit chan struct{}
}

func NewMessageSender(
	identity *ecdsa.PrivateKey,
	persistence messagingtypes.MessageSenderPersistence,
	mvdsPersistence mvdsnode.Persistence,
	segmentationPersistence segmentation.Persistence,
	transport *transport.Transport,
	encryptor *encryption.Protocol,
	logger *zap.Logger,
) (*MessageSender, error) {
	logger = logger.Named("message_sender")

	p := &MessageSender{
		identity:      identity,
		transport:     transport,
		segmenter:     segmentation.NewSegmenter(segmentationPersistence, logger),
		protocol:      encryptor,
		reliability:   reliability.NewReliability(mvdsPersistence, identity, logger),
		persistence:   persistence,
		publisher:     pubsub.NewPublisher(),
		logger:        logger,
		ephemeralKeys: make(map[string]*ecdsa.PrivateKey),
		quit:          make(chan struct{}),
	}

	p.csender = controllers.NewSender(
		identity,
		transport,
		p.segmenter,
		p.protocol,
		p.reliability,
		logger,
	)

	return p, nil
}

func (s *MessageSender) Start() error {
	subscriptions, err := s.protocol.Start(s.identity)
	if err != nil {
		return err
	}

	// handle stored shared secrets
	err = s.HandleSharedSecrets(subscriptions.SharedSecrets)
	if err != nil {
		return err
	}

	s.startCleanupLoop("messageSegmentsCleanupLoop", s.cleanupSegments)
	s.startCleanupLoop("hashRatchetEncryptedMessagesCleanupLoop", s.cleanupHashRatchetEncryptedMessages)

	err = s.csender.Start()
	if err != nil {
		return err
	}

	go func() {
		defer gocommon.LogOnPanic()

		s.wg.Add(1)
		defer s.wg.Done()

		scheduledSendSub, scheduledSendUnsub := pubsub.Subscribe[controllers.ScheduledReliableSend](s.csender.Publisher(), 100)
		defer scheduledSendUnsub()

		sentSub, sentUnsub := pubsub.Subscribe[controllers.SentMessage](s.csender.Publisher(), 100)
		defer sentUnsub()

		for {
			select {
			case scheduledSend := <-scheduledSendSub:
				// We don't need to receive confirmations from our own devices
				if !crypto.IsPubKeyEqual(scheduledSend.Recipient, &s.identity.PublicKey) {
					confirmation := &messagingtypes.RawMessageConfirmation{
						PublicKey:  crypto.CompressPubkey(scheduledSend.Recipient),
						MessageID:  scheduledSend.MessageID,
						DataSyncID: scheduledSend.ReliabilityMessageID,
					}

					err = s.persistence.InsertPendingConfirmation(confirmation)
					if err != nil {
						s.logger.Error("failed to insert pending confirmation", zap.Error(err))
					}
				}
			case messageSent := <-sentSub:
				var pubkey *ecdsa.PublicKey
				if messageSent.Private {
					pubkey = messageSent.Recipient
				}
				s.notifyOnSentMessage(&messagingevents.SentMessage{
					PublicKey: pubkey,
					Spec: &encryption.ProtocolMessageSpec{
						Installations: messageSent.RecipientInstallations,
					},
					MessageIDs: messageSent.MessageIDs,
				})
			case <-s.quit:
				return
			}
		}
	}()

	return nil
}

func (s *MessageSender) Stop() error {
	close(s.quit)

	s.publisher.Close()
	s.csender.Stop()

	err := s.transport.Stop()
	if err != nil {
		return err
	}

	func() {
		s.wg.Add(1)
		defer s.wg.Done()

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		err := s.transport.ResetFilters(ctx)
		if err != nil {
			s.logger.Warn("could not reset filters", zap.Error(err))
		}
	}()

	err = s.protocol.Stop()
	if err != nil {
		return err
	}

	s.wg.Wait()

	return nil
}

// SendPrivate takes encoded data, encrypts it and sends through the wire.
func (s *MessageSender) SendPrivate(
	ctx context.Context,
	recipient *ecdsa.PublicKey,
	rawMessage *messagingtypes.RawMessage,
) ([]byte, error) {
	// Currently we don't support sending through datasync and setting custom waku fields,
	// as the datasync interface is not rich enough to propagate that information, so we
	// would have to add some complexity to handle this.
	if rawMessage.ResendType == messagingtypes.ResendTypeDataSync && (rawMessage.Sender != nil || rawMessage.SkipEncryptionLayer || rawMessage.SendOnPersonalTopic) {
		return nil, errors.New("setting identity, skip-encryption or personal topic and datasync not supported")
	}

	rawMessage.Recipients = []*ecdsa.PublicKey{recipient}
	return s.sendPrivate(ctx, rawMessage)
}

// SendCommunityMessage takes encoded data, encrypts it and sends through the wire
// using the community topic and their key
func (s *MessageSender) SendCommunityMessage(
	ctx context.Context,
	rawMessage *messagingtypes.RawMessage,
) ([]byte, error) {
	s.logger.Debug(
		"sending a community message",
		zap.String("communityId", cryptotypes.EncodeHex(rawMessage.CommunityID)),
		zap.String("site", "SendCommunityMessage"),
	)
	rawMessage.Sender = s.identity

	return s.sendCommunity(ctx, rawMessage)
}

// SendGroup takes encoded data, encrypts it and sends through the wire,
// always return the messageID
func (s *MessageSender) SendGroup(
	ctx context.Context,
	recipients []*ecdsa.PublicKey,
	rawMessage *messagingtypes.RawMessage,
) ([]byte, error) {
	rawMessage.Recipients = recipients
	return s.sendPrivate(ctx, rawMessage)
}

func (s *MessageSender) getMessageID(rawMessage *messagingtypes.RawMessage) (cryptotypes.HexBytes, error) {
	wrappedMessage, err := s.wrapIntoAppLayerMessage(rawMessage)
	if err != nil {
		return nil, errors.Wrap(err, "failed to wrap message")
	}

	messageID := messagingtypes.MessageID(&rawMessage.Sender.PublicKey, wrappedMessage)
	return messageID, nil
}

func (s *MessageSender) ValidateRawMessage(rawMessage *messagingtypes.RawMessage) error {
	id, err := s.getMessageID(rawMessage)
	if err != nil {
		return err
	}
	messageID := cryptotypes.EncodeHex(id)

	return s.validateMessageID(messageID, rawMessage)
}

func (s *MessageSender) validateMessageID(messageID string, rawMessage *messagingtypes.RawMessage) error {
	if len(rawMessage.ID) > 0 && rawMessage.ID != messageID {
		s.logger.Error("failed to validate message ID, RawMessage content was modified",
			zap.String("prevID", rawMessage.ID),
			zap.String("newID", messageID),
			zap.Any("contentType", rawMessage.MessageType))
		return messagingtypes.ErrModifiedRawMessage
	}
	return nil
}

func (s *MessageSender) setMessageID(messageID cryptotypes.HexBytes, rawMessage *messagingtypes.RawMessage) error {
	msgID := cryptotypes.EncodeHex(messageID)

	if err := s.validateMessageID(msgID, rawMessage); err != nil {
		return err
	}

	rawMessage.ID = msgID
	return nil
}

func shouldCommunityMessageBeEncrypted(msgType protobuf.ApplicationMetadataMessage_Type) bool {
	return msgType == protobuf.ApplicationMetadataMessage_CHAT_MESSAGE ||
		msgType == protobuf.ApplicationMetadataMessage_EDIT_MESSAGE ||
		msgType == protobuf.ApplicationMetadataMessage_DELETE_MESSAGE ||
		msgType == protobuf.ApplicationMetadataMessage_PIN_MESSAGE ||
		msgType == protobuf.ApplicationMetadataMessage_EMOJI_REACTION
}

// sendCommunity sends a message that's to be sent in a community
// If it's a chat message, it will go to the respective topic derived by the
// chat id, if it's not a chat message, it will go to the community topic.
func (s *MessageSender) sendCommunity(
	ctx context.Context,
	rawMessage *messagingtypes.RawMessage,
) ([]byte, error) {
	if rawMessage.Sender == nil {
		rawMessage.Sender = s.identity
	}

	messageID, err := s.getMessageID(rawMessage)
	if err != nil {
		return nil, err
	}

	logger := s.logger.Named("sendCommunity").With(
		zap.Stringer("messageID", messageID),
		zap.String("communityID", cryptotypes.EncodeHex(rawMessage.CommunityID)),
		zap.String("sender", crypto.PubkeyToHex(&rawMessage.Sender.PublicKey)),
	)

	if err = s.setMessageID(messageID, rawMessage); err != nil {
		return nil, err
	}

	if rawMessage.BeforeDispatch != nil {
		if err := rawMessage.BeforeDispatch(rawMessage); err != nil {
			return nil, err
		}
	}
	// Notify before dispatching, otherwise the dispatch subscription might happen
	// earlier than the scheduled
	s.notifyOnScheduledMessage(nil, rawMessage)

	// We want to fill up old keys to a given users
	if rawMessage.CommunityKeyExMsgType == messagingtypes.KeyExMsgReuse {
		return messageID, s.csender.SendPrivateHashRatchetKeys(ctx, rawMessage.Recipients, rawMessage.HashRatchetGroupID)
	}

	wrappedMessage, err := s.wrapIntoAppLayerMessage(rawMessage)
	if err != nil {
		return nil, err
	}

	hashRatchetParams := &controllers.HashRatchetParams{
		Encrypt:   false,
		GroupID:   rawMessage.HashRatchetGroupID,
		KeyExType: rawMessage.CommunityKeyExMsgType,
		Members:   rawMessage.Recipients,
	}

	// If it's a chat message, we send it on the community chat topic
	if shouldCommunityMessageBeEncrypted(rawMessage.MessageType) {
		if len(rawMessage.HashRatchetGroupID) == 0 {
			return nil, errors.New("missing hash ratchet group ID for community encrypted message")
		}

		hashRatchetParams.Encrypt = true

		err = s.csender.SendPublic(ctx, controllers.SendPublicParams{
			Sender:       &rawMessage.Sender.PublicKey,
			Payload:      wrappedMessage,
			PubsubTopic:  rawMessage.PubsubTopic,
			ContentTopic: rawMessage.ContentTopic,
			HashRatchet:  hashRatchetParams,
		})

	} else {
		var pubkey *ecdsa.PublicKey
		pubkey, err = crypto.DecompressPubkey(rawMessage.CommunityID)
		if err != nil {
			return nil, errors.Wrap(err, "failed to decompress pubkey")
		}

		err = s.csender.SendPublic(ctx, controllers.SendPublicParams{
			Sender:             &rawMessage.Sender.PublicKey,
			Payload:            wrappedMessage,
			PubsubTopic:        rawMessage.PubsubTopic,
			ContentTopic:       rawMessage.ContentTopic,
			HashRatchet:        hashRatchetParams,
			CommunityPublicKey: pubkey,
		})
	}

	if err != nil {
		return nil, errors.Wrap(err, "failed to send community message")
	}

	logger.Debug("sent-message",
		zap.String("messageType", "community"),
		zap.Any("contentType", rawMessage.MessageType),
	)

	s.notifyOnSentRawMessage(rawMessage)

	return messageID, nil
}

// sendPrivate sends data to the recipient identifying with a given public key.
func (s *MessageSender) sendPrivate(
	ctx context.Context,
	rawMessage *messagingtypes.RawMessage,
) ([]byte, error) {
	if rawMessage.Sender == nil {
		rawMessage.Sender = s.identity
	}

	var wrappedMessage []byte
	var err error
	if rawMessage.SkipApplicationWrap {
		wrappedMessage = rawMessage.Payload
	} else {
		wrappedMessage, err = s.wrapIntoAppLayerMessage(rawMessage)
		if err != nil {
			return nil, errors.Wrap(err, "failed to wrap message")
		}
	}

	messageID := messagingtypes.MessageID(&rawMessage.Sender.PublicKey, wrappedMessage)

	logger := s.logger.Named("sendPrivate").With(
		zap.Stringer("messageID", messageID),
	)

	logger.Debug("sending private message",
		zap.Strings("recipients", crypto.PubkeysToHex(rawMessage.Recipients)),
		zap.Stringer("contentType", rawMessage.MessageType),
	)

	if err = s.setMessageID(messageID, rawMessage); err != nil {
		return nil, err
	}

	if rawMessage.BeforeDispatch != nil {
		if err := rawMessage.BeforeDispatch(rawMessage); err != nil {
			return nil, err
		}
	}

	var hashRatchetGroupID []byte
	if rawMessage.CommunityKeyExMsgType == messagingtypes.KeyExMsgReuse {
		hashRatchetGroupID = rawMessage.HashRatchetGroupID
	}

	for _, recipient := range rawMessage.Recipients {
		s.notifyOnScheduledMessage(recipient, rawMessage)

		err = s.csender.SendPrivate(ctx, controllers.SendPrivateParams{
			Sender:              rawMessage.Sender,
			Recipient:           recipient,
			Payload:             wrappedMessage,
			PubsubTopic:         rawMessage.PubsubTopic,
			WithReliability:     rawMessage.ResendType == messagingtypes.ResendTypeDataSync,
			SkipEncryptionLayer: rawMessage.SkipEncryptionLayer,
			SendOnPersonalTopic: rawMessage.SendOnPersonalTopic,
			HashRatchetGroupID:  hashRatchetGroupID,
		})
		if err != nil {
			return nil, errors.Wrap(err, "failed to send private message")
		}
	}

	s.notifyOnSentRawMessage(rawMessage)

	return messageID, nil
}

// sendPairInstallation sends data to the recipients, using DH
func (s *MessageSender) SendPairInstallation(
	ctx context.Context,
	recipient *ecdsa.PublicKey,
	rawMessage messagingtypes.RawMessage,
) ([]byte, error) {
	s.logger.Debug("sending private message", zap.String("recipient", cryptotypes.EncodeHex(crypto.FromECDSAPub(recipient))))

	wrappedMessage, err := s.wrapIntoAppLayerMessage(&rawMessage)
	if err != nil {
		return nil, errors.Wrap(err, "failed to wrap message")
	}

	err = s.csender.SendPrivate(ctx, controllers.SendPrivateParams{
		Sender:     s.identity,
		Recipient:  recipient,
		Payload:    wrappedMessage,
		SendWithDH: true,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to send private DH message")
	}

	messageID := messagingtypes.MessageID(&s.identity.PublicKey, wrappedMessage)

	s.notifyOnSentRawMessage(&rawMessage)

	return messageID, nil
}

// SendPublic takes encoded data, encrypts it and sends through the wire.
func (s *MessageSender) SendPublic(
	ctx context.Context,
	chatName string,
	rawMessage messagingtypes.RawMessage,
) ([]byte, error) {
	if rawMessage.Sender == nil {
		rawMessage.Sender = s.identity
	}

	if len(rawMessage.ContentTopic) == 0 {
		rawMessage.ContentTopic = chatName
	}

	var wrappedMessage []byte
	var err error
	if rawMessage.SkipApplicationWrap {
		wrappedMessage = rawMessage.Payload
	} else {
		wrappedMessage, err = s.wrapIntoAppLayerMessage(&rawMessage)
		if err != nil {
			return nil, errors.Wrap(err, "failed to wrap message")
		}
	}

	messageID := messagingtypes.MessageID(&rawMessage.Sender.PublicKey, wrappedMessage)
	if err = s.setMessageID(messageID, &rawMessage); err != nil {
		return nil, err
	}

	logger := s.logger.Named("sendPublic").With(
		zap.Stringer("messageID", messageID),
	)

	if rawMessage.BeforeDispatch != nil {
		if err := rawMessage.BeforeDispatch(&rawMessage); err != nil {
			return nil, err
		}
	}

	// notify before dispatching
	s.notifyOnScheduledMessage(nil, &rawMessage)

	var hashRatchetParams *controllers.HashRatchetParams
	if len(rawMessage.HashRatchetGroupID) != 0 {
		hashRatchetParams = &controllers.HashRatchetParams{
			Encrypt:   false,
			GroupID:   rawMessage.HashRatchetGroupID,
			KeyExType: rawMessage.CommunityKeyExMsgType,
			Members:   rawMessage.Recipients,
		}
	}

	err = s.csender.SendPublic(ctx, controllers.SendPublicParams{
		Sender:              &rawMessage.Sender.PublicKey,
		Payload:             wrappedMessage,
		PubsubTopic:         rawMessage.PubsubTopic,
		ContentTopic:        rawMessage.ContentTopic,
		SkipEncryptionLayer: rawMessage.SkipEncryptionLayer,
		Ephemeral:           rawMessage.Ephemeral,
		Priority:            rawMessage.Priority,
		HashRatchet:         hashRatchetParams,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to send public message")
	}

	logger.Debug("sent-message",
		zap.Any("contentType", rawMessage.MessageType),
		zap.String("messageType", "public"),
	)

	s.notifyOnSentRawMessage(&rawMessage)

	return messageID, nil
}

// HandleMessages expects a whisper message as input, and it will go through
// a series of transformations until the message is parsed into an application
// layer message, or in case of Raw methods, the processing stops at the layer
// before.
// It returns an error only if the processing of required steps failed.
func (s *MessageSender) HandleMessages(msg *messagingtypes.ReceivedMessage) (*messagingtypes.HandleMessageResponse, error) {
	logger := s.logger.With(zap.String("site", "HandleMessages"))
	hlogger := logger.With(zap.String("hash", cryptotypes.HexBytes(msg.Hash).String()))

	response, err := s.handleMessage(msg)
	if err != nil {
		// Hash ratchet with a group id not found yet, save the message for future processing
		if err == encryption.ErrHashRatchetGroupIDNotFound && len(response.Message.EncryptionLayer.HashRatchetInfo) == 1 {
			info := response.Message.EncryptionLayer.HashRatchetInfo[0]
			return nil, s.persistence.SaveHashRatchetMessage(info.GroupID, info.KeyID, msg)
		}

		return nil, err
	}

	if response == nil {
		return nil, nil
	}

	// Process queued hash ratchet messages
	for _, hashRatchetInfo := range response.Message.EncryptionLayer.HashRatchetInfo {
		messages, err := s.persistence.GetHashRatchetMessages(hashRatchetInfo.KeyID)
		if err != nil {
			return nil, err
		}

		var processedIds [][]byte
		for _, message := range messages {
			hlogger.Info("handling out of order encrypted messages", zap.String("hash", cryptotypes.Bytes2Hex(message.Hash)))
			r, err := s.handleMessage(message)
			if err != nil {
				hlogger.Debug("failed to handle hash ratchet message", zap.Error(err))
				continue
			}
			response.ReliabilityMessages = append(response.toPublicResponse().StatusMessages, r.Messages()...)
			response.AckedMessageIDs = append(response.AckedMessageIDs, r.AckedMessageIDs...)

			processedIds = append(processedIds, message.Hash)
		}

		err = s.persistence.DeleteHashRatchetMessages(processedIds)
		if err != nil {
			s.logger.Warn("failed to delete hash ratchet messages", zap.Error(err))
			return nil, err
		}
	}

	return response.toPublicResponse(), nil
}

func (h *handleMessageResponse) toPublicResponse() *messagingtypes.HandleMessageResponse {
	return &messagingtypes.HandleMessageResponse{
		StatusMessages:  h.Messages(),
		AckedMessageIDs: h.AckedMessageIDs,
	}
}

type handleMessageResponse struct {
	Message             *messagingtypes.Message
	ReliabilityMessages []*messagingtypes.Message
	AckedMessageIDs     []cryptotypes.HexBytes
}

func (h *handleMessageResponse) Messages() []*messagingtypes.Message {
	if len(h.ReliabilityMessages) > 0 {
		return h.ReliabilityMessages
	}
	return []*messagingtypes.Message{h.Message}
}

func (s *MessageSender) handleMessage(receivedMsg *messagingtypes.ReceivedMessage) (*handleMessageResponse, error) {
	hlogger := s.logger.Named("handleMessage").With(zap.String("hash", cryptotypes.EncodeHex(receivedMsg.Hash)))

	message := &messagingtypes.Message{}

	response := &handleMessageResponse{
		Message:             message,
		ReliabilityMessages: []*messagingtypes.Message{},
		AckedMessageIDs:     []cryptotypes.HexBytes{},
	}

	err := populateMessageTransportLayer(message, receivedMsg)
	if err != nil {
		hlogger.Error("failed to handle transport layer message", zap.Error(err))
		return nil, err
	}

	isSegmentMessage, completed, err := s.handleSegmentationLayer(message)
	if err != nil {
		return nil, err
	}

	// Segments not completed yet, stop processing
	if isSegmentMessage && !completed {
		return nil, nil
	}

	err = s.handleEncryptionLayer(context.Background(), message)
	if err != nil {
		hlogger.Debug("failed to handle an encryption message", zap.Error(err))

		// Hash ratchet with a group id not found yet, stop processing
		if err == encryption.ErrHashRatchetGroupIDNotFound {
			return response, err
		}
	}

	statusMessages, ackedMessageIDs, err := s.handleReliabilityLayer(message)
	if err == nil {
		response.ReliabilityMessages = append(response.ReliabilityMessages, statusMessages...)
		response.AckedMessageIDs = append(response.AckedMessageIDs, ackedMessageIDs...)
	} else {
		hlogger.Debug("failed to handle datasync message", zap.Error(err))
	}

	for _, msg := range response.Messages() {
		err := populateMessageApplicationLayer(msg)
		if err != nil {
			hlogger.Error("failed to handle application metadata layer message", zap.Error(err))
		}
		s.logger.Debug("calculated ID for envelope",
			zap.String("envelopeHash", hexutil.Encode(msg.TransportLayer.Hash)),
			zap.String("messageId", hexutil.Encode(msg.ApplicationLayer.ID)),
		)
	}

	return response, nil
}

// fetchDecryptionKey returns the private key associated with this public key, and returns true if it's an ephemeral key
func (s *MessageSender) fetchDecryptionKey(destination *ecdsa.PublicKey) (*ecdsa.PrivateKey, bool) {
	destinationID := cryptotypes.EncodeHex(crypto.FromECDSAPub(destination))

	s.ephemeralKeysMutex.Lock()
	decryptionKey, ok := s.ephemeralKeys[destinationID]
	s.ephemeralKeysMutex.Unlock()

	// the key is not there, fallback on identity
	if !ok {
		return s.identity, false
	}
	return decryptionKey, true
}

func (s *MessageSender) handleEncryptionLayer(ctx context.Context, message *messagingtypes.Message) error {
	logger := s.logger.Named("handleEncryptionLayer")
	publicKey := message.SigPubKey()

	// if it's an ephemeral key, we don't negotiate a topic
	decryptionKey, skipNegotiation := s.fetchDecryptionKey(message.TransportLayer.Dst)

	// As we handle non-encrypted messages, we make sure that DecryptPayload
	// is set regardless of whether this step is successful
	message.EncryptionLayer.Payload = message.TransportLayer.Payload

	// Nothing to do
	if skipNegotiation {
		return nil
	}

	var protocolMessage encryption.ProtocolMessage
	err := proto.Unmarshal(message.TransportLayer.Payload, &protocolMessage)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal ProtocolMessage")
	}

	response, err := s.protocol.HandleMessage(
		decryptionKey,
		publicKey,
		&protocolMessage,
		message.TransportLayer.Hash,
	)

	switch err {
	case nil:
		message.EncryptionLayer.Payload = response.DecryptedMessage
		message.EncryptionLayer.Installations = adapters.FromEncryptionInstallations(response.Installations)
		message.EncryptionLayer.HashRatchetInfo = adapters.FromEncryptionHashRatchets(response.HashRatchetInfo)

		err := s.HandleSharedSecrets(response.SharedSecrets)
		if err != nil {
			logger.Error("failed to handle shared secrets", zap.Error(err))
		}
	case encryption.ErrHashRatchetGroupIDNotFound:
		if response != nil {
			message.EncryptionLayer.HashRatchetInfo = adapters.FromEncryptionHashRatchets(response.HashRatchetInfo)
		}
	case encryption.ErrDeviceNotFound:
		err := s.csender.SendPrivateAdvertiseBundle(ctx, publicKey)
		if err != nil {
			logger.Error("failed to handle ErrDeviceNotFound", zap.Error(err))
		}
	}

	return err
}

func (s *MessageSender) wrapIntoAppLayerMessage(rawMessage *messagingtypes.RawMessage) ([]byte, error) {
	wrappedMessage, err := v1protocol.WrapIntoAppLayerMessage(rawMessage.Payload, rawMessage.MessageType, rawMessage.Sender)
	if err != nil {
		return nil, errors.Wrap(err, "failed to wrap message")
	}
	return wrappedMessage, nil
}

func (s *MessageSender) notifyOnSentMessage(sentMessage *messagingevents.SentMessage) {
	pubsub.Publish(s.publisher, messagingevents.MessageEvent{
		Type:        messagingevents.MessageSent,
		SentMessage: sentMessage,
	})
}

func (s *MessageSender) notifyOnSentRawMessage(rawMessage *messagingtypes.RawMessage) {
	pubsub.Publish(s.publisher, messagingevents.MessageEvent{
		Type:       messagingevents.RawMessageSent,
		RawMessage: rawMessage,
	})
}

func (s *MessageSender) notifyOnScheduledMessage(recipient *ecdsa.PublicKey, message *messagingtypes.RawMessage) {
	pubsub.Publish(s.publisher, messagingevents.MessageEvent{
		Type:       messagingevents.MessageScheduled,
		Recipient:  recipient,
		RawMessage: message,
	})
}

func (s *MessageSender) JoinPublic(id string) (*transport.Filter, error) {
	filter, err := s.transport.JoinPublic(id)
	if err != nil {
		return nil, err
	}
	return filter, nil
}

func (s *MessageSender) getRandomEphemeralKey() *ecdsa.PrivateKey {
	k := rand.Intn(len(s.ephemeralKeys)) //nolint: gosec
	for _, key := range s.ephemeralKeys {
		if k == 0 {
			return key
		}
		k--
	}
	return nil
}

func (s *MessageSender) GetEphemeralKey() (*ecdsa.PrivateKey, error) {
	s.ephemeralKeysMutex.Lock()
	if len(s.ephemeralKeys) >= maxMessageSenderEphemeralKeys {
		s.ephemeralKeysMutex.Unlock()
		return s.getRandomEphemeralKey(), nil
	}
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		s.ephemeralKeysMutex.Unlock()
		return nil, err
	}

	s.ephemeralKeys[cryptotypes.EncodeHex(crypto.FromECDSAPub(&privateKey.PublicKey))] = privateKey
	s.ephemeralKeysMutex.Unlock()
	_, err = s.transport.LoadKeyFilters(privateKey)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func (s *MessageSender) SaveHashRatchetMessage(groupID []byte, keyID []byte, m *messagingtypes.ReceivedMessage) error {
	return s.persistence.SaveHashRatchetMessage(groupID, keyID, m)
}

// GetCurrentKeyForGroup returns the latest key timestampID belonging to a key group
func (s *MessageSender) GetCurrentKeyForGroup(groupID []byte) (*encryption.HashRatchetKeyCompatibility, error) {
	return s.protocol.GetCurrentKeyForGroup(groupID)
}

// GetKeyIDsForGroup returns a slice of key IDs belonging to a given group ID
func (s *MessageSender) GetKeysForGroup(groupID []byte) ([]*encryption.HashRatchetKeyCompatibility, error) {
	return s.protocol.GetKeysForGroup(groupID)
}

func (s *MessageSender) cleanupHashRatchetEncryptedMessages() error {
	monthAgo := time.Now().AddDate(0, -1, 0).Unix()

	err := s.persistence.DeleteHashRatchetMessagesOlderThan(monthAgo)
	if err != nil {
		return err
	}

	return nil
}

func (s *MessageSender) Publisher() *pubsub.Publisher {
	return s.publisher
}

func (s *MessageSender) HandleSharedSecrets(secrets []*sharedsecret.Secret) error {
	for _, secret := range secrets {
		fSecret := ethtypes.NegotiatedSecret{
			PublicKey: secret.Identity,
			Key:       secret.Key,
		}
		_, err := s.transport.ProcessNegotiatedSecret(fSecret)
		if err != nil {
			return err
		}
	}
	return nil
}

func populateMessageTransportLayer(m *messagingtypes.Message, msg *messagingtypes.ReceivedMessage) error {
	publicKey, err := crypto.UnmarshalPubkey(msg.Sig)
	if err != nil {
		return errors.Wrap(err, "failed to get signature")
	}

	m.TransportLayer.Message = msg
	m.TransportLayer.Hash = msg.Hash
	m.TransportLayer.SigPubKey = publicKey
	m.TransportLayer.Payload = msg.Payload

	if msg.Dst != nil {
		publicKey, err := crypto.UnmarshalPubkey(msg.Dst)
		if err != nil {
			return err
		}
		m.TransportLayer.Dst = publicKey
	}

	return nil
}

func populateMessageApplicationLayer(m *messagingtypes.Message) error {
	message, err := protobuf.Unmarshal(m.EncryptionLayer.Payload)
	if err != nil {
		return err
	}

	recoveredKey, err := utils.RecoverKey(message)
	if err != nil {
		return err
	}

	m.ApplicationLayer.SigPubKey = recoveredKey
	// Calculate ID using the wrapped record
	m.ApplicationLayer.ID = messagingtypes.MessageID(recoveredKey, m.EncryptionLayer.Payload)
	m.ApplicationLayer.Payload = message.Payload
	m.ApplicationLayer.Type = message.Type
	return nil
}

func (s *MessageSender) startCleanupLoop(name string, cleanupFunc func() error) {
	logger := s.logger.Named(name)

	go func() {
		defer gocommon.LogOnPanic()

		s.wg.Add(1)
		defer s.wg.Done()

		// Delay by a few minutes to minimize messenger's startup time
		var interval time.Duration = 5 * time.Minute
		for {
			select {
			case <-time.After(interval):
				// Set the regular interval after the first execution
				interval = 1 * time.Hour

				err := cleanupFunc()
				if err != nil {
					logger.Error("failed to cleanup", zap.Error(err))
				}

			case <-s.quit:
				return
			}
		}
	}()
}
