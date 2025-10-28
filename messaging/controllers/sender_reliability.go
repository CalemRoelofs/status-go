package controllers

import (
	"context"
	"crypto/ecdsa"

	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/status-im/status-go/crypto"
	cryptotypes "github.com/status-im/status-go/crypto/types"
	"github.com/status-im/status-go/pkg/pubsub"
)

var errReliabilityNotStarted = errors.New("reliability not started")

func (s *Sender) StartReliability() error {
	return s.reliability.Start(s.sendPrivateReliability)
}

func (s *Sender) StopReliability() {
	s.reliability.Stop()
}

func (s *Sender) scheduleReliableSend(recipient *ecdsa.PublicKey, message []byte) ([]byte, error) {
	if !s.reliability.Started() {
		return nil, errReliabilityNotStarted
	}

	datasyncID, err := s.reliability.WrapAndQueueMessageForDispatch(recipient, message)
	if err != nil {
		return nil, err
	}

	return datasyncID[:], nil
}

func (s *Sender) sendPrivateReliability(recipient *ecdsa.PublicKey, wrappedPayload []byte, messages [][]byte) error {
	messageIDs := make([]cryptotypes.HexBytes, 0, len(messages))
	for _, msgPayload := range messages {
		messageIDs = append(messageIDs, messageID(&s.identity.PublicKey, msgPayload))
	}

	logger := s.logger.Named("sendPrivateReliability").With(
		zap.Stringers("messageIDs", messageIDs),
		zap.String("recipient", crypto.PubkeyToHex(recipient)),
	)

	spec, err := s.buildEncryptedMessage(s.identity, recipient, wrappedPayload)
	if err != nil {
		return errors.Wrap(err, "failed to build encrypted message")
	}

	payload, sharedSecretKey, err := s.processAndMarshalMessageSpec(spec)
	if err != nil {
		return errors.Wrap(err, "failed to process and marshal message spec")
	}

	hashes, wakuMessages, err := s.sendPrivate(context.Background(), logger, sendPrivateParams{
		recipient:       recipient,
		payload:         payload,
		sharedSecretKey: sharedSecretKey,
	})
	if err != nil {
		return errors.Wrap(err, "failed to send private message")
	}

	logger.Debug("sent-message",
		zap.Strings("hashes", cryptotypes.EncodeHexes(hashes)),
	)

	byteMessageIDs := make([][]byte, len(messageIDs))
	for i, id := range messageIDs {
		byteMessageIDs[i] = []byte(id)
	}

	s.transport.TrackMany(byteMessageIDs, hashes, wakuMessages)

	pubsub.Publish(s.publisher, SentMessage{
		Private:                true,
		Recipient:              recipient,
		RecipientInstallations: spec.Installations,
		MessageIDs:             byteMessageIDs,
	})

	return nil
}
