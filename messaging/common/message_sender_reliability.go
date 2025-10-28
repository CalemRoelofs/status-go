package common

import (
	"crypto/ecdsa"
	"encoding/hex"

	"github.com/pkg/errors"
	"go.uber.org/zap"

	cryptotypes "github.com/status-im/status-go/crypto/types"
	messagingtypes "github.com/status-im/status-go/messaging/types"
)

var errReliabilityNotStarted = errors.New("reliability not started")

func (s *MessageSender) StartReliability() error {
	return s.csender.Start()
}

func (s *MessageSender) StopReliability() {
	s.csender.Stop()
}

func (s *MessageSender) ReportUserOnline(publicKey *ecdsa.PublicKey, eventTime uint64) {
	s.reliability.ReportPeerOnline(publicKey, eventTime)
}

// handleReliabilityLayer tries to unwrap message as datasync one and in case of success
// returns cloned messages with replaced payloads
func (s *MessageSender) handleReliabilityLayer(m *messagingtypes.Message) ([]*messagingtypes.Message, []cryptotypes.HexBytes, error) {
	if !s.reliability.Started() {
		return nil, nil, errReliabilityNotStarted
	}

	datasyncMessage, err := s.reliability.UnwrapAndAcknowledgeMessage(
		m.SigPubKey(),
		m.EncryptionLayer.Payload,
	)
	if err != nil {
		return nil, nil, err
	}

	var statusMessages []*messagingtypes.Message
	for _, ds := range datasyncMessage.Messages {
		message, err := m.Clone()
		if err != nil {
			return nil, nil, err
		}
		message.EncryptionLayer.Payload = ds.Body
		statusMessages = append(statusMessages, message)
	}

	ackedMessageIDs := make([]cryptotypes.HexBytes, 0, len(datasyncMessage.Acks))
	for _, ack := range datasyncMessage.Acks {
		messageIDBytes, err := s.persistence.MarkAsConfirmed(ack, true)
		if err != nil {
			s.logger.Info("got datasync acknowledge for message we don't have in db", zap.String("ack", hex.EncodeToString(ack)))
			continue
		}

		s.transport.ConfirmMessageDelivered(messageIDBytes.String())

		ackedMessageIDs = append(ackedMessageIDs, messageIDBytes)
	}

	return statusMessages, ackedMessageIDs, nil
}
