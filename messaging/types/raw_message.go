package types

import (
	"errors"
)

type CommKeyExMsgType uint8

const (
	KeyExMsgNone  CommKeyExMsgType = 0
	KeyExMsgReuse CommKeyExMsgType = 1
	KeyExMsgRekey CommKeyExMsgType = 2
)

// MessagePriority determines the ordering for publishing  message
type MessagePriority = int

var (
	LowPriority    MessagePriority = 0
	NormalPriority MessagePriority = 1
	HighPriority   MessagePriority = 2
)

type RawMessageConfirmation struct {
	// DataSyncID is the ID of the datasync message sent
	DataSyncID []byte
	// MessageID is the message id of the message
	MessageID []byte
	// PublicKey is the compressed receiver public key
	PublicKey []byte
	// ConfirmedAt is the unix timestamp in seconds of when the message was confirmed
	ConfirmedAt int64
}

var ErrModifiedRawMessage = errors.New("modified rawMessage")
