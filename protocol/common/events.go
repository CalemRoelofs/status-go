package common

import "crypto/ecdsa"

type ScheduledMessageEvent struct {
	Recipient  *ecdsa.PublicKey
	RawMessage *RawMessage
}
