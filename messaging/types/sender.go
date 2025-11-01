package types

import "crypto/ecdsa"

type SendPublicParams struct {
	Sender              *ecdsa.PublicKey
	Payload             []byte
	PubsubTopic         string
	ContentTopic        string
	SkipEncryptionLayer bool
	Ephemeral           bool
	Priority            *MessagePriority
	HashRatchet         *SendPublicHashRatchetParams
	CommunityPublicKey  *ecdsa.PublicKey
}

type SendPublicHashRatchetParams struct {
	Encrypt   bool
	GroupID   []byte
	KeyExType CommKeyExMsgType
	Members   []*ecdsa.PublicKey
}

type SendPrivateParams struct {
	Sender              *ecdsa.PrivateKey
	Recipient           *ecdsa.PublicKey
	Payload             []byte
	PubsubTopic         string
	WithReliability     bool
	SendWithDH          bool
	SkipEncryptionLayer bool
	SendOnPersonalTopic bool
	HashRatchetGroupID  []byte
}
