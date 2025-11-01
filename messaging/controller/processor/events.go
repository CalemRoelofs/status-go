package processor

import "crypto/ecdsa"

type DeviceNotFound struct {
	PublicKey *ecdsa.PublicKey
}
