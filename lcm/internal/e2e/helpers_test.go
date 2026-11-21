package e2e

import (
	"crypto/ecdsa"

	"zir/lcm/internal/crypto/jws"
)

func jwsVerify(k *ecdsa.PublicKey, msg, sig []byte) bool { return jws.VerifyRaw(k, msg, sig) }
