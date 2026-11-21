// Package signer owns the server's private keys. Keys live in the
// server_keys table encrypted with the master key; decrypted keys stay inside
// this package, and other packages only get operations (sign, open).
package signer

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"sort"
	"time"

	"zir/lcm/internal/crypto/ecies"
	"zir/lcm/internal/crypto/envelope"
	"zir/lcm/internal/crypto/espsig"
	"zir/lcm/internal/crypto/jws"
	"zir/lcm/internal/db"
)

type Purpose string

const (
	FwSign    Purpose = "fw_sign"   // RSA-3072, app/bootstrap images (Secure Boot V2 block)
	Manifest  Purpose = "manifest"  // ES256, update manifests
	Config    Purpose = "config"    // ES256, device configs
	EngToken  Purpose = "engtoken"  // ES256, engineer tokens
	WWW       Purpose = "www"       // ES256, .zwww containers
	Telemetry Purpose = "telemetry" // ECDH P-256, telemetry / passwords to the server
)

var AllPurposes = []Purpose{FwSign, Manifest, Config, EngToken, WWW, Telemetry}

type key struct {
	kid     string
	purpose Purpose
	active  bool
	rsa     *rsa.PrivateKey
	ec      *ecdsa.PrivateKey
}

type Signer struct {
	env    *envelope.Key
	byKid  map[string]*key
	active map[Purpose]*key
}

func aad(kid string) string { return "server_key:" + kid }

// Load reads all keys. It fails if a purpose has no active key: run
// `lcmctl init-keys` first.
func Load(ctx context.Context, q db.Q, env *envelope.Key) (*Signer, error) {
	s := &Signer{env: env, byKid: map[string]*key{}, active: map[Purpose]*key{}}
	rows, err := q.Query(ctx, `SELECT kid, purpose, alg, private_enc, active FROM server_keys`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var kid, purpose, alg string
		var enc []byte
		var active bool
		if err := rows.Scan(&kid, &purpose, &alg, &enc, &active); err != nil {
			return nil, err
		}
		der, err := env.Open(enc, aad(kid))
		if err != nil {
			return nil, fmt.Errorf("signer: key %s: %w", kid, err)
		}
		k := &key{kid: kid, purpose: Purpose(purpose), active: active}
		priv, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("signer: key %s: %w", kid, err)
		}
		switch p := priv.(type) {
		case *rsa.PrivateKey:
			k.rsa = p
		case *ecdsa.PrivateKey:
			k.ec = p
		default:
			return nil, fmt.Errorf("signer: key %s: unexpected type %T", kid, priv)
		}
		s.byKid[kid] = k
		if active {
			s.active[k.purpose] = k
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, p := range AllPurposes {
		if s.active[p] == nil {
			return nil, fmt.Errorf("signer: no active %s key (run `lcmctl init-keys`)", p)
		}
	}
	return s, nil
}

// Init generates keys for purposes that have none. Returns the created kids.
// It never replaces an existing key.
func Init(ctx context.Context, q db.Q, env *envelope.Key) ([]string, error) {
	var created []string
	for _, p := range AllPurposes {
		var n int
		if err := q.QueryRow(ctx, `SELECT count(*) FROM server_keys WHERE purpose=$1`, string(p)).Scan(&n); err != nil {
			return nil, err
		}
		if n > 0 {
			continue
		}
		kid, err := generate(ctx, q, env, p)
		if err != nil {
			return nil, err
		}
		created = append(created, kid)
	}
	return created, nil
}

func generate(ctx context.Context, q db.Q, env *envelope.Key, p Purpose) (string, error) {
	var priv any
	var pub any
	alg := "P-256"
	if p == FwSign {
		k, err := rsa.GenerateKey(rand.Reader, espsig.KeyBits)
		if err != nil {
			return "", err
		}
		priv, pub, alg = k, &k.PublicKey, "RSA-3072"
	} else {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return "", err
		}
		priv, pub = k, &k.PublicKey
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	suffix := make([]byte, 3)
	rand.Read(suffix)
	kid := fmt.Sprintf("%s-%s-%s", p, time.Now().UTC().Format("20060102"), hex.EncodeToString(suffix))
	enc, err := env.Seal(der, aad(kid))
	if err != nil {
		return "", err
	}
	_, err = q.Exec(ctx, `INSERT INTO server_keys (kid, purpose, alg, private_enc, public_der) VALUES ($1,$2,$3,$4,$5)`,
		kid, string(p), alg, enc, pubDER)
	return kid, err
}

// SignApp signs an app or bootstrap image with the firmware signing key.
func (s *Signer) SignApp(img []byte) ([]byte, error) {
	return espsig.Sign(img, s.active[FwSign].rsa)
}

// FirmwarePublicKey is the key devices check OTA images against.
func (s *Signer) FirmwarePublicKey() *rsa.PublicKey { return &s.active[FwSign].rsa.PublicKey }

// SignJWS signs payload with the active key of an ES256 purpose.
func (s *Signer) SignJWS(p Purpose, typ string, payload any) (string, error) {
	k := s.active[p]
	if k == nil || k.ec == nil || p == Telemetry {
		return "", fmt.Errorf("signer: %s is not a signing purpose", p)
	}
	return jws.Sign(k.ec, k.kid, typ, payload)
}

// SignRaw returns (kid, r||s signature) of msg with an ES256 purpose key.
func (s *Signer) SignRaw(p Purpose, msg []byte) (string, []byte, error) {
	k := s.active[p]
	if k == nil || k.ec == nil || p == Telemetry {
		return "", nil, fmt.Errorf("signer: %s is not a signing purpose", p)
	}
	sig, err := jws.SignRaw(k.ec, msg)
	return k.kid, sig, err
}

// VerifyKey returns the public key of an ES256 key by kid (for self-checks
// and the device simulator).
func (s *Signer) VerifyKey(kid string) *ecdsa.PublicKey {
	if k := s.byKid[kid]; k != nil && k.ec != nil {
		return &k.ec.PublicKey
	}
	return nil
}

// TelemetryPublic is the ECDH key devices encrypt to.
func (s *Signer) TelemetryPublic() *ecdh.PublicKey {
	pub, _ := s.active[Telemetry].ec.PublicKey.ECDH()
	return pub
}

// OpenBox decrypts a box sent to K_telemetry. Every telemetry key (also
// retired ones) is tried, so devices with an older key table still work.
func (s *Signer) OpenBox(info string, box ecies.Box, aadData []byte) ([]byte, error) {
	var lastErr error
	for _, k := range s.byKid {
		if k.purpose != Telemetry {
			continue
		}
		priv, err := k.ec.ECDH()
		if err != nil {
			return nil, err
		}
		plain, err := ecies.Open(priv, info, box, aadData)
		if err == nil {
			return plain, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

type PublicKey struct {
	Kid     string
	Purpose Purpose
	Active  bool
	Key     any // *rsa.PublicKey or *ecdsa.PublicKey
}

// PublicKeys lists all public keys, active first, for export to the firmware.
func (s *Signer) PublicKeys() []PublicKey {
	var out []PublicKey
	for _, k := range s.byKid {
		pk := PublicKey{Kid: k.kid, Purpose: k.purpose, Active: k.active}
		if k.rsa != nil {
			pk.Key = &k.rsa.PublicKey
		} else {
			pk.Key = &k.ec.PublicKey
		}
		out = append(out, pk)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Purpose != out[j].Purpose {
			return out[i].Purpose < out[j].Purpose
		}
		if out[i].Active != out[j].Active {
			return out[i].Active
		}
		return out[i].Kid < out[j].Kid
	})
	return out
}

// PublicPEM encodes a public key as PKIX PEM.
func PublicPEM(key any) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// ExportPrivatePEM returns the active private key of a purpose as PKCS#8 PEM,
// for the offline copy. Only lcmctl calls this, never the HTTP server.
func (s *Signer) ExportPrivatePEM(p Purpose) ([]byte, string, error) {
	k := s.active[p]
	if k == nil {
		return nil, "", fmt.Errorf("signer: no %s key", p)
	}
	var priv any = k.ec
	if k.rsa != nil {
		priv = k.rsa
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, "", err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), k.kid, nil
}

// ActiveKid is the kid new signatures of a purpose will carry.
func (s *Signer) ActiveKid(p Purpose) string { return s.active[p].kid }
