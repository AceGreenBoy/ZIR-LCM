package core

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"

	"zir/lcm/internal/crypto/ecies"
	"zir/lcm/internal/db"
	"zir/lcm/internal/signer"
)

const (
	claimTTL          = 30 * time.Minute
	claimMaxFailures  = 5
	claimFailWindow   = 10 * time.Minute
	crockford         = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	webPasswordMinLen = 8
	webPasswordMaxLen = 63
)

// RegisterRequest is the body of POST /dev/v1/register/request, signed with
// the dev_sign key it carries.
type RegisterRequest struct {
	MAC              string    `json:"mac"`
	ChipRev          string    `json:"chip_rev"`
	BootstrapVersion string    `json:"bootstrap_version"`
	DevSignPub       string    `json:"dev_sign_pub"` // b64, 65-byte uncompressed P-256
	DevKexPub        string    `json:"dev_kex_pub"`  // b64, 65-byte uncompressed P-256
	WebPassword      ecies.Box `json:"web_password"` // to K_telemetry, info zir-reg/1, aad = mac (lowercase)
}

type RegisterReply struct {
	RequestID string `json:"request_id"`
	ClaimCode string `json:"claim_code"`
	ExpiresIn int    `json:"expires_in"`
}

func normMAC(s string) (string, error) {
	hw, err := net.ParseMAC(s)
	if err != nil || len(hw) != 6 {
		return "", fmt.Errorf("bad mac")
	}
	return hw.String(), nil
}

func newClaimCode() string {
	b := randBytes(8)
	out := make([]byte, 8)
	for i, v := range b {
		out[i] = crockford[int(v)%32]
	}
	return string(out)
}

// FormatClaim shows a code as XXXX-XXXX.
func FormatClaim(code string) string {
	if len(code) == 8 {
		return code[:4] + "-" + code[4:]
	}
	return code
}

// NormalizeClaim accepts lower case, dashes, spaces and the usual Crockford
// look-alikes (O→0, I/L→1).
func NormalizeClaim(s string) string {
	s = strings.ToUpper(s)
	r := strings.NewReplacer("-", "", " ", "", "O", "0", "I", "1", "L", "1", "U", "V")
	return r.Replace(s)
}

func (c *Core) RequestRegistration(ctx context.Context, body []byte, method, uri, sig, ip string) (RegisterReply, error) {
	var req RegisterRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return RegisterReply{}, userErr(400, "bad_request", "bad json")
	}
	mac, err := normMAC(req.MAC)
	if err != nil {
		return RegisterReply{}, userErr(400, "bad_request", "bad mac")
	}
	signPub, err1 := DecodeB64(req.DevSignPub)
	kexPub, err2 := DecodeB64(req.DevKexPub)
	if err1 != nil || err2 != nil {
		return RegisterReply{}, userErr(400, "bad_request", "bad keys")
	}
	if _, _, err := p256Point(signPub); err != nil {
		return RegisterReply{}, userErr(400, "bad_request", "bad dev_sign_pub")
	}
	if _, _, err := p256Point(kexPub); err != nil {
		return RegisterReply{}, userErr(400, "bad_request", "bad dev_kex_pub")
	}
	if !VerifyDeviceSig(signPub, method, uri, body, sig) {
		return RegisterReply{}, userErr(401, "bad_signature", "bad signature")
	}
	pw, err := c.Signer.OpenBox(ecies.InfoRegPassword, req.WebPassword, []byte(mac))
	if err != nil || len(pw) < webPasswordMinLen || len(pw) > webPasswordMaxLen {
		return RegisterReply{}, userErr(400, "bad_password", "web_password cannot be decrypted or has bad length")
	}

	id := uuid.NewString()
	pwEnc, err := c.Env.Seal(pw, "reg:"+id+":web_password")
	if err != nil {
		return RegisterReply{}, err
	}
	var code string
	for attempt := 0; ; attempt++ {
		code = newClaimCode()
		_, err = c.Pool.Exec(ctx, `INSERT INTO registration_requests
			(id, claim_code, mac, chip_rev, bootstrap_version, dev_sign_pub, dev_kex_pub, web_password_enc, expires_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			id, code, mac, req.ChipRev, req.BootstrapVersion, signPub, kexPub, pwEnc, c.Now().Add(claimTTL))
		if err == nil || !db.IsUniqueViolation(err) || attempt > 5 {
			break
		}
	}
	if err != nil {
		return RegisterReply{}, err
	}
	return RegisterReply{RequestID: id, ClaimCode: code, ExpiresIn: int(claimTTL.Seconds())}, nil
}

// RegisterStatus is the reply of GET /dev/v1/register/status.
type RegisterStatus struct {
	Status   string     `json:"status"` // pending | approved | rejected | expired
	DeviceID string     `json:"device_id,omitempty"`
	Serial   string     `json:"serial,omitempty"`
	Config   string     `json:"config,omitempty"`  // JWS signed with K_config
	OTAKey   *ecies.Box `json:"ota_key,omitempty"` // PEM of the RSA-3072 K_ota, to dev_kex, info zir-otakey/1, aad = device_id
}

func (c *Core) RegistrationStatus(ctx context.Context, requestID, method, uri, sig string) (RegisterStatus, error) {
	var signPub, result []byte
	var status string
	var expires time.Time
	err := c.Pool.QueryRow(ctx, `SELECT dev_sign_pub, status, expires_at, result FROM registration_requests WHERE id::text=$1`,
		requestID).Scan(&signPub, &status, &expires, &result)
	if db.IsNoRows(err) {
		return RegisterStatus{}, userErr(404, "not_found", "unknown request")
	}
	if err != nil {
		return RegisterStatus{}, err
	}
	if !VerifyDeviceSig(signPub, method, uri, nil, sig) {
		return RegisterStatus{}, userErr(401, "bad_signature", "bad signature")
	}
	if status == "pending" && c.Now().After(expires) {
		c.Pool.Exec(ctx, `UPDATE registration_requests SET status='expired' WHERE id=$1 AND status='pending'`, requestID)
		status = "expired"
	}
	out := RegisterStatus{Status: status}
	if status == "approved" {
		if err := json.Unmarshal(result, &out); err != nil {
			return out, err
		}
		out.Status = status
	}
	return out, nil
}

// Claim is what the manufacturer sees after entering a code.
type Claim struct {
	RequestID        string
	ClaimCode        string
	MAC              string
	ChipRev          string
	BootstrapVersion string
	CreatedAt        time.Time
	ExpiresAt        time.Time
	// Set when the MAC already belongs to a registered device.
	ExistingDevice  string
	ExistingSerial  string
	ExistingRevoked bool
}

func (c *Core) ClaimCode(ctx context.Context, a Actor, code string) (Claim, error) {
	if err := a.require(RoleManufacturer); err != nil {
		return Claim{}, err
	}
	var fails int
	if err := c.Pool.QueryRow(ctx, `SELECT count(*) FROM claim_failures WHERE user_id=$1 AND at > $2`,
		a.UserID, c.Now().Add(-claimFailWindow)).Scan(&fails); err != nil {
		return Claim{}, err
	}
	if fails >= claimMaxFailures {
		return Claim{}, userErr(429, "too_many", "забагато невірних кодів, зачекайте 10 хвилин")
	}
	var cl Claim
	var mac net.HardwareAddr
	err := c.Pool.QueryRow(ctx, `SELECT id, claim_code, mac, chip_rev, bootstrap_version, created_at, expires_at
		FROM registration_requests WHERE claim_code=$1 AND status='pending' AND expires_at > $2`,
		NormalizeClaim(code), c.Now()).Scan(&cl.RequestID, &cl.ClaimCode, &mac, &cl.ChipRev, &cl.BootstrapVersion, &cl.CreatedAt, &cl.ExpiresAt)
	if db.IsNoRows(err) {
		c.Pool.Exec(ctx, `INSERT INTO claim_failures (user_id) VALUES ($1)`, a.UserID)
		return Claim{}, userErr(404, "not_found", "код не знайдено або він прострочений")
	}
	if err != nil {
		return Claim{}, err
	}
	cl.MAC = mac.String()
	var status string
	err = c.Pool.QueryRow(ctx, `SELECT id, serial, status FROM devices WHERE mac=$1`, cl.MAC).Scan(&cl.ExistingDevice, &cl.ExistingSerial, &status)
	if err == nil {
		cl.ExistingRevoked = status == "revoked"
		anomaly(ctx, c.Pool, cl.ExistingDevice, "duplicate_registration",
			map[string]any{"request_id": cl.RequestID, "claimed_by": a.Login})
	} else if !db.IsNoRows(err) {
		return Claim{}, err
	}
	return cl, nil
}

type ApproveInput struct {
	RequestID  string
	Profile    string
	Params     HardParams
	Reregister bool
}

// Approve registers the device (or re-registers an existing one with fresh
// keys), creates its K_ota and the first signed config.
func (c *Core) Approve(ctx context.Context, a Actor, in ApproveInput) (deviceID string, err error) {
	if err := a.require(RoleManufacturer); err != nil {
		return "", err
	}
	prof, schema, err := c.Profile(ctx, c.Pool, in.Profile)
	if err != nil {
		return "", err
	}
	if !prof.Active {
		return "", userErr(400, "inactive_profile", "профіль %s вимкнено", prof.Code)
	}
	if err := ValidateParams(schema, in.Params); err != nil {
		return "", err
	}

	// RSA-3072 generation takes a moment: do it outside the transaction.
	otaKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return "", err
	}
	otaPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(otaKey)})
	otaPubDER, _ := x509.MarshalPKIXPublicKey(&otaKey.PublicKey)

	err = db.InTx(ctx, c.Pool, func(tx pgxTx) error {
		var mac net.HardwareAddr
		var chipRev, status string
		var signPub, kexPub, pwEncReg []byte
		var expires time.Time
		err := tx.QueryRow(ctx, `SELECT mac, chip_rev, dev_sign_pub, dev_kex_pub, web_password_enc, status, expires_at
			FROM registration_requests WHERE id::text=$1 FOR UPDATE`, in.RequestID).
			Scan(&mac, &chipRev, &signPub, &kexPub, &pwEncReg, &status, &expires)
		if db.IsNoRows(err) {
			return userErr(404, "not_found", "запит на реєстрацію не знайдено")
		}
		if err != nil {
			return err
		}
		if status != "pending" || c.Now().After(expires) {
			return userErr(409, "not_pending", "запит уже оброблено або прострочено, перезапустіть реєстрацію на приладі")
		}
		pw, err := c.Env.Open(pwEncReg, "reg:"+in.RequestID+":web_password")
		if err != nil {
			return err
		}

		var existingID, existingStatus string
		err = tx.QueryRow(ctx, `SELECT id, status FROM devices WHERE mac=$1 FOR UPDATE`, mac.String()).Scan(&existingID, &existingStatus)
		switch {
		case err == nil && !in.Reregister:
			return userErr(409, "mac_exists", "прилад з цим MAC уже зареєстровано; оберіть «перереєструвати існуючий»")
		case err == nil && existingStatus == "revoked":
			return userErr(409, "revoked", "прилад відкликано; спочатку superadmin має зняти відкликання")
		case err != nil && !db.IsNoRows(err):
			return err
		}

		action := "device.register"
		if existingID == "" {
			deviceID = uuid.NewString()
		} else {
			deviceID = existingID
			action = "device.reregister"
		}
		otaEnc, err := c.Env.Seal(otaPEM, "device:"+deviceID+":ota_key")
		if err != nil {
			return err
		}
		pwEnc, err := c.Env.Seal(pw, "device:"+deviceID+":web_password")
		if err != nil {
			return err
		}

		var serial string
		var cfgVersion int
		if existingID == "" {
			var n int64
			if err := tx.QueryRow(ctx, `SELECT nextval('device_serial_seq')`).Scan(&n); err != nil {
				return err
			}
			serial = fmt.Sprintf("ZIR3M-%06d", n)
			cfgVersion = 1
			_, err = tx.Exec(ctx, `INSERT INTO devices (id, serial, mac, chip_rev, profile_id, dev_sign_pub, dev_kex_pub,
				ota_key_enc, ota_pub_der, web_password_enc, web_password_changed_at, config_version, registered_by)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,now(),$11,$12)`,
				deviceID, serial, mac.String(), chipRev, prof.ID, signPub, kexPub, otaEnc, otaPubDER, pwEnc, cfgVersion, a.UserID)
		} else {
			err = tx.QueryRow(ctx, `UPDATE devices SET chip_rev=$2, profile_id=$3, dev_sign_pub=$4, dev_kex_pub=$5,
				ota_key_enc=$6, ota_pub_der=$7, web_password_enc=$8, web_password_changed_at=now(),
				config_version=config_version+1, current_app_sha256=NULL, current_www_sha256=NULL,
				registered_by=$9, registered_at=now()
				WHERE id=$1 RETURNING serial, config_version`,
				deviceID, chipRev, prof.ID, signPub, kexPub, otaEnc, otaPubDER, pwEnc, a.UserID).Scan(&serial, &cfgVersion)
			if err == nil {
				// Old keys are void: drop sessions and the encrypted image cache.
				_, err = tx.Exec(ctx, `DELETE FROM device_sessions WHERE device_id=$1`, deviceID)
				c.dropImageCache(deviceID)
			}
		}
		if err != nil {
			return err
		}
		cfg, err := c.signConfig(ctx, tx, deviceID, mac.String(), prof.Code, cfgVersion, in.Params, a.UserID)
		if err != nil {
			return err
		}
		_, kexECDH, _ := p256Point(kexPub)
		box, err := ecies.Seal(kexECDH, ecies.InfoOTAKey, otaPEM, []byte(deviceID))
		if err != nil {
			return err
		}
		result, _ := json.Marshal(RegisterStatus{DeviceID: deviceID, Serial: serial, Config: cfg, OTAKey: &box})
		if _, err := tx.Exec(ctx, `UPDATE registration_requests SET status='approved', approved_by=$2, device_id=$3, result=$4 WHERE id=$1`,
			in.RequestID, a.UserID, deviceID, result); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO device_counters (device_id) VALUES ($1) ON CONFLICT DO NOTHING`, deviceID); err != nil {
			return err
		}
		return a.audit(ctx, tx, action, "device", deviceID, map[string]any{
			"serial": serial, "mac": mac.String(), "profile": prof.Code, "params": in.Params, "request_id": in.RequestID})
	})
	return deviceID, err
}

// ConfigPayload is the signed device config (ARCHITECTURE 7.5).
type ConfigPayload struct {
	Typ      string           `json:"typ"`
	DeviceID string           `json:"device_id"`
	MAC      string           `json:"mac"`
	Profile  string           `json:"profile"`
	Version  int              `json:"version"`
	IAT      int64            `json:"iat"`
	Modules  map[string]bool  `json:"modules"`
	Ranges   map[string]Range `json:"ranges"`
}

func (c *Core) signConfig(ctx context.Context, tx pgxTx, deviceID, mac, profile string, version int, p HardParams, by string) (string, error) {
	payload := ConfigPayload{Typ: "zir-config/1", DeviceID: deviceID, MAC: mac, Profile: profile,
		Version: version, IAT: c.Now().Unix(), Modules: p.Modules, Ranges: p.Ranges}
	tok, err := c.Signer.SignJWS(signer.Config, "zir-config/1", payload)
	if err != nil {
		return "", err
	}
	params, _ := json.Marshal(p)
	var byPtr *string
	if by != "" {
		byPtr = &by
	}
	_, err = tx.Exec(ctx, `INSERT INTO device_configs (device_id, version, hard_params, signed_blob, created_by) VALUES ($1,$2,$3,$4,$5)`,
		deviceID, version, params, tok, byPtr)
	return tok, err
}
