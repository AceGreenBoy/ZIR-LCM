package web

import (
	"context"
	"net/http"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"zir/lcm/internal/auth"
	"zir/lcm/internal/signer"
)

func checkPassword(hash, pw string) bool { return auth.CheckPassword(hash, pw) }

func contextWith(r *http.Request, s *session) context.Context {
	return context.WithValue(r.Context(), sessKey{}, s)
}

func pemOf(key any) ([]byte, error) { return signer.PublicPEM(key) }

func totpKey(login, secret string) (*otp.Key, error) {
	return otp.NewKeyFromURL("otpauth://totp/ZIR%20LCM:" + login + "?issuer=ZIR%20LCM&secret=" + secret)
}

// pendingTOTPSecret returns the user's not-yet-confirmed TOTP secret,
// creating one on first use.
func (h *Handler) pendingTOTPSecret(r *http.Request, s *session) (string, error) {
	ctx := r.Context()
	var enc []byte
	if err := h.Core.Pool.QueryRow(ctx, `SELECT totp_secret_enc FROM users WHERE id=$1`, s.actor.UserID).Scan(&enc); err != nil {
		return "", err
	}
	if enc != nil {
		secret, err := h.Core.Env.Open(enc, "user:"+s.actor.UserID+":totp")
		return string(secret), err
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "ZIR LCM", AccountName: s.actor.Login})
	if err != nil {
		return "", err
	}
	enc, err = h.Core.Env.Seal([]byte(key.Secret()), "user:"+s.actor.UserID+":totp")
	if err != nil {
		return "", err
	}
	_, err = h.Core.Pool.Exec(ctx, `UPDATE users SET totp_secret_enc=$2, totp_enabled=false WHERE id=$1 AND totp_secret_enc IS NULL`, s.actor.UserID, enc)
	return key.Secret(), err
}
