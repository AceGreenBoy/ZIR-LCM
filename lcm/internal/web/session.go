package web

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"time"

	"zir/lcm/internal/core"
	"zir/lcm/internal/db"
	"zir/lcm/internal/httpapi"
)

const (
	sessionMaxAge   = 12 * time.Hour
	sessionIdle     = 2 * time.Hour
	loginMaxFails   = 5
	loginFailWindow = 15 * time.Minute
)

type session struct {
	hash   []byte
	csrf   string
	totpOK bool
	actor  core.Actor
	totpOn bool
}

type sessKey struct{}

func (h *Handler) cookieName() string {
	if h.InsecureCookie {
		return "zir_session"
	}
	return "__Host-zir_session"
}

func (h *Handler) setCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: h.cookieName(), Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: !h.InsecureCookie, SameSite: http.SameSiteStrictMode,
	})
}

func token(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashToken(t string) []byte {
	s := sha256.Sum256([]byte(t))
	return s[:]
}

// newSession starts a session after a correct password (second factor pending).
func (h *Handler) newSession(ctx context.Context, w http.ResponseWriter, r *http.Request, userID string) error {
	t := token(32)
	_, err := h.Core.Pool.Exec(ctx, `INSERT INTO web_sessions (id_hash, user_id, csrf, expires_at, ip, user_agent)
		VALUES ($1,$2,$3,$4,$5,$6)`, hashToken(t), userID, token(24), time.Now().Add(sessionMaxAge),
		httpapi.ClientIP(r), r.UserAgent())
	if err != nil {
		return err
	}
	h.setCookie(w, t, int(sessionMaxAge.Seconds()))
	return nil
}

func (h *Handler) loadSession(r *http.Request) (*session, error) {
	c, err := r.Cookie(h.cookieName())
	if err != nil || c.Value == "" {
		return nil, nil
	}
	s := &session{hash: hashToken(c.Value), actor: core.Actor{Roles: map[string]bool{}, IP: httpapi.ClientIP(r)}}
	var status string
	var lastSeen time.Time
	err = h.Core.Pool.QueryRow(r.Context(), `SELECT s.csrf, s.totp_ok, s.last_seen_at, u.id, u.login, u.display_name, u.status, u.totp_enabled
		FROM web_sessions s JOIN users u ON u.id=s.user_id WHERE s.id_hash=$1 AND s.expires_at > now()`, s.hash).
		Scan(&s.csrf, &s.totpOK, &lastSeen, &s.actor.UserID, &s.actor.Login, &s.actor.Name, &status, &s.totpOn)
	if db.IsNoRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if status != "active" || time.Since(lastSeen) > sessionIdle {
		h.Core.Pool.Exec(r.Context(), `DELETE FROM web_sessions WHERE id_hash=$1`, s.hash)
		return nil, nil
	}
	rows, err := h.Core.Pool.Query(r.Context(), `SELECT role FROM user_roles WHERE user_id=$1`, s.actor.UserID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var role string
		rows.Scan(&role)
		s.actor.Roles[role] = true
	}
	rows.Close()
	h.Core.Pool.Exec(r.Context(), `UPDATE web_sessions SET last_seen_at=now() WHERE id_hash=$1`, s.hash)
	return s, nil
}

// requireLogin lets through only fully signed-in users (password and TOTP)
// and checks the CSRF token on every state-changing request.
func (h *Handler) requireLogin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, err := h.loadSession(r)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		if s == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if !s.totpOK {
			http.Redirect(w, r, "/login/totp", http.StatusSeeOther)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if subtle.ConstantTimeCompare([]byte(r.FormValue("csrf")), []byte(s.csrf)) != 1 {
				http.Error(w, "CSRF token mismatch: reload the page", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessKey{}, s)))
	})
}

func sess(r *http.Request) *session    { return r.Context().Value(sessKey{}).(*session) }
func actor(r *http.Request) core.Actor { return sess(r).actor }

func (h *Handler) loginBlocked(ctx context.Context, login string) bool {
	var n int
	h.Core.Pool.QueryRow(ctx, `SELECT count(*) FROM login_failures WHERE login=$1 AND at > $2`, login, time.Now().Add(-loginFailWindow)).Scan(&n)
	return n >= loginMaxFails
}

func (h *Handler) loginFailed(ctx context.Context, login string) {
	h.Core.Pool.Exec(ctx, `INSERT INTO login_failures (login) VALUES ($1)`, login)
	h.Core.Pool.Exec(ctx, `DELETE FROM login_failures WHERE at < now() - interval '1 day'`)
}
