// Package httpapi serves the device API (/dev/v1).
package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"zir/lcm/internal/core"
)

const maxBody = 64 << 10

type ctxKey struct{}

type API struct{ Core *core.Core }

func (a *API) Routes() http.Handler {
	r := chi.NewRouter()
	r.Post("/register/request", a.registerRequest)
	r.Get("/register/status", a.registerStatus)
	r.Post("/auth/challenge", a.challenge)
	r.Post("/auth/session", a.session)
	r.Group(func(r chi.Router) {
		r.Use(a.auth)
		r.Get("/update", a.update)
		r.Get("/artifacts/{release}/{kind}", a.artifact)
		r.Get("/dev-artifacts/{build}", a.devArtifact)
		r.Get("/dev-artifacts/{build}/www", a.devWWW)
		r.Post("/update/report", a.report)
		r.Get("/config", a.config)
		r.Post("/web-password", a.webPassword)
		r.Post("/telemetry", notImplemented)
		r.Post("/coredump", notImplemented)
		r.Post("/config/request", notImplemented)
		r.Post("/engineer/confirm", notImplemented)
	})
	return r
}

// ClientIP is the client address: Traefik's X-Real-Ip, or the peer address.
func ClientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-Ip"); ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		writeErr(w, &core.Error{Status: 413, Code: "too_large", Msg: "body too large"})
		return nil, false
	}
	return body, true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	if e, ok := core.AsError(err); ok {
		writeJSON(w, e.Status, map[string]string{"error": e.Code, "message": e.Msg})
		return
	}
	slog.Error("device api", "err", err)
	writeJSON(w, 500, map[string]string{"error": "internal", "message": "internal error"})
}

func notImplemented(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 501, map[string]string{"error": "not_implemented", "message": "not implemented in the MVP server yet"})
}

func sig(r *http.Request) string { return r.Header.Get("X-Zir-Sig") }

func (a *API) registerRequest(w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	res, err := a.Core.RequestRegistration(r.Context(), body, r.Method, r.RequestURI, sig(r), ClientIP(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, res)
}

func (a *API) registerStatus(w http.ResponseWriter, r *http.Request) {
	res, err := a.Core.RegistrationStatus(r.Context(), r.URL.Query().Get("request_id"), r.Method, r.RequestURI, sig(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, res)
}

func (a *API) challenge(w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	var req struct {
		DeviceID string `json:"device_id"`
	}
	if json.Unmarshal(body, &req) != nil {
		writeErr(w, &core.Error{Status: 400, Code: "bad_request", Msg: "bad json"})
		return
	}
	res, err := a.Core.Challenge(r.Context(), req.DeviceID)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, res)
}

func (a *API) session(w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	res, err := a.Core.Session(r.Context(), body, r.Method, r.RequestURI, sig(r), ClientIP(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, res)
}

func (a *API) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok {
			writeErr(w, &core.Error{Status: 401, Code: "no_token", Msg: "Authorization: Bearer <session_token> required"})
			return
		}
		s, err := a.Core.Authenticate(r.Context(), token)
		if err != nil {
			writeErr(w, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, s)))
	})
}

func devSession(r *http.Request) core.DeviceSession {
	return r.Context().Value(ctxKey{}).(core.DeviceSession)
}

func (a *API) update(w http.ResponseWriter, r *http.Request) {
	res, err := a.Core.CheckUpdate(r.Context(), devSession(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, res)
}

func (a *API) artifact(w http.ResponseWriter, r *http.Request) {
	s := devSession(r)
	release := chi.URLParam(r, "release")
	var path string
	var err error
	switch chi.URLParam(r, "kind") {
	case "app":
		path, err = a.Core.AppImagePath(r.Context(), s, release)
	case "www":
		path, err = a.Core.WWWPath(r.Context(), s, release)
	default:
		err = &core.Error{Status: 404, Code: "not_found", Msg: "unknown artifact"}
	}
	serveFile(w, r, path, err)
}

func (a *API) devArtifact(w http.ResponseWriter, r *http.Request) {
	path, err := a.Core.DevImagePath(r.Context(), devSession(r), chi.URLParam(r, "build"))
	serveFile(w, r, path, err)
}

func (a *API) devWWW(w http.ResponseWriter, r *http.Request) {
	path, err := a.Core.DevWWWPath(r.Context(), devSession(r), chi.URLParam(r, "build"))
	serveFile(w, r, path, err)
}

func serveFile(w http.ResponseWriter, r *http.Request, path string, err error) {
	if err != nil {
		writeErr(w, err)
		return
	}
	f, err := os.Open(path)
	if err != nil {
		writeErr(w, err)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	// ServeContent handles Range requests for resumed downloads.
	http.ServeContent(w, r, filepath.Base(path), time.Time{}, f)
}

func (a *API) report(w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	if err := a.Core.ReportUpdate(r.Context(), devSession(r), body, ClientIP(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *API) config(w http.ResponseWriter, r *http.Request) {
	res, err := a.Core.DeviceConfig(r.Context(), devSession(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, res)
}

func (a *API) webPassword(w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	if err := a.Core.ReportWebPassword(r.Context(), devSession(r), body, ClientIP(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
