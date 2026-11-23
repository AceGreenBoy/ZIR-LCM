package httpapi

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"zir/lcm/internal/core"
)

// AdminAPI is the token API for lcmctl (/api/v1). It covers only developer
// builds and bootstrap uploads: everything else stays in the admin UI behind TOTP.
type AdminAPI struct{ Core *core.Core }

type actorKey struct{}

const maxAppUpload = 4 << 20

func (a *AdminAPI) Routes() http.Handler {
	r := chi.NewRouter()
	r.Use(a.auth)
	r.Get("/dev-devices", a.devDevices)
	r.Post("/dev-builds", a.devBuild)
	r.Get("/bootstrap-builds", a.bootstrapBuilds)
	r.Post("/bootstrap-builds", a.bootstrapUpload)
	return r
}

func (a *AdminAPI) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok {
			writeErr(w, &core.Error{Status: 401, Code: "no_token", Msg: "Authorization: Bearer <API token> required"})
			return
		}
		actor, err := a.Core.TokenActor(r.Context(), strings.TrimSpace(tok), ClientIP(r))
		if err != nil {
			writeErr(w, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), actorKey{}, actor)))
	})
}

func tokenActor(r *http.Request) core.Actor { return r.Context().Value(actorKey{}).(core.Actor) }

// DevDevice is a row of GET /api/v1/dev-devices.
type DevDevice struct {
	ID           string     `json:"id"`
	Serial       string     `json:"serial"`
	Profile      string     `json:"profile"`
	Status       string     `json:"status"`
	Version      string     `json:"version"`
	DevBuild     string     `json:"dev_build,omitempty"`
	DevCritical  bool       `json:"dev_critical,omitempty"`
	DevInstalled bool       `json:"dev_installed,omitempty"`
	LastSeen     *time.Time `json:"last_seen,omitempty"`
}

func (a *AdminAPI) devDevices(w http.ResponseWriter, r *http.Request) {
	if !tokenActor(r).Roles[core.RoleSuperadmin] {
		writeErr(w, &core.Error{Status: 403, Code: "forbidden", Msg: "лише superadmin"})
		return
	}
	list, err := a.Core.DevDevices(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	out := []DevDevice{}
	for _, d := range list {
		out = append(out, DevDevice{ID: d.ID, Serial: d.Serial, Profile: d.Profile, Status: d.Status, Version: d.CurrentVersion,
			DevBuild: d.DevBuild, DevCritical: d.DevCritical, DevInstalled: d.DevInstalled, LastSeen: d.LastSeen})
	}
	writeJSON(w, 200, out)
}

// DevBuildReply is the reply of POST /api/v1/dev-builds.
type DevBuildReply struct {
	BuildID  string   `json:"build_id"`
	Version  string   `json:"version"`
	Profile  string   `json:"profile"`
	SHA256   string   `json:"sha256"`
	Assigned []string `json:"assigned"` // serials
	Critical bool     `json:"critical"`
}

// devBuild: multipart form with "app" (firmware.bin), optional "elf",
// "devices" (comma-separated serials or ids, "all", or empty to only upload)
// and "critical" (1/true).
func (a *AdminAPI) devBuild(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 3*maxAppUpload)
	if err := r.ParseMultipartForm(3 * maxAppUpload); err != nil {
		writeErr(w, &core.Error{Status: 400, Code: "bad_request", Msg: "multipart form expected: " + err.Error()})
		return
	}
	read := func(name string) []byte {
		f, _, err := r.FormFile(name)
		if err != nil {
			return nil
		}
		defer f.Close()
		b, _ := io.ReadAll(io.LimitReader(f, maxAppUpload))
		return b
	}
	img := read("app")
	if img == nil {
		writeErr(w, &core.Error{Status: 400, Code: "bad_request", Msg: "no app file"})
		return
	}
	actor := tokenActor(r)
	b, err := a.Core.UploadDevApp(r.Context(), actor, img, read("elf"))
	if err != nil {
		writeErr(w, err)
		return
	}
	crit := r.FormValue("critical")
	reply := DevBuildReply{BuildID: b.ID, Version: b.Version, Profile: b.Profile, SHA256: b.SHA256, Assigned: []string{},
		Critical: crit == "1" || crit == "true" || crit == "on"}
	var devices []string
	for _, d := range strings.Split(r.FormValue("devices"), ",") {
		if d = strings.TrimSpace(d); d != "" {
			devices = append(devices, d)
		}
	}
	if len(devices) > 0 {
		reply.Assigned, err = a.Core.AssignDevBuild(r.Context(), actor, b.ID, devices, reply.Critical)
		if err != nil {
			// The build is stored; say so, so the caller can assign it later.
			if e, ok := core.AsError(err); ok {
				writeJSON(w, e.Status, map[string]string{"error": e.Code, "message": e.Msg + " (збірку завантажено: " + b.ID + ")",
					"build_id": b.ID})
				return
			}
			writeErr(w, err)
			return
		}
	}
	writeJSON(w, 200, reply)
}

// BootstrapBuild is a row of GET /api/v1/bootstrap-builds and the reply of POST.
type BootstrapBuild struct {
	BuildID   string    `json:"build_id"`
	Version   string    `json:"version"`
	Size      int       `json:"size"`
	SHA256    string    `json:"sha256"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by,omitempty"`
}

func (a *AdminAPI) bootstrapBuilds(w http.ResponseWriter, r *http.Request) {
	if !tokenActor(r).Roles[core.RoleSuperadmin] {
		writeErr(w, &core.Error{Status: 403, Code: "forbidden", Msg: "лише superadmin"})
		return
	}
	list, err := a.Core.Builds(r.Context(), "bootstrap")
	if err != nil {
		writeErr(w, err)
		return
	}
	out := []BootstrapBuild{}
	for _, b := range list {
		out = append(out, BootstrapBuild{BuildID: b.ID, Version: b.Version, Size: b.Size, SHA256: b.SHA256, CreatedAt: b.CreatedAt, CreatedBy: b.CreatedBy})
	}
	writeJSON(w, 200, out)
}

// bootstrapUpload: multipart form with "image" (zir3m-bootstrap-<version>.bin).
func (a *AdminAPI) bootstrapUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxAppUpload+64<<10)
	if err := r.ParseMultipartForm(maxAppUpload); err != nil {
		writeErr(w, &core.Error{Status: 400, Code: "bad_request", Msg: "multipart form expected: " + err.Error()})
		return
	}
	f, _, err := r.FormFile("image")
	if err != nil {
		writeErr(w, &core.Error{Status: 400, Code: "bad_request", Msg: "no image file"})
		return
	}
	defer f.Close()
	img, err := io.ReadAll(io.LimitReader(f, maxAppUpload))
	if err != nil {
		writeErr(w, err)
		return
	}
	b, err := a.Core.UploadBootstrap(r.Context(), tokenActor(r), img)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, BootstrapBuild{BuildID: b.ID, Version: b.Version, Size: b.Size, SHA256: b.SHA256, CreatedAt: time.Now()})
}
