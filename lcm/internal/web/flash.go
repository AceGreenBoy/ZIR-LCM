package web

import (
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/go-chi/chi/v5"

	"zir/lcm/internal/core"
	"zir/lcm/internal/httpapi"
)

type flashData struct {
	Builds []core.Build
	Public bool   // /bootstrap, no login
	Image  string // URL prefix of the image: <Image><id>/bootstrap.bin
	Done   string // where flash.js reports a finished write
}

// ── bootstrap: upload and USB flashing from the browser ─────────────────────
// The flashing itself runs in the browser (static/flash.js, Web Serial and
// esptool-js); the server serves the image and records the result.

func (h *Handler) flashPage(w http.ResponseWriter, r *http.Request) {
	if !actor(r).Has(core.RoleManufacturer, core.RoleEngineer) {
		h.fail(w, r, &core.Error{Status: 403, Msg: "недостатньо прав"})
		return
	}
	list, err := h.Core.Builds(r.Context(), "bootstrap")
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.render(w, r, "flash", "Прошивка USB", flashData{Builds: list, Image: "/builds/", Done: "/flash/done"})
}

// publicFlashPage is /flash without login, for the production line: it can
// only write a bootstrap the superadmin uploaded.
func (h *Handler) publicFlashPage(w http.ResponseWriter, r *http.Request) {
	list, err := h.Core.Builds(r.Context(), "bootstrap")
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.render(w, r, "flash", "Прошивка bootstrap", flashData{Builds: list, Public: true, Image: "/bootstrap/", Done: "/bootstrap/done"})
}

func (h *Handler) publicBootstrapFile(w http.ResponseWriter, r *http.Request) {
	p, err := h.Core.PublicBootstrapFile(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	f, err := os.Open(p)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="bootstrap.bin"`)
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, "bootstrap.bin", time.Time{}, f)
}

// publicFlashDone has no session and so no CSRF token: it accepts only
// same-origin requests, and core rate-limits it per IP.
func (h *Handler) publicFlashDone(w http.ResponseWriter, r *http.Request) {
	if o := r.Header.Get("Origin"); o != "" {
		if u, err := url.Parse(o); err != nil || u.Host != r.Host {
			http.Error(w, "cross-origin request", http.StatusForbidden)
			return
		}
	}
	err := h.Core.BootstrapFlashed(r.Context(), core.Actor{IP: httpapi.ClientIP(r)}, r.FormValue("build_id"), r.FormValue("mac"),
		r.FormValue("chip"), r.FormValue("erase") == "1")
	if err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// flashDone is called by flash.js after a successful write.
func (h *Handler) flashDone(w http.ResponseWriter, r *http.Request) {
	err := h.Core.BootstrapFlashed(r.Context(), actor(r), r.FormValue("build_id"), r.FormValue("mac"), r.FormValue("chip"),
		r.FormValue("erase") == "1")
	if err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) uploadBootstrap(w http.ResponseWriter, r *http.Request) {
	img, err := formFile(r, "bootstrap")
	if err != nil || img == nil {
		back(w, r, "/builds", &core.Error{Msg: "оберіть файл образу"}, "")
		return
	}
	b, err := h.Core.UploadBootstrap(r.Context(), actor(r), img)
	back(w, r, "/builds", err, "bootstrap "+b.Version+" перевірено й збережено; його можна прошити на сторінці «Прошивка USB»")
}
