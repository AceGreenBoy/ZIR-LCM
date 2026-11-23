package web

import (
	"net/http"

	"zir/lcm/internal/core"
)

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
	h.render(w, r, "flash", "Прошивка USB", map[string]any{"Builds": list})
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
