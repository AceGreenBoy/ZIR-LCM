package web

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"zir/lcm/internal/core"
)

// ── developer devices and builds (superadmin) ───────────────────────────────

func (h *Handler) deviceDevMode(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	on := r.FormValue("dev") == "1"
	err := h.Core.SetDevMode(r.Context(), actor(r), id, on)
	msg := "прилад більше не є приладом розробника; нова конфігурація підписана"
	if on {
		msg = "прилад став приладом розробника; нова конфігурація підписана"
	}
	back(w, r, "/devices/"+id, err, msg)
}

func (h *Handler) deviceDevBuild(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var err error
	if b := r.FormValue("build_id"); b != "" {
		_, err = h.Core.AssignDevBuild(r.Context(), actor(r), b, []string{id}, r.FormValue("critical") == "on")
	} else {
		err = h.Core.ClearDevBuild(r.Context(), actor(r), id)
	}
	back(w, r, "/devices/"+id, err, "збережено")
}

type devData struct {
	Builds   []core.Build
	Devices  []core.Device
	Tokens   []core.APIToken
	NewToken string
	Build    string // preselected build
}

func (h *Handler) devData(r *http.Request) (devData, error) {
	var d devData
	var err error
	if d.Builds, err = h.Core.Builds(r.Context(), "dev_app"); err != nil {
		return d, err
	}
	if d.Devices, err = h.Core.DevDevices(r.Context()); err != nil {
		return d, err
	}
	if d.Tokens, err = h.Core.APITokens(r.Context(), actor(r)); err != nil {
		return d, err
	}
	d.Build = r.URL.Query().Get("build")
	return d, nil
}

func (h *Handler) devPage(w http.ResponseWriter, r *http.Request) {
	if !actor(r).Roles[core.RoleSuperadmin] {
		h.fail(w, r, &core.Error{Status: 403, Msg: "лише superadmin"})
		return
	}
	d, err := h.devData(r)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.render(w, r, "dev", "Розробка", d)
}

func (h *Handler) devUpload(w http.ResponseWriter, r *http.Request) {
	img, err := formFile(r, "app")
	if err != nil || img == nil {
		back(w, r, "/dev", &core.Error{Msg: "оберіть файл образу"}, "")
		return
	}
	elf, _ := formFile(r, "elf")
	b, err := h.Core.UploadDevApp(r.Context(), actor(r), img, elf)
	if err != nil {
		back(w, r, "/dev", err, "")
		return
	}
	back(w, r, "/dev?build="+b.ID, nil, "збірку "+b.Version+" завантажено; оберіть прилади й призначте її")
}

func (h *Handler) devAssign(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	devices := r.Form["device"]
	assigned, err := h.Core.AssignDevBuild(r.Context(), actor(r), r.FormValue("build_id"), devices, r.FormValue("critical") == "on")
	msg := "збірку призначено: "
	for i, s := range assigned {
		if i > 0 {
			msg += ", "
		}
		msg += s
	}
	if r.FormValue("critical") == "on" {
		msg += ". Критична: прилади поставлять її протягом хвилини, без підтвердження"
	} else {
		msg += ". Користувач побачить кнопку «Оновити»"
	}
	back(w, r, "/dev", err, msg)
}

func (h *Handler) devTokenCreate(w http.ResponseWriter, r *http.Request) {
	tok, err := h.Core.CreateAPIToken(r.Context(), actor(r), r.FormValue("name"))
	if err != nil {
		back(w, r, "/dev", err, "")
		return
	}
	// The token is shown once, in this response only (never in a URL).
	d, err := h.devData(r)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	d.NewToken = tok
	h.render(w, r, "dev", "Розробка", d)
}

func (h *Handler) devTokenRevoke(w http.ResponseWriter, r *http.Request) {
	err := h.Core.RevokeAPIToken(r.Context(), actor(r), chi.URLParam(r, "id"))
	back(w, r, "/dev", err, "токен відкликано")
}
