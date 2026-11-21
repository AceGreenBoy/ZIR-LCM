// Package web is the admin UI: server-rendered pages, plain HTML forms.
package web

import (
	"bytes"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"image/png"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/pquerna/otp/totp"

	"zir/lcm/internal/audit"
	"zir/lcm/internal/core"
	"zir/lcm/internal/httpapi"
)

//go:embed templates static
var assets embed.FS

type Handler struct {
	Core           *core.Core
	InsecureCookie bool
	PublicURL      string
	pages          map[string]*template.Template
}

const maxUpload = 4 << 20

func New(c *core.Core, insecureCookie bool, publicURL string) *Handler {
	h := &Handler{Core: c, InsecureCookie: insecureCookie, PublicURL: publicURL, pages: map[string]*template.Template{}}
	funcs := template.FuncMap{
		"claim": core.FormatClaim,
		"label": func(m string) string { return core.ModuleCatalog[m].Label },
		"order": func() []string { return core.ModuleOrder },
		"dt":    fmtTime,
		"dtp": func(t *time.Time) string {
			if t == nil {
				return "—"
			}
			return fmtTime(*t)
		},
		"kb": func(n int) string { return fmt.Sprintf("%.1f КБ", float64(n)/1024) },
		"short": func(s string) string {
			if len(s) > 12 {
				return s[:12]
			}
			return s
		},
		"has":    func(a core.Actor, roles ...string) bool { return a.Has(roles...) },
		"isroot": func(a core.Actor) bool { return a.Roles[core.RoleSuperadmin] },
		"inmods": func(mods []core.ProfileModule, name string) *core.ProfileModule {
			for i := range mods {
				if mods[i].Name == name {
					return &mods[i]
				}
			}
			return nil
		},
	}
	pages, _ := fs.Glob(assets, "templates/*.html")
	for _, p := range pages {
		name := strings.TrimSuffix(filepath.Base(p), ".html")
		if name == "layout" {
			continue
		}
		h.pages[name] = template.Must(template.New("layout.html").Funcs(funcs).ParseFS(assets, "templates/layout.html", p))
	}
	return h
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.Local().Format("02.01.2006 15:04")
}

func (h *Handler) Routes() http.Handler {
	r := chi.NewRouter()
	r.Use(securityHeaders)
	static, _ := fs.Sub(assets, "static")
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.FS(static))))
	r.Get("/login", h.loginPage)
	r.Post("/login", h.loginPost)
	r.Get("/login/totp", h.totpPage)
	r.Post("/login/totp", h.totpPost)
	r.Post("/logout", h.logout)
	r.Group(func(r chi.Router) {
		r.Use(h.requireLogin)
		r.Get("/", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/devices", http.StatusSeeOther) })
		r.Get("/devices", h.devices)
		r.Get("/devices/{id}", h.device)
		r.Post("/devices/{id}/config", h.deviceConfig)
		r.Post("/devices/{id}/flags", h.deviceFlags)
		r.Post("/devices/{id}/install", h.deviceInstall)
		r.Post("/devices/{id}/revoke", h.deviceRevoke)
		r.Post("/devices/{id}/password", h.devicePassword)
		r.Get("/register", h.register)
		r.Post("/register/claim", h.registerClaim)
		r.Post("/register/approve", h.registerApprove)
		r.Get("/profiles", h.profiles)
		r.Post("/profiles", h.profileSave)
		r.Get("/builds", h.builds)
		r.Post("/builds/app", h.uploadApp)
		r.Post("/builds/www", h.uploadWWW)
		r.Get("/builds/{id}/{file}", h.buildFile)
		r.Get("/releases", h.releases)
		r.Post("/releases", h.releaseCreate)
		r.Post("/releases/{id}/promote", h.releasePromote)
		r.Post("/releases/{id}/critical", h.releaseCritical)
		r.Get("/audit", h.auditPage)
		r.Get("/keys", h.keysPage)
	})
	return r
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

type page struct {
	Title  string
	Nav    string
	Actor  core.Actor
	CSRF   string
	Flash  string
	Error  string
	Data   any
	Public string
}

func (h *Handler) render(w http.ResponseWriter, r *http.Request, name, title string, data any) {
	p := page{Title: title, Nav: name, Data: data, Public: h.PublicURL}
	if s, ok := r.Context().Value(sessKey{}).(*session); ok {
		p.Actor, p.CSRF = s.actor, s.csrf
	}
	p.Flash = r.URL.Query().Get("ok")
	p.Error = r.URL.Query().Get("err")
	var buf bytes.Buffer
	if err := h.pages[name].Execute(&buf, p); err != nil {
		slog.Error("template", "page", name, "err", err)
		http.Error(w, "template error", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	buf.WriteTo(w)
}

// back redirects with a message (PRG pattern).
func back(w http.ResponseWriter, r *http.Request, to string, err error, ok string) {
	sep := "?"
	if strings.Contains(to, "?") {
		sep = "&"
	}
	if err != nil {
		msg := "внутрішня помилка"
		if e, isUser := core.AsError(err); isUser {
			msg = e.Msg
		} else {
			slog.Error("admin action", "path", r.URL.Path, "err", err)
		}
		http.Redirect(w, r, to+sep+"err="+urlq(msg), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, to+sep+"ok="+urlq(ok), http.StatusSeeOther)
}

func urlq(s string) string { return strings.ReplaceAll(templateURL(s), "+", "%20") }

func templateURL(s string) string { return template.URLQueryEscaper(s) }

func (h *Handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	if e, ok := core.AsError(err); ok {
		http.Error(w, e.Msg, e.Status)
		return
	}
	slog.Error("admin", "path", r.URL.Path, "err", err)
	http.Error(w, "внутрішня помилка", 500)
}

// ── login ───────────────────────────────────────────────────────────────────

func (h *Handler) loginPage(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, "login", "Вхід", nil)
}

func (h *Handler) loginPost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	login := strings.TrimSpace(r.FormValue("login"))
	if h.loginBlocked(ctx, login) {
		http.Redirect(w, r, "/login?err="+urlq("забагато невдалих спроб, зачекайте 15 хвилин"), http.StatusSeeOther)
		return
	}
	var id, hash, status string
	err := h.Core.Pool.QueryRow(ctx, `SELECT id, password_hash, status FROM users WHERE login=$1`, login).Scan(&id, &hash, &status)
	if err != nil || status != "active" || !checkPassword(hash, r.FormValue("password")) {
		h.loginFailed(ctx, login)
		http.Redirect(w, r, "/login?err="+urlq("невірний логін або пароль"), http.StatusSeeOther)
		return
	}
	if err := h.newSession(ctx, w, r, id); err != nil {
		h.fail(w, r, err)
		return
	}
	http.Redirect(w, r, "/login/totp", http.StatusSeeOther)
}

type totpData struct {
	Setup  bool
	Secret string
	QR     template.URL
}

func (h *Handler) totpPage(w http.ResponseWriter, r *http.Request) {
	s, err := h.loadSession(r)
	if err != nil || s == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if s.totpOK {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	r = r.WithContext(contextWith(r, s))
	if s.totpOn {
		h.render(w, r, "totp", "Код TOTP", totpData{})
		return
	}
	// First login: enroll. The secret is kept (disabled) until a code confirms it.
	secret, err := h.pendingTOTPSecret(r, s)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	key, err := totpKey(s.actor.Login, secret)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	img, err := key.Image(220, 220)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	var buf bytes.Buffer
	png.Encode(&buf, img)
	h.render(w, r, "totp", "Налаштування TOTP", totpData{Setup: true, Secret: secret,
		QR: template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()))})
}

func (h *Handler) totpPost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	s, err := h.loadSession(r)
	if err != nil || s == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.FormValue("csrf")), []byte(s.csrf)) != 1 {
		http.Error(w, "CSRF", 403)
		return
	}
	if h.loginBlocked(ctx, s.actor.Login) {
		http.Redirect(w, r, "/login/totp?err="+urlq("забагато невдалих спроб, зачекайте 15 хвилин"), http.StatusSeeOther)
		return
	}
	var enc []byte
	if err := h.Core.Pool.QueryRow(ctx, `SELECT totp_secret_enc FROM users WHERE id=$1`, s.actor.UserID).Scan(&enc); err != nil || enc == nil {
		http.Redirect(w, r, "/login/totp", http.StatusSeeOther)
		return
	}
	secret, err := h.Core.Env.Open(enc, "user:"+s.actor.UserID+":totp")
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if !totp.Validate(strings.ReplaceAll(r.FormValue("code"), " ", ""), string(secret)) {
		h.loginFailed(ctx, s.actor.Login)
		http.Redirect(w, r, "/login/totp?err="+urlq("невірний код"), http.StatusSeeOther)
		return
	}
	if !s.totpOn {
		h.Core.Pool.Exec(ctx, `UPDATE users SET totp_enabled=true WHERE id=$1`, s.actor.UserID)
		audit.Log(ctx, h.Core.Pool, audit.Entry{ActorType: "user", ActorID: audit.Str(s.actor.UserID), Action: "user.totp_enroll", IP: httpapi.ClientIP(r)})
	}
	// Rotate the session id on privilege change.
	h.Core.Pool.Exec(ctx, `DELETE FROM web_sessions WHERE id_hash=$1`, s.hash)
	t := token(32)
	if _, err := h.Core.Pool.Exec(ctx, `INSERT INTO web_sessions (id_hash, user_id, csrf, totp_ok, expires_at, ip, user_agent)
		VALUES ($1,$2,$3,true,$4,$5,$6)`, hashToken(t), s.actor.UserID, token(24), time.Now().Add(sessionMaxAge), httpapi.ClientIP(r), r.UserAgent()); err != nil {
		h.fail(w, r, err)
		return
	}
	h.setCookie(w, t, int(sessionMaxAge.Seconds()))
	audit.Log(ctx, h.Core.Pool, audit.Entry{ActorType: "user", ActorID: audit.Str(s.actor.UserID), Action: "user.login", IP: httpapi.ClientIP(r)})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	if s, _ := h.loadSession(r); s != nil {
		if subtle.ConstantTimeCompare([]byte(r.FormValue("csrf")), []byte(s.csrf)) == 1 {
			h.Core.Pool.Exec(r.Context(), `DELETE FROM web_sessions WHERE id_hash=$1`, s.hash)
		}
	}
	h.setCookie(w, "", -1)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ── devices ─────────────────────────────────────────────────────────────────

func (h *Handler) devices(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	list, err := h.Core.Devices(r.Context(), q)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.render(w, r, "devices", "Прилади", map[string]any{"Q": q, "List": list})
}

func (h *Handler) device(w http.ResponseWriter, r *http.Request) {
	d, err := h.Core.Device(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	prof, _, err := h.Core.Profile(r.Context(), h.Core.Pool, d.ProfileID)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	events, _ := h.Core.UpdateEvents(r.Context(), d.ID)
	rels, _ := h.Core.Releases(r.Context())
	var forProfile []core.Release
	for _, rel := range rels {
		if _, ok := rel.Apps[d.Profile]; ok {
			forProfile = append(forProfile, rel)
		}
	}
	offer, _ := h.Core.SelectUpdate(r.Context(), d.ID)
	h.render(w, r, "device", d.Serial, map[string]any{"D": d, "Profile": prof, "Events": events,
		"Releases": forProfile, "Offer": offer, "Password": r.URL.Query().Get("pw") == "1"})
}

func paramsFromForm(r *http.Request, mods []core.ProfileModule) core.HardParams {
	p := core.HardParams{Modules: map[string]bool{}, Ranges: map[string]core.Range{}}
	for _, m := range mods {
		p.Modules[m.Name] = r.FormValue("mod_"+m.Name) == "on"
		mn, _ := strconv.Atoi(r.FormValue("min_" + m.Name))
		mx, _ := strconv.Atoi(r.FormValue("max_" + m.Name))
		p.Ranges[m.Name] = core.Range{Min: mn, Max: mx}
	}
	return p
}

func (h *Handler) deviceConfig(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	d, err := h.Core.Device(r.Context(), id)
	if err == nil {
		var prof core.Profile
		prof, _, err = h.Core.Profile(r.Context(), h.Core.Pool, d.ProfileID)
		if err == nil {
			err = h.Core.UpdateConfig(r.Context(), actor(r), id, paramsFromForm(r, prof.Modules))
		}
	}
	back(w, r, "/devices/"+id, err, "конфігурацію підписано, прилад отримає її при наступній перевірці оновлень")
}

func (h *Handler) deviceFlags(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	err := h.Core.SetFlags(r.Context(), actor(r), id, r.FormValue("is_test") == "on", r.FormValue("pinned") == "on")
	back(w, r, "/devices/"+id, err, "збережено")
}

func (h *Handler) deviceInstall(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	err := h.Core.AssignRelease(r.Context(), actor(r), id, r.FormValue("release_id"))
	back(w, r, "/devices/"+id, err, "версію призначено")
}

func (h *Handler) deviceRevoke(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	revoke := r.FormValue("action") == "revoke"
	err := h.Core.SetRevoked(r.Context(), actor(r), id, revoke, r.FormValue("reason"))
	back(w, r, "/devices/"+id, err, "збережено")
}

func (h *Handler) devicePassword(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	pw, err := h.Core.WebPassword(r.Context(), actor(r), id)
	if err != nil {
		back(w, r, "/devices/"+id, err, "")
		return
	}
	d, _ := h.Core.Device(r.Context(), id)
	h.render(w, r, "password", "Пароль приладу", map[string]any{"D": d, "Password": pw})
}

// ── registration ────────────────────────────────────────────────────────────

func (h *Handler) register(w http.ResponseWriter, r *http.Request) {
	profiles, err := h.Core.Profiles(r.Context())
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.render(w, r, "register", "Реєстрація приладу", map[string]any{"Profiles": profiles})
}

func (h *Handler) registerClaim(w http.ResponseWriter, r *http.Request) {
	cl, err := h.Core.ClaimCode(r.Context(), actor(r), r.FormValue("code"))
	if err != nil {
		back(w, r, "/register", err, "")
		return
	}
	profiles, _ := h.Core.Profiles(r.Context())
	var active []core.Profile
	for _, p := range profiles {
		if p.Active {
			active = append(active, p)
		}
	}
	h.render(w, r, "register", "Реєстрація приладу", map[string]any{"Claim": cl, "Profiles": active})
}

func (h *Handler) registerApprove(w http.ResponseWriter, r *http.Request) {
	prof, _, err := h.Core.Profile(r.Context(), h.Core.Pool, r.FormValue("profile"))
	if err != nil {
		back(w, r, "/register", err, "")
		return
	}
	id, err := h.Core.Approve(r.Context(), actor(r), core.ApproveInput{
		RequestID: r.FormValue("request_id"), Profile: prof.Code,
		Params: paramsFromForm(r, prof.Modules), Reregister: r.FormValue("reregister") == "on",
	})
	if err != nil {
		back(w, r, "/register", err, "")
		return
	}
	back(w, r, "/devices/"+id, nil, "прилад зареєстровано; він отримає ключі протягом кількох секунд і почне оновлення")
}

// ── profiles ────────────────────────────────────────────────────────────────

func (h *Handler) profiles(w http.ResponseWriter, r *http.Request) {
	list, err := h.Core.Profiles(r.Context())
	if err != nil {
		h.fail(w, r, err)
		return
	}
	var edit *core.Profile
	if id := r.URL.Query().Get("edit"); id != "" {
		for i := range list {
			if list[i].ID == id {
				edit = &list[i]
			}
		}
	}
	h.render(w, r, "profiles", "Профілі", map[string]any{"List": list, "Edit": edit, "Catalog": core.DefaultModules()})
}

func (h *Handler) profileSave(w http.ResponseWriter, r *http.Request) {
	a := actor(r)
	if !a.Roles[core.RoleSuperadmin] {
		back(w, r, "/profiles", &core.Error{Status: 403, Msg: "лише superadmin"}, "")
		return
	}
	var mods []core.ProfileModule
	for _, name := range core.ModuleOrder {
		if r.FormValue("mod_"+name) != "on" {
			continue
		}
		mn, _ := strconv.Atoi(r.FormValue("lmin_" + name))
		mx, _ := strconv.Atoi(r.FormValue("lmax_" + name))
		mods = append(mods, core.ProfileModule{Name: name, Limit: core.Range{Min: mn, Max: mx}})
	}
	_, err := h.Core.SaveProfile(r.Context(), a, r.FormValue("id"), core.ProfileInput{
		Code: strings.TrimSpace(r.FormValue("code")), Name: strings.TrimSpace(r.FormValue("name")),
		Description: r.FormValue("description"), Modules: mods, Defaults: core.DefaultParams(mods),
	})
	back(w, r, "/profiles", err, "профіль збережено")
}

// ── builds and releases ─────────────────────────────────────────────────────

func (h *Handler) builds(w http.ResponseWriter, r *http.Request) {
	list, err := h.Core.Builds(r.Context(), "")
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.render(w, r, "builds", "Збірки", map[string]any{"List": list})
}

func formFile(r *http.Request, name string) ([]byte, error) {
	f, _, err := r.FormFile(name)
	if err == http.ErrMissingFile {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxUpload*2))
}

func (h *Handler) uploadApp(w http.ResponseWriter, r *http.Request) {
	img, err := formFile(r, "app")
	if err != nil || img == nil {
		back(w, r, "/builds", &core.Error{Msg: "оберіть файл образу"}, "")
		return
	}
	elf, _ := formFile(r, "elf")
	_, err = h.Core.UploadApp(r.Context(), actor(r), img, elf)
	back(w, r, "/builds", err, "збірку перевірено й підписано")
}

func (h *Handler) uploadWWW(w http.ResponseWriter, r *http.Request) {
	data, err := formFile(r, "www")
	if err != nil || data == nil {
		back(w, r, "/builds", &core.Error{Msg: "оберіть www.tar"}, "")
		return
	}
	_, err = h.Core.UploadWWW(r.Context(), actor(r), data)
	back(w, r, "/builds", err, "інтерфейс перевірено, контейнер .zwww підписано")
}

func (h *Handler) buildFile(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "file")
	p, err := h.Core.BuildFile(r.Context(), actor(r), chi.URLParam(r, "id"), name)
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
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-%s"`, chi.URLParam(r, "id")[:8], name))
	http.ServeContent(w, r, name, time.Time{}, f)
}

func (h *Handler) releases(w http.ResponseWriter, r *http.Request) {
	rels, err := h.Core.Releases(r.Context())
	if err != nil {
		h.fail(w, r, err)
		return
	}
	apps, _ := h.Core.Builds(r.Context(), "app")
	wwws, _ := h.Core.Builds(r.Context(), "www")
	profiles, _ := h.Core.Profiles(r.Context())
	byProfile := map[string][]core.Build{}
	for _, b := range apps {
		byProfile[b.Profile] = append(byProfile[b.Profile], b)
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].Code < profiles[j].Code })
	h.render(w, r, "releases", "Релізи", map[string]any{"List": rels, "Apps": byProfile, "WWW": wwws, "Profiles": profiles})
}

func (h *Handler) releaseCreate(w http.ResponseWriter, r *http.Request) {
	profiles, _ := h.Core.Profiles(r.Context())
	apps := map[string]string{}
	for _, p := range profiles {
		if b := r.FormValue("app_" + p.Code); b != "" {
			apps[p.ID] = b
		}
	}
	_, err := h.Core.CreateRelease(r.Context(), actor(r), core.ReleaseInput{
		Version: strings.TrimSpace(r.FormValue("version")), Notes: r.FormValue("notes"),
		WWWBuildID: r.FormValue("www"), Apps: apps,
	})
	back(w, r, "/releases", err, "реліз створено в каналі beta")
}

func (h *Handler) releasePromote(w http.ResponseWriter, r *http.Request) {
	err := h.Core.Promote(r.Context(), actor(r), chi.URLParam(r, "id"), r.FormValue("critical") == "on")
	back(w, r, "/releases", err, "реліз переведено в stable")
}

func (h *Handler) releaseCritical(w http.ResponseWriter, r *http.Request) {
	err := h.Core.SetCritical(r.Context(), actor(r), chi.URLParam(r, "id"), r.FormValue("critical") == "1")
	back(w, r, "/releases", err, "збережено")
}

// ── audit and keys ──────────────────────────────────────────────────────────

type auditRow struct {
	At                            time.Time
	ActorType, Actor, Action      string
	TargetType, TargetID, Details string
	IP                            string
}

func (h *Handler) auditPage(w http.ResponseWriter, r *http.Request) {
	if !actor(r).Has(core.RoleAdmin) {
		h.fail(w, r, &core.Error{Status: 403, Msg: "недостатньо прав"})
		return
	}
	rows, err := h.Core.Pool.Query(r.Context(), `SELECT a.at, a.actor_type, COALESCE(u.login, d.serial, a.actor_id::text, ''), a.action,
		COALESCE(a.target_type,''), COALESCE(a.target_id::text,''), COALESCE(a.details::text,''), COALESCE(host(a.ip),'')
		FROM audit_log a LEFT JOIN users u ON u.id=a.actor_id LEFT JOIN devices d ON d.id=a.actor_id
		ORDER BY a.id DESC LIMIT 300`)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	defer rows.Close()
	var list []auditRow
	for rows.Next() {
		var a auditRow
		if err := rows.Scan(&a.At, &a.ActorType, &a.Actor, &a.Action, &a.TargetType, &a.TargetID, &a.Details, &a.IP); err != nil {
			h.fail(w, r, err)
			return
		}
		list = append(list, a)
	}
	h.render(w, r, "audit", "Аудит", list)
}

func (h *Handler) keysPage(w http.ResponseWriter, r *http.Request) {
	type key struct {
		Kid, Purpose, PEM string
		Active            bool
	}
	var keys []key
	for _, k := range h.Core.Signer.PublicKeys() {
		pemData, _ := pemOf(k.Key)
		keys = append(keys, key{k.Kid, string(k.Purpose), string(pemData), k.Active})
	}
	h.render(w, r, "keys", "Ключі сервера", keys)
}
