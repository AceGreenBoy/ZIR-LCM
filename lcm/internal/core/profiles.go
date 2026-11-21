package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"zir/lcm/internal/audit"
	"zir/lcm/internal/db"
)

// Hardware limits of the receiver modules, MHz (FIRMWARE web-ui-brief).
var ModuleCatalog = map[string]struct {
	Label    string
	Min, Max int
}{
	"ft3500": {"FT3500 · 3.3 ГГц", 2000, 4050},
	"rx5808": {"RX5808 · 5.8 ГГц", 4900, 6184},
	"ta8804": {"TA8804 · 1.2 ГГц", 900, 2250},
}

// ModuleOrder is the order the device shows its modules in.
var ModuleOrder = []string{"ft3500", "rx5808", "ta8804"}

// Range is a frequency range in MHz.
type Range struct {
	Min int `json:"min"`
	Max int `json:"max"`
}

// HardParams are the signed parameters of a device: fitted modules and their
// frequency ranges.
type HardParams struct {
	Modules map[string]bool  `json:"modules"`
	Ranges  map[string]Range `json:"ranges"`
}

// ProfileModule describes a module compiled into a profile's firmware and the
// limits an engineer may set for it.
type ProfileModule struct {
	Name  string `json:"name"`
	Limit Range  `json:"limit"`
}

type Profile struct {
	ID          string
	Code        string
	Name        string
	Description string
	Modules     []ProfileModule // derived from the schema
	Defaults    HardParams
	Active      bool
}

var profileCodeRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,30}$`)

// BuildSchema generates the JSON Schema of hard params for a module set.
func BuildSchema(mods []ProfileModule) map[string]any {
	modProps := map[string]any{}
	rangeProps := map[string]any{}
	var names []string
	for _, m := range mods {
		names = append(names, m.Name)
		modProps[m.Name] = map[string]any{"type": "boolean"}
		bound := map[string]any{"type": "integer", "minimum": m.Limit.Min, "maximum": m.Limit.Max}
		rangeProps[m.Name] = map[string]any{
			"type": "object", "additionalProperties": false, "required": []string{"min", "max"},
			"properties": map[string]any{"min": bound, "max": bound},
		}
	}
	sort.Strings(names)
	return map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"type":    "object", "additionalProperties": false, "required": []string{"modules", "ranges"},
		"properties": map[string]any{
			"modules": map[string]any{"type": "object", "additionalProperties": false, "required": names, "properties": modProps},
			"ranges":  map[string]any{"type": "object", "additionalProperties": false, "required": names, "properties": rangeProps},
		},
		"x-zir-modules": mods,
	}
}

func modulesFromSchema(schema []byte) []ProfileModule {
	var s struct {
		Mods []ProfileModule `json:"x-zir-modules"`
	}
	json.Unmarshal(schema, &s)
	return s.Mods
}

// ValidateParams checks params against a profile's schema and ranges.
func ValidateParams(schema []byte, p HardParams) error {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schema))
	if err != nil {
		return err
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("profile.json", doc); err != nil {
		return err
	}
	sch, err := c.Compile("profile.json")
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(p)
	inst, _ := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err := sch.Validate(inst); err != nil {
		return userErr(400, "bad_params", "параметри не відповідають профілю: %v", err)
	}
	for name, r := range p.Ranges {
		if r.Min >= r.Max {
			return userErr(400, "bad_params", "%s: мінімальна частота має бути менша за максимальну", name)
		}
	}
	any := false
	for _, on := range p.Modules {
		any = any || on
	}
	if !any {
		return userErr(400, "bad_params", "має бути встановлено хоча б один модуль")
	}
	return nil
}

type ProfileInput struct {
	Code, Name, Description string
	Modules                 []ProfileModule
	Defaults                HardParams
}

func (in ProfileInput) check() ([]byte, error) {
	if !profileCodeRe.MatchString(in.Code) {
		return nil, userErr(400, "bad_profile", "код профілю: латиниця в нижньому регістрі, цифри, дефіс (2–31 символ)")
	}
	if in.Name == "" || len(in.Modules) == 0 {
		return nil, userErr(400, "bad_profile", "потрібні назва і хоча б один модуль")
	}
	for _, m := range in.Modules {
		hw, ok := ModuleCatalog[m.Name]
		if !ok {
			return nil, userErr(400, "bad_profile", "невідомий модуль %q", m.Name)
		}
		if m.Limit.Min < hw.Min || m.Limit.Max > hw.Max || m.Limit.Min >= m.Limit.Max {
			return nil, userErr(400, "bad_profile", "%s: межі мають бути в %d–%d МГц", m.Name, hw.Min, hw.Max)
		}
	}
	schema, _ := json.Marshal(BuildSchema(in.Modules))
	if err := ValidateParams(schema, in.Defaults); err != nil {
		return nil, userErr(400, "bad_profile", "типові параметри: %v", err)
	}
	return schema, nil
}

func (c *Core) SaveProfile(ctx context.Context, actor Actor, id string, in ProfileInput) (string, error) {
	schema, err := in.check()
	if err != nil {
		return "", err
	}
	defs, _ := json.Marshal(in.Defaults)
	err = db.InTx(ctx, c.Pool, func(tx pgxTx) error {
		if id == "" {
			err := tx.QueryRow(ctx, `INSERT INTO hw_profiles (code, name, description, params_schema, default_params)
				VALUES ($1,$2,$3,$4,$5) RETURNING id`, in.Code, in.Name, in.Description, schema, defs).Scan(&id)
			if db.IsUniqueViolation(err) {
				return userErr(409, "exists", "профіль %s вже існує", in.Code)
			}
			if err != nil {
				return err
			}
		} else {
			// The code is fixed: it names the profiles/<code>/ directory and is baked into firmware.
			if _, err := tx.Exec(ctx, `UPDATE hw_profiles SET name=$2, description=$3, params_schema=$4, default_params=$5 WHERE id=$1`,
				id, in.Name, in.Description, schema, defs); err != nil {
				return err
			}
		}
		return actor.audit(ctx, tx, "profile.save", "profile", id, map[string]any{"code": in.Code, "modules": in.Modules})
	})
	return id, err
}

func scanProfile(row interface{ Scan(...any) error }) (Profile, error) {
	var p Profile
	var schema, defs []byte
	if err := row.Scan(&p.ID, &p.Code, &p.Name, &p.Description, &schema, &defs, &p.Active); err != nil {
		return p, err
	}
	p.Modules = modulesFromSchema(schema)
	json.Unmarshal(defs, &p.Defaults)
	return p, nil
}

const profileCols = `id, code, name, description, params_schema, default_params, active`

func (c *Core) Profiles(ctx context.Context) ([]Profile, error) {
	rows, err := c.Pool.Query(ctx, `SELECT `+profileCols+` FROM hw_profiles ORDER BY code`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Profile
	for rows.Next() {
		p, err := scanProfile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (c *Core) Profile(ctx context.Context, q db.Q, idOrCode string) (Profile, []byte, error) {
	row := q.QueryRow(ctx, `SELECT `+profileCols+`, params_schema FROM hw_profiles WHERE id::text=$1 OR code=$1`, idOrCode)
	var p Profile
	var schema, defs, schema2 []byte
	err := row.Scan(&p.ID, &p.Code, &p.Name, &p.Description, &schema, &defs, &p.Active, &schema2)
	if db.IsNoRows(err) {
		return p, nil, userErr(404, "no_profile", "профіль %s не знайдено", idOrCode)
	}
	if err != nil {
		return p, nil, err
	}
	p.Modules = modulesFromSchema(schema)
	json.Unmarshal(defs, &p.Defaults)
	return p, schema, nil
}

// DefaultModules is the full module set with hardware limits.
func DefaultModules() []ProfileModule {
	var out []ProfileModule
	for _, n := range ModuleOrder {
		hw := ModuleCatalog[n]
		out = append(out, ProfileModule{Name: n, Limit: Range{hw.Min, hw.Max}})
	}
	return out
}

func DefaultParams(mods []ProfileModule) HardParams {
	p := HardParams{Modules: map[string]bool{}, Ranges: map[string]Range{}}
	for _, m := range mods {
		p.Modules[m.Name] = true
		p.Ranges[m.Name] = m.Limit
	}
	return p
}

func moduleLabel(name string) string {
	if m, ok := ModuleCatalog[name]; ok {
		return m.Label
	}
	return fmt.Sprintf("%s", name)
}

var _ = audit.Str
