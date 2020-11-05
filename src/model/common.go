package model

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/dgraph-io/dgo/v200/protos/api"
	"github.com/open-trust/ot-auth/src/conf"
	"github.com/open-trust/ot-auth/src/service/dgraph"
	"github.com/open-trust/ot-auth/src/util"
	otgo "github.com/open-trust/ot-go-lib"
	"github.com/teambition/gear"
)

func init() {
	util.DigProvide(NewModels)
}

// Model ...
type Model struct {
	*dgraph.Dgraph
}

// Models ...
type Models struct {
	Model        *Model
	Federation   *Federation
	Registration *Registration
}

// NewModels ...
func NewModels(dg *dgraph.Dgraph) *Models {
	m := &Model{dg}
	return &Models{
		Model:        m,
		Federation:   &Federation{m},
		Registration: &Registration{m},
	}
}

// RegistryUKkey ...
func RegistryUKkey(id otgo.OTID) string {
	switch conf.SubjectType(id) {
	case 1:
		return "userUK"
	case 2:
		return "serviceUK"
	default:
		return ""
	}
}

// VerificationInfo ...
type VerificationInfo struct {
	ID               otgo.OTID
	Status           int      `json:"status"`
	ReleaseID        string   `json:"releaseId"`
	Keys             []string `json:"keys"`
	AllowedList      []string `json:"allowedList"`
	ServiceEndpoints []string `json:"serviceEndpoints"`
}

// Nquads ...
type Nquads struct {
	ID    string
	Type  string
	UKkey string
	UKval string
	KV    map[string]interface{}
}

// Bytes ...
func (ns Nquads) Bytes() ([]byte, error) {
	if ns.ID == "" {
		return nil, errors.New("ID are required")
	}

	id := ns.ID
	if !strings.HasPrefix(id, "_:") && !strings.HasPrefix(id, "uid(") {
		id = fmt.Sprintf("<%s>", id)
	}

	var b bytes.Buffer
	if ns.Type != "" {
		fmt.Fprintf(&b, "%s <%s> \"%v\" .\n", id, "dgraph.type", ns.Type)
	}
	for k, v := range ns.KV {
		switch val := v.(type) {
		case bool:
			fmt.Fprintf(&b, "%s <%s> \"%t\"^^<xs:boolean> .\n", id, k, val)
		case string:
			if val != "*" && !strings.HasPrefix(val, "uid(") && !strings.HasPrefix(val, "val(") {
				val = strconv.Quote(val)
			}
			fmt.Fprintf(&b, "%s <%s> %s .\n", id, k, val)
		case int, int64:
			fmt.Fprintf(&b, "%s <%s> \"%v\"^^<xs:int> .\n", id, k, val)
		case float64:
			fmt.Fprintf(&b, "%s <%s> \"%v\"^^<xs:double> .\n", id, k, val)
		case time.Time:
			fmt.Fprintf(&b, "%s <%s> \"%s\"^^<xs:dateTime> .\n", id, k, val.UTC().Format(time.RFC3339))
		case []string:
			for _, e := range val {
				if e != "*" && !strings.HasPrefix(e, "uid(") && !strings.HasPrefix(e, "val(") {
					e = strconv.Quote(e)
				}
				fmt.Fprintf(&b, "%s <%s> %s .\n", id, k, e)
			}
		case []int:
			for _, e := range val {
				fmt.Fprintf(&b, "%s <%s> \"%v\"^^<xs:int> .\n", id, k, e)
			}
		case []int64:
			for _, e := range val {
				fmt.Fprintf(&b, "%s <%s> \"%v\"^^<xs:int> .\n", id, k, e)
			}
		case []float64:
			for _, e := range val {
				fmt.Fprintf(&b, "%s <%s> \"%v\"^^<xs:double> .\n", id, k, e)
			}
		case []time.Time:
			for _, e := range val {
				fmt.Fprintf(&b, "%s <%s> \"%s\"^^<xs:dateTime> .\n", id, k, e.Format(time.RFC3339))
			}
		default:
			return nil, fmt.Errorf("invalid value: %v", v)
		}
	}
	return b.Bytes(), nil
}

type jsonUID struct {
	UID string `json:"uid"`
}

// Create ...
func (m *Model) Create(ctx context.Context, nq *Nquads) error {
	if nq.UKkey == "" || nq.UKval == "" || nq.Type == "" {
		return errors.New("UK and Type required for Create")
	}

	q := fmt.Sprintf(`query {
		result(func: eq(%s, "%s")) {
			_uid as uid
		}
	}
	`, nq.UKkey, nq.UKval)

	nq.ID = "_:x"
	nq.KV[nq.UKkey] = nq.UKval
	data, err := nq.Bytes()
	if err != nil {
		return err
	}

	r := make([]*jsonUID, 0)
	out := &otgo.Response{Result: &r}
	err = m.Do(ctx, q, nil, out, &api.Mutation{
		Cond:      "@if(eq(len(_uid), 0))",
		SetNquads: data,
	})
	if err != nil {
		return err
	}
	if len(r) > 0 {
		return gear.ErrConflict.WithMsgf("%s exists", r[0].UID)
	}
	return nil
}

// CreateOrUpdate ...
func (m *Model) CreateOrUpdate(ctx context.Context, qs string, create, update *Nquads) error {
	if create.UKkey == "" || create.UKval == "" || create.Type == "" {
		return errors.New("UK and Type required for CreateOrUpdate")
	}

	q := fmt.Sprintf(`query {
		result(func: eq(%s, "%s")) {
			_uid as uid
		}
		%s
	}
	`, create.UKkey, create.UKval, qs)

	create.ID = "_:x"
	create.KV[create.UKkey] = create.UKval
	createData, err := create.Bytes()
	if err != nil {
		return err
	}

	update.ID = "uid(_uid)"
	updateData, err := update.Bytes()
	if err != nil {
		return err
	}

	r := make([]*jsonUID, 0)
	out := &otgo.Response{Result: &r}
	err = m.Do(ctx, q, nil, out, &api.Mutation{
		Cond:      "@if(eq(len(_uid), 0))",
		SetNquads: createData,
	}, &api.Mutation{
		Cond:      "@if(eq(len(_uid), 1))",
		SetNquads: updateData,
	})
	if err != nil {
		return err
	}
	if len(r) > 1 {
		return gear.ErrUnprocessableEntity.WithMsgf("unexpected resources: %v", r)
	}
	return nil
}

// Get ...
func (m *Model) Get(ctx context.Context, query string, vars map[string]string, one interface{}) error {
	res := make([]json.RawMessage, 0)
	out := &otgo.Response{Result: &res}
	err := m.Query(ctx, query, vars, out)
	if err != nil {
		return err
	}
	if len(res) == 0 {
		return gear.ErrNotFound.WithMsgf("resource not found")
	}
	if len(res) > 1 {
		return gear.ErrInternalServerError.WithMsgf("unexpected resources: %d", len(res))
	}
	return json.Unmarshal(res[0], one)
}
