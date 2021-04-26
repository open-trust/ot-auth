package dgraph

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/open-trust/ot-auth/src/conf"
	"github.com/open-trust/ot-auth/src/util"

	"github.com/dgraph-io/dgo/v200"
	"github.com/dgraph-io/dgo/v200/protos/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding/gzip"
)

func init() {
	util.DigProvide(NewDgraph)
}

// Nquads ...
type Nquads struct {
	ID    string
	Type  string
	UKkey string
	UKval string
	KV    map[string]interface{}
}

func scalarVal(v interface{}) string {
	switch val := v.(type) {
	case string:
		if val == "*" || val[:1] == "<" || val[:2] == "_:" || val[:4] == "uid(" || val[:4] == "val(" {
			return val
		}
		return strconv.Quote(val)
	case time.Time:
		return fmt.Sprintf("\"%s\"", val.UTC().Format(time.RFC3339))
	default:
		return fmt.Sprintf("\"%v\"", val)
	}
}

// WithLang ...
type WithLang struct {
	V string
	L string
}

func (l WithLang) String() string {
	return fmt.Sprintf("%s@%s", strconv.Quote(l.V), l.L)
}

// WithFacets ...
type WithFacets struct {
	V  interface{}
	KV map[string]interface{}
}

func (fs WithFacets) String() string {
	if len(fs.KV) == 0 {
		return scalarVal(fs.V)
	}
	kv := make([]string, 0, len(fs.KV))
	for k, v := range fs.KV {
		switch val := v.(type) {
		case string:
			kv = append(kv, fmt.Sprintf("%s=%s", k, strconv.Quote(val)))
		case time.Time:
			kv = append(kv, fmt.Sprintf("%s=%s", k, val.UTC().Format(time.RFC3339)))
		default:
			kv = append(kv, fmt.Sprintf("%s=%v", k, v))
		}
	}
	return fmt.Sprintf("%s (%s)", scalarVal(fs.V), strings.Join(kv, ", "))
}

// Bytes ...
func (ns Nquads) Bytes() ([]byte, error) {
	if ns.ID == "" {
		return nil, errors.New("ID are required")
	}

	id := ns.ID
	if id[:1] != "<" && id[:2] != "_:" && id[:4] != "uid(" {
		id = fmt.Sprintf("<%s>", id)
	}

	b := new(bytes.Buffer)
	if ns.Type != "" {
		if err := writeNquad(b, id, "dgraph.type", ns.Type); err != nil {
			return nil, err
		}
	}

	for k, v := range ns.KV {
		if err := writeNquad(b, id, k, v); err != nil {
			return nil, err
		}
	}
	return b.Bytes(), nil
}

func writeNquad(w io.Writer, subject, predicate string, object interface{}) error {
	var err error
	switch val := object.(type) {
	case string, bool, int, int64, float64, time.Time:
		_, err = fmt.Fprintf(w, "%s <%s> %s .\n", subject, predicate, scalarVal(val))
	case WithLang:
		_, err = fmt.Fprintf(w, "%s <%s> %s .\n", subject, predicate, val.String())
	case WithFacets:
		_, err = fmt.Fprintf(w, "%s <%s> %s .\n", subject, predicate, val.String())
	case []string:
		for _, v := range val {
			_, err = fmt.Fprintf(w, "%s <%s> %s .\n", subject, predicate, scalarVal(v))
		}
	case []int:
		for _, v := range val {
			_, err = fmt.Fprintf(w, "%s <%s> \"%v\" .\n", subject, predicate, v)
		}
	case []int64:
		for _, v := range val {
			_, err = fmt.Fprintf(w, "%s <%s> \"%v\" .\n", subject, predicate, v)
		}
	case []float64:
		for _, v := range val {
			_, err = fmt.Fprintf(w, "%s <%s> \"%v\" .\n", subject, predicate, v)
		}
	case []time.Time:
		for _, v := range val {
			_, err = fmt.Fprintf(w, "%s <%s> \"%s\" .\n", subject, predicate, v.Format(time.RFC3339))
		}
	default:
		err = fmt.Errorf("invalid value: %#v", object)
	}
	return err
}

// Dgraph ...
type Dgraph struct {
	*dgo.Dgraph
	dc api.DgraphClient
}

// NewDgraph ...
func NewDgraph() (*Dgraph, error) {
	opts := []grpc.DialOption{
		grpc.WithDefaultCallOptions(grpc.UseCompressor(gzip.Name)),
	}
	if conf.Config.Dgraph.Insecure {
		opts = append(opts, grpc.WithInsecure())
	}
	conn, err := grpc.Dial(conf.Config.Dgraph.GRPCEndpoint, opts...)

	if err != nil {
		return nil, err
	}

	dc := api.NewDgraphClient(conn)
	dg := dgo.NewDgraphClient(dc)
	return &Dgraph{Dgraph: dg, dc: dc}, nil
}

// CheckHealth ...
func (dg *Dgraph) CheckHealth(ctx context.Context) (interface{}, error) {
	_, err := dg.dc.CheckVersion(ctx, &api.Check{})
	if err != nil {
		return nil, err
	}
	return map[string]string{"status": "OK"}, nil
}

// Query ...
func (dg *Dgraph) Query(ctx context.Context, query string, vars map[string]string, out interface{}) error {
	txn := dg.NewReadOnlyTxn().BestEffort()
	resp, err := txn.QueryWithVars(ctx, query, vars)
	if err == nil && out != nil {
		err = json.Unmarshal(resp.Json, out)
	}
	return err
}

// Do ...
func (dg *Dgraph) Do(ctx context.Context, query string, vars map[string]string, out interface{}, mus ...*api.Mutation) error {
	if len(mus) == 0 {
		return dg.Query(ctx, query, vars, out)
	}

	txn := dg.NewTxn()
	defer txn.Discard(ctx)

	req := &api.Request{
		Query:     query,
		Vars:      vars,
		Mutations: mus,
		CommitNow: true,
	}
	resp, err := txn.Do(ctx, req)
	if err == nil && out != nil {
		err = json.Unmarshal(resp.Json, out)
	}
	return err
}

// RunTxn ...
func (dg *Dgraph) RunTxn(ctx context.Context, fn func(txn *dgo.Txn) error) error {
	txn := dg.NewTxn()
	defer txn.Discard(ctx)
	err := fn(txn)
	if err == nil {
		err = txn.Commit(ctx)
	}
	return err
}
