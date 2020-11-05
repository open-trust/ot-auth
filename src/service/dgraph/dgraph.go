package dgraph

import (
	"context"
	"encoding/json"

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
