// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"fmt"

	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/source"
)

type writerAdapter struct {
	w *writer.Writer
}

type writerTxnAdapter struct {
	writer.WriteTxn
}

func newWriterAdapter(w *writer.Writer) writerAPI {
	return &writerAdapter{w: w}
}

func (a *writerAdapter) WriteTxn(extraTables ...statedb.TableMeta) writeTxn {
	return &writerTxnAdapter{WriteTxn: a.w.WriteTxn(extraTables...)}
}

func (a *writerAdapter) UpsertServiceAndFrontends(txn writeTxn, svc *loadbalancer.Service, fes ...loadbalancer.FrontendParams) error {
	real, err := unwrapTxn(txn)
	if err != nil {
		return err
	}
	return a.w.UpsertServiceAndFrontends(real, svc, fes...)
}

func (a *writerAdapter) DeleteServiceAndFrontends(txn writeTxn, name loadbalancer.ServiceName) (*loadbalancer.Service, error) {
	real, err := unwrapTxn(txn)
	if err != nil {
		return nil, err
	}
	return a.w.DeleteServiceAndFrontends(real, name)
}

func (a *writerAdapter) SetBackends(txn writeTxn, name loadbalancer.ServiceName, src source.Source, bes ...loadbalancer.BackendParams) error {
	real, err := unwrapTxn(txn)
	if err != nil {
		return err
	}
	return a.w.SetBackends(real, name, src, bes...)
}

func (t *writerTxnAdapter) Abort() {
	t.WriteTxn.Abort()
}

func (t *writerTxnAdapter) Commit() {
	t.WriteTxn.Commit()
}

func unwrapTxn(txn writeTxn) (writer.WriteTxn, error) {
	if real, ok := txn.(*writerTxnAdapter); ok {
		return real.WriteTxn, nil
	}
	return writer.WriteTxn{}, fmt.Errorf("unexpected transaction type %T", txn)
}
