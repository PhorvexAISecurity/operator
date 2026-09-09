package ingest

import (
	"context"
	"reflect"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type ownerReadKey struct {
	kind reflect.Type
	key  client.ObjectKey
}
type ownerRead struct {
	object client.Object
	err    error
}

// Snapshot-local only: never use this reader at the destructive boundary. Each
// pod still has its own UID, selector and lifecycle checked against cached owners.
type snapshotOwnerReader struct {
	client.Reader
	reads map[ownerReadKey]ownerRead
}

func newSnapshotOwnerReader(r client.Reader) client.Reader {
	if r == nil {
		return nil
	}
	return &snapshotOwnerReader{Reader: r, reads: make(map[ownerReadKey]ownerRead)}
}
func (r *snapshotOwnerReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	k := ownerReadKey{reflect.TypeOf(obj), key}
	v, ok := r.reads[k]
	if !ok {
		err := r.Reader.Get(ctx, key, obj, opts...)
		v = ownerRead{err: err}
		if err == nil {
			v.object = obj.DeepCopyObject().(client.Object)
		}
		r.reads[k] = v
	}
	if v.err == nil {
		reflect.ValueOf(obj).Elem().Set(reflect.ValueOf(v.object.DeepCopyObject()).Elem())
	}
	return v.err
}
