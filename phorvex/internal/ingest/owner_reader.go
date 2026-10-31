package ingest

import (
	"context"
	"errors"
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

var errOwnerObjectNotObserved = errors.New("owner object was not observed by this snapshot's existing owner reads")

// Snapshot evidence can inspect only objects already read by the rotation
// producer. It has no route to issue an additional API Get or List.
type snapshotEvidenceReader struct{ cache *snapshotOwnerReader }

func ownerEvidenceReader(r client.Reader) client.Reader {
	cache, ok := r.(*snapshotOwnerReader)
	if !ok || cache == nil {
		return nil
	}
	return snapshotEvidenceReader{cache: cache}
}
func (r snapshotEvidenceReader) Get(_ context.Context, key client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
	value, ok := r.cache.reads[ownerReadKey{reflect.TypeOf(obj), key}]
	if !ok {
		return errOwnerObjectNotObserved
	}
	if value.err != nil {
		return value.err
	}
	reflect.ValueOf(obj).Elem().Set(reflect.ValueOf(value.object.DeepCopyObject()).Elem())
	return nil
}
func (snapshotEvidenceReader) List(context.Context, client.ObjectList, ...client.ListOption) error {
	return errOwnerObjectNotObserved
}
