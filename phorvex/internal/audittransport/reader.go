package audittransport

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"time"
)

// Reader pins one manifest segment identity and byte size. It never observes
// later appends or a replacement while a history/derived request is running.
// Each bounded chunk is fetched over the authenticated source and checked
// against this generation; failure is an error, never an empty audit record.
type Reader struct {
	Client     *Client
	Segment    Segment
	Ctx        context.Context
	mu         sync.Mutex
	position   int64
	cacheStart int64
	cache      []byte
}

func (c *Client) Open(ctx context.Context, s Segment) *Reader {
	return &Reader{Client: c, Segment: s, Ctx: ctx, cacheStart: -1}
}
func (r *Reader) Generation() string { return r.Segment.Generation }
func (r *Reader) Name() string       { return "audit://" + r.Segment.ID }
func (r *Reader) Close() error       { return nil }
func (r *Reader) Verify() error {
	if r.Segment.Size > 0 {
		_, e := r.Client.Chunk(r.Ctx, r.Segment, r.Segment.Size-1)
		return e
	}
	m, e := r.Client.Manifest(r.Ctx)
	if e != nil {
		return e
	}
	for _, s := range m.Segments {
		if s.Generation == r.Segment.Generation && s.ID == r.Segment.ID {
			return nil
		}
	}
	return errors.New("empty audit generation no longer retained")
}

type remoteInfo struct {
	name string
	size int64
}

func (i remoteInfo) Name() string       { return i.name }
func (i remoteInfo) Size() int64        { return i.size }
func (i remoteInfo) Mode() os.FileMode  { return 0600 }
func (i remoteInfo) ModTime() time.Time { return time.Time{} }
func (i remoteInfo) IsDir() bool        { return false }
func (i remoteInfo) Sys() any           { return nil }
func (r *Reader) Stat() (os.FileInfo, error) {
	return remoteInfo{name: r.Segment.ID, size: r.Segment.Size}, nil
}

func (r *Reader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("negative audit read offset")
	}
	if off >= r.Segment.Size {
		return 0, io.EOF
	}
	read := 0
	for read < len(p) && off+int64(read) < r.Segment.Size {
		start := ((off + int64(read)) / ChunkBytes) * ChunkBytes
		r.mu.Lock()
		if r.cacheStart != start {
			b, e := r.Client.Chunk(r.Ctx, r.Segment, start)
			if e != nil {
				r.mu.Unlock()
				return read, e
			}
			r.cache = b
			r.cacheStart = start
		}
		at := int(off + int64(read) - start)
		n := copy(p[read:], r.cache[at:])
		r.mu.Unlock()
		if n == 0 {
			return read, io.ErrUnexpectedEOF
		}
		read += n
	}
	if read < len(p) {
		return read, io.EOF
	}
	return read, nil
}
func (r *Reader) Read(p []byte) (int, error) {
	r.mu.Lock()
	off := r.position
	r.mu.Unlock()
	n, e := r.ReadAt(p, off)
	r.mu.Lock()
	r.position += int64(n)
	r.mu.Unlock()
	return n, e
}
func (r *Reader) Seek(offset int64, whence int) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var next int64
	switch whence {
	case io.SeekStart:
		next = offset
	case io.SeekCurrent:
		next = r.position + offset
	case io.SeekEnd:
		next = r.Segment.Size + offset
	default:
		return r.position, errors.New("invalid audit seek")
	}
	if next < 0 {
		return r.position, errors.New("negative audit seek")
	}
	r.position = next
	return next, nil
}
