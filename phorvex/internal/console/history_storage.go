package console

// Retention is opt-in. Normal service startup never copies the archive: bounded
// background maintenance expires records and compresses legacy values in place.
// Explicit offline compaction preserves importer offsets and cursor sequences.
import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

var historyStorageMeta = []byte("storage-v2")
var historyGzipPool = sync.Pool{New: func() any { w, _ := gzip.NewWriterLevel(io.Discard, gzip.BestSpeed); return w }}

func encodeHistoryValue(raw []byte) ([]byte, error) {
	if len(raw) < 512 {
		return bytes.Clone(raw), nil
	}
	var out bytes.Buffer
	w := historyGzipPool.Get().(*gzip.Writer)
	defer historyGzipPool.Put(w)
	w.Reset(&out)
	if _, err := w.Write(raw); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	if out.Len() >= len(raw) {
		return bytes.Clone(raw), nil
	}
	return out.Bytes(), nil
}
func decodeHistoryValue(value []byte) ([]byte, error) {
	const maximum = liveRecordBytes + (64 << 10)
	if len(value) > maximum {
		return nil, errors.New("oversized archived history record")
	}
	if !bytes.HasPrefix(value, []byte{0x1f, 0x8b}) {
		return value, nil
	}
	z, err := gzip.NewReader(bytes.NewReader(value))
	if err != nil {
		return nil, err
	}
	defer z.Close()
	raw, err := io.ReadAll(io.LimitReader(z, maximum+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maximum {
		return nil, errors.New("oversized compressed history record")
	}
	return raw, nil
}
func expiredHistoryValue(raw []byte, cutoff time.Time) (storedHistoryRecord, bool, error) {
	var env storedHistoryRecord
	if err := json.Unmarshal(raw, &env); err != nil {
		return env, false, err
	}
	var rec struct {
		Time time.Time `json:"time"`
	}
	if err := json.Unmarshal(env.Record, &rec); err != nil {
		return env, false, err
	}
	// Unknown timestamps cannot authorize deletion.
	return env, !rec.Time.IsZero() && rec.Time.Before(cutoff), nil
}

// prepareHistoryStorage is explicit offline maintenance, not a server startup step.
// The caller must arrange downtime and exclusive access for the full copy/verification.
func prepareHistoryStorage(cfg Config) error {
	if cfg.HistoryRetentionDays == 0 {
		return nil
	}
	path := filepath.Join(cfg.StateDir, "audit-history.db")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	src, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return err
	}
	defer src.Close()
	ready := false
	if err = src.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(historyStorageMeta)
		ready = b != nil && bytes.Equal(b.Get([]byte("format")), []byte("gzip-v1"))
		return nil
	}); err != nil {
		return err
	}
	if ready {
		return nil
	}
	return compactHistoryStorage(cfg, src)
}

// compactHistoryStorage requires the caller to own the source DB's exclusive lock.
func compactHistoryStorage(cfg Config, src *bolt.DB) error {
	maximum, minimum, reserve, err := cfg.historyCapacityLimits()
	if err != nil {
		return err
	}
	path := src.Path()
	tmp := path + ".compact"
	// A previous interrupted copy has never been published. Only this derived file is removed.
	if err = os.Remove(tmp); err != nil && !os.IsNotExist(err) {
		return err
	}
	defer os.Remove(tmp)
	checkSpace := func() error {
		usage, e := readHistoryFilesystemUsage(path)
		if e != nil {
			return e
		}
		if usage.availableBytes < minimum+reserve {
			return errors.New("history compaction refused: insufficient free-space reserve")
		}
		if st, e := os.Stat(tmp); e == nil && st.Size() > maximum-reserve {
			return errors.New("history compaction exceeds configured archive ceiling")
		}
		return nil
	}
	if err = checkSpace(); err != nil {
		return err
	}
	dst, err := bolt.Open(tmp, 0600, nil)
	if err != nil {
		return err
	}
	defer dst.Close()
	cutoff := cfg.now().Add(-time.Duration(cfg.HistoryRetentionDays) * 24 * time.Hour)
	var pruned uint64
	tx, err := dst.Begin(true)
	if err != nil {
		return err
	}
	defer func() {
		if tx != nil {
			_ = tx.Rollback()
		}
	}()
	batch := 0
	flush := func() error {
		if e := checkSpace(); e != nil {
			return e
		}
		if e := tx.Commit(); e != nil {
			return e
		}
		tx = nil
		var e error
		tx, e = dst.Begin(true)
		batch = 0
		return e
	}
	err = src.View(func(st *bolt.Tx) error {
		return st.ForEach(func(name []byte, b *bolt.Bucket) error {
			if bytes.Equal(name, historyStorageMeta) {
				return nil
			}
			target, e := tx.CreateBucket(name)
			if e != nil {
				return e
			}
			if e = target.SetSequence(b.Sequence()); e != nil {
				return e
			}
			return b.ForEach(func(k, v []byte) error {
				if v == nil {
					return errors.New("unexpected nested history bucket; original archive retained")
				}
				value := v
				if bytes.Equal(name, historyRecords) {
					raw, e := decodeHistoryValue(v)
					if e != nil {
						return e
					}
					_, expired, e := expiredHistoryValue(raw, cutoff)
					if e != nil {
						return e
					}
					if expired {
						pruned++
						return nil
					}
					value, e = encodeHistoryValue(raw)
					if e != nil {
						return e
					}
				} else if bytes.Equal(name, historySeen) {
					if tx.Bucket(historyRecords).Get(v) == nil {
						return nil
					}
				} else if bytes.Equal(name, historyIndex) {
					if len(k) < 8 {
						return errors.New("invalid history index key")
					}
					if tx.Bucket(historyRecords).Get(k[len(k)-8:]) == nil {
						return nil
					}
				}
				target = tx.Bucket(name)
				target.FillPercent = 0.9
				if e = target.Put(k, value); e != nil {
					return e
				}
				batch += len(k) + len(value)
				if batch >= historyBatchBytes {
					return flush()
				}
				return nil
			})
		})
	})
	if err != nil {
		return err
	}
	meta, err := tx.CreateBucketIfNotExists(historyStorageMeta)
	if err != nil {
		return err
	}
	if err = meta.Put([]byte("format"), []byte("gzip-v1")); err != nil {
		return err
	}
	if err = meta.Put([]byte("initial-pruned"), []byte(fmt.Sprint(pruned))); err != nil {
		return err
	}
	if err = checkSpace(); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	tx = nil
	// Compare every surviving value to the original, including offsets, gaps, and sequences.
	err = src.View(func(st *bolt.Tx) error {
		return dst.View(func(dt *bolt.Tx) error {
			return st.ForEach(func(name []byte, b *bolt.Bucket) error {
				if bytes.Equal(name, historyStorageMeta) {
					return nil
				}
				other := dt.Bucket(name)
				if other == nil || other.Sequence() != b.Sequence() {
					return errors.New("history compaction sequence mismatch")
				}
				expected := 0
				err := b.ForEach(func(k, v []byte) error {
					want := v
					got := other.Get(k)
					if bytes.Equal(name, historyRecords) {
						var e error
						want, e = decodeHistoryValue(v)
						if e != nil {
							return e
						}
						_, expired, e := expiredHistoryValue(want, cutoff)
						if e != nil {
							return e
						}
						if expired {
							if got != nil {
								return errors.New("expired history value retained")
							}
							return nil
						}
						got, e = decodeHistoryValue(got)
						if e != nil {
							return e
						}
					} else if bytes.Equal(name, historySeen) && dt.Bucket(historyRecords).Get(v) == nil {
						return nil
					} else if bytes.Equal(name, historyIndex) && dt.Bucket(historyRecords).Get(k[len(k)-8:]) == nil {
						return nil
					}
					expected++
					if !bytes.Equal(want, got) {
						return errors.New("history compaction value mismatch")
					}
					return nil
				})
				if err != nil {
					return err
				}
				if other.Stats().KeyN != expected {
					return errors.New("history compaction row count mismatch")
				}
				return nil
			})
		})
	})
	if err != nil {
		return err
	}
	if err = dst.Sync(); err != nil {
		return err
	}
	if err = dst.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// pruneExpiredHistory performs bounded expiry and legacy compression, separate from source ingestion.
// Offsets stay intact so expired source rows are not imported again.
func (h *historyStore) pruneExpiredHistory() error {
	if h.cfg.HistoryRetentionDays == 0 {
		return nil
	}
	cutoff := h.cfg.now().Add(-time.Duration(h.cfg.HistoryRetentionDays) * 24 * time.Hour)
	var next []byte
	// Deletion also allocates copy-on-write pages. Never bypass the importer's
	// archive and free-space reserves, even when removing expired records.
	err := h.update(func(tx *bolt.Tx) error {
		rows, seen, index := tx.Bucket(historyRecords), tx.Bucket(historySeen), tx.Bucket(historyIndex)
		cursor := rows.Cursor()
		k, v := cursor.First()
		if len(h.pruneAfter) > 0 {
			k, v = cursor.Seek(h.pruneAfter)
			if bytes.Equal(k, h.pruneAfter) {
				k, v = cursor.Next()
			}
		}
		scanned := 0
		for n := 0; k != nil && n < historyBatchRecords && scanned < historyBatchBytes; n++ {
			key := bytes.Clone(k)
			raw, e := decodeHistoryValue(v)
			if e != nil {
				return e
			}
			scanned += len(raw)
			env, expired, e := expiredHistoryValue(raw, cutoff)
			if e != nil {
				return e
			}
			next = key
			if expired {
				if e = index.Delete(append(append([]byte(env.Source), 0), key...)); e != nil {
					return e
				}
				identity, e := hex.DecodeString(env.ID)
				if e != nil || len(identity) != 16 {
					return errors.New("invalid history identity; retention rolled back")
				}
				sc := seen.Cursor()
				for sk, sv := sc.Seek(identity); sk != nil && bytes.HasPrefix(sk, identity); sk, sv = sc.Next() {
					if bytes.Equal(sv, key) {
						if e = sc.Delete(); e != nil {
							return e
						}
						break
					}
				}
				if e = cursor.Delete(); e != nil {
					return e
				}
			} else if !bytes.HasPrefix(v, []byte{0x1f, 0x8b}) {
				compressed, e := encodeHistoryValue(raw)
				if e != nil {
					return e
				}
				if len(compressed) < len(v) {
					if e = rows.Put(key, compressed); e != nil {
						return e
					}
				}
			}
			// Writes and deletes may change cursor positions. Resume strictly after
			// the processed identity rather than skipping its following neighbour.
			k, v = cursor.Seek(key)
			if bytes.Equal(k, key) {
				k, v = cursor.Next()
			}
		}
		if k == nil {
			next = nil
		}
		return nil
	})
	if err == nil {
		h.pruneAfter = next
	}
	return err
}
