package console

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

var collectionPagingKey = func() []byte {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("console pagination generation: " + err.Error())
	}
	return b
}()

var collectionPagingGeneration = hex.EncodeToString(collectionPagingKey)

const (
	defaultCollectionPageLimit = 20
	maxCollectionPageLimit     = 50
	maxCollectionCursorLength  = 4096
)

type collectionPage struct {
	Limit         int    `json:"limit"`
	Total         int    `json:"total"`
	NextCursor    string `json:"nextCursor,omitempty"`
	CurrentCursor string `json:"currentCursor,omitempty"`
}

type collectionCursor struct {
	Version  int    `json:"v"`
	Endpoint string `json:"e"`
	Scope    string `json:"s"`
	Limit    int    `json:"l"`
	Snapshot int    `json:"n"`
	Anchor   string `json:"a"`
	Offset   int    `json:"o"`
	Check    string `json:"c"`
}

type collectionPaging struct {
	Enabled bool
	Limit   int
	Cursor  collectionCursor
	Scope   string
}

func collectionPagingFromRequest(r *http.Request, endpoint string, p *Principal, filters map[string]string) (collectionPaging, error) {
	q := r.URL.Query()
	rawLimit, rawCursor := q.Get("limit"), q.Get("cursor")
	if rawLimit == "" && rawCursor == "" {
		return collectionPaging{}, nil
	}
	limit := defaultCollectionPageLimit
	if rawLimit != "" {
		var err error
		limit, err = strconv.Atoi(rawLimit)
		if err != nil || limit < 1 || limit > maxCollectionPageLimit {
			return collectionPaging{}, fmt.Errorf("limit must be an integer from 1 to %d", maxCollectionPageLimit)
		}
	}
	scope := collectionScope(endpoint, p, filters)
	pg := collectionPaging{Enabled: true, Limit: limit, Scope: scope}
	if rawCursor == "" {
		return pg, nil
	}
	if len(rawCursor) > maxCollectionCursorLength {
		return collectionPaging{}, fmt.Errorf("cursor is too large")
	}
	c, err := decodeCollectionCursor(rawCursor)
	if err != nil {
		return collectionPaging{}, err
	}
	if c.Version != 1 || c.Endpoint != endpoint || c.Scope != scope || c.Limit != limit || c.Snapshot < 0 || c.Offset < 0 {
		return collectionPaging{}, fmt.Errorf("cursor does not match this endpoint, query, authorization, or limit")
	}
	pg.Cursor = c
	return pg, nil
}

func collectionScope(endpoint string, p *Principal, filters map[string]string) string {
	keys := make([]string, 0, len(filters))
	for k := range filters {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(collectionPagingGeneration)
	b.WriteByte(0)
	b.WriteString(endpoint)
	b.WriteByte(0)
	if p != nil {
		b.WriteString(p.Issuer)
		b.WriteByte(0)
		b.WriteString(p.Subject)
		b.WriteByte(0)
		b.WriteString(strings.Join(p.Tenants, "\x1f"))
		b.WriteByte(0)
		b.WriteString(strings.Join(p.Targets, "\x1f"))
	}
	for _, k := range keys {
		b.WriteByte(0)
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(filters[k])
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:16])
}

func collectionAnchor(ids []string) string {
	h := sha256.New()
	for _, id := range ids {
		h.Write([]byte(strconv.Itoa(len(id))))
		h.Write([]byte{':'})
		h.Write([]byte(id))
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

func (p collectionPaging) establish(endpoint string, snapshot int, anchor string) collectionCursor {
	if p.Cursor.Version != 0 {
		return p.Cursor
	}
	return collectionCursor{Version: 1, Endpoint: endpoint, Scope: p.Scope, Limit: p.Limit, Snapshot: snapshot, Anchor: anchor}
}

func collectionPageFor(c collectionCursor, total int) (int, int, collectionPage, error) {
	if c.Offset > total {
		return 0, 0, collectionPage{}, fmt.Errorf("cursor position is outside this snapshot")
	}
	end := c.Offset + c.Limit
	if end > total {
		end = total
	}
	page := collectionPage{Limit: c.Limit, Total: total}
	current := c
	page.CurrentCursor = encodeCollectionCursor(current)
	if end < total {
		next := c
		next.Offset = end
		page.NextCursor = encodeCollectionCursor(next)
	}
	return c.Offset, end, page, nil
}

func encodeCollectionCursor(c collectionCursor) string {
	c.Check = ""
	raw, _ := json.Marshal(c)
	sig := hmac.New(sha256.New, collectionPagingKey)
	_, _ = sig.Write(raw)
	c.Check = hex.EncodeToString(sig.Sum(nil)[:16])
	raw, _ = json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func decodeCollectionCursor(raw string) (collectionCursor, error) {
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return collectionCursor{}, fmt.Errorf("invalid cursor encoding")
	}
	var c collectionCursor
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return collectionCursor{}, fmt.Errorf("invalid cursor payload")
	}
	check := c.Check
	c.Check = ""
	canonical, _ := json.Marshal(c)
	sig := hmac.New(sha256.New, collectionPagingKey)
	_, _ = sig.Write(canonical)
	want, err := hex.DecodeString(check)
	if err != nil || len(want) != 16 || !hmac.Equal(want, sig.Sum(nil)[:16]) {
		return collectionCursor{}, fmt.Errorf("invalid cursor checksum")
	}
	c.Check = check
	return c, nil
}

func writeCollectionPagingError(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
}

func containsFold(haystack, needle string) bool {
	return needle == "" || strings.Contains(strings.ToLower(haystack), needle)
}
