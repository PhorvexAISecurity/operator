package jetstreamprobe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const maxJSZBytes = 1 << 20

type JSZReceipt struct {
	ServerID       string `json:"serverID"`
	Streams        int    `json:"streams"`
	Consumers      int    `json:"consumers"`
	Messages       uint64 `json:"messages"`
	MetaLeader     string `json:"metaLeader,omitempty"`
	MetaSize       int    `json:"metaSize,omitempty"`
	MetaPending    int    `json:"metaPending,omitempty"`
	Stream         string `json:"stream"`
	StreamMessages uint64 `json:"streamMessages"`
	Consumer       string `json:"consumer"`
}

type jszEnvelope struct {
	ServerID  string `json:"server_id"`
	Streams   int    `json:"streams"`
	Consumers int    `json:"consumers"`
	Messages  uint64 `json:"messages"`
	Meta      *struct {
		Leader  string `json:"leader"`
		Size    int    `json:"cluster_size"`
		Pending int    `json:"pending"`
	} `json:"meta_cluster"`
	Accounts []struct {
		Streams []struct {
			Name  string `json:"name"`
			State struct {
				Messages uint64 `json:"messages"`
			} `json:"state"`
			Consumers []struct {
				Name   string `json:"name"`
				Stream string `json:"stream_name"`
			} `json:"consumer_detail"`
		} `json:"stream_detail"`
	} `json:"account_details"`
}

// ReadJSZ reads only the exact monitoring endpoint supplied by the fixture and
// requires its server, stream, and consumer identities. The caller is expected
// to invoke it once per pinned fixture member; no endpoint discovery occurs.
func ReadJSZ(ctx context.Context, monitorBaseURL, expectedServerID, stream, consumer string, timeout time.Duration) (JSZReceipt, error) {
	if expectedServerID == "" || stream == "" || consumer == "" || timeout <= 0 {
		return JSZReceipt{}, errors.New("expected server, stream, consumer, and positive timeout are required")
	}
	endpoint, err := exactJSZURL(monitorBaseURL)
	if err != nil {
		return JSZReceipt{}, err
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return JSZReceipt{}, err
	}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: nil,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("monitor redirect refused") },
	}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return JSZReceipt{}, fmt.Errorf("read exact jsz endpoint: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return JSZReceipt{}, fmt.Errorf("jsz status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxJSZBytes+1))
	if err != nil {
		return JSZReceipt{}, fmt.Errorf("read jsz body: %w", err)
	}
	if len(raw) > maxJSZBytes {
		return JSZReceipt{}, errors.New("jsz body exceeds bound")
	}
	var body jszEnvelope
	if err := json.Unmarshal(raw, &body); err != nil {
		return JSZReceipt{}, fmt.Errorf("decode jsz body: %w", err)
	}
	if body.ServerID != expectedServerID {
		return JSZReceipt{}, fmt.Errorf("jsz server ID %q differs from exact %q", body.ServerID, expectedServerID)
	}
	foundStreams, foundConsumers := 0, 0
	var streamMessages uint64
	for _, account := range body.Accounts {
		for _, observedStream := range account.Streams {
			if observedStream.Name != stream {
				continue
			}
			foundStreams++
			streamMessages = observedStream.State.Messages
			for _, observedConsumer := range observedStream.Consumers {
				if observedConsumer.Name == consumer && observedConsumer.Stream == stream {
					foundConsumers++
				}
			}
		}
	}
	if foundStreams != 1 || foundConsumers != 1 {
		return JSZReceipt{}, fmt.Errorf("jsz exact identity count stream=%d consumer=%d", foundStreams, foundConsumers)
	}
	receipt := JSZReceipt{ServerID: body.ServerID, Streams: body.Streams, Consumers: body.Consumers, Messages: body.Messages, Stream: stream, StreamMessages: streamMessages, Consumer: consumer}
	if body.Meta != nil {
		receipt.MetaLeader = body.Meta.Leader
		receipt.MetaSize = body.Meta.Size
		receipt.MetaPending = body.Meta.Pending
	}
	return receipt, nil
}

func exactJSZURL(base string) (string, error) {
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("invalid exact monitor base URL %q", base)
	}
	u.Path = "/jsz"
	q := u.Query()
	q.Set("accounts", "true")
	q.Set("config", "true")
	q.Set("consumers", "true")
	q.Set("streams", "true")
	u.RawQuery = q.Encode()
	return u.String(), nil
}
