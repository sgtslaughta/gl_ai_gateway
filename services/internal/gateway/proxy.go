package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"ai-access/internal/token"
)

// DefaultMaxBodyBytes is the request body limit when Config.MaxBodyBytes is unset.
const DefaultMaxBodyBytes = 10 << 20

// Config is the gateway configuration.
type Config struct {
	UpstreamURL     string
	MaxBodyBytes    int64
	BatchServiceURL string
}

type auditRecord struct {
	Time     string `json:"time"`
	User     string `json:"user"`
	DN       string `json:"dn"`
	Project  string `json:"project"`
	Ref      string `json:"ref"`
	SHA      string `json:"sha"`
	Pipeline string `json:"pipeline"`
	Job      string `json:"job"`
	Runner   int64  `json:"runner"`
	Method   string `json:"method"`
	Path     string `json:"path"`
	Status   int    `json:"status"`
	BytesIn  int64  `json:"bytes_in"`
	BytesOut int64  `json:"bytes_out"`
	Duration int64  `json:"duration_ms"`
	CallID   string `json:"call_id"`
}

type handler struct {
	cfg      Config
	upstream *url.URL
	v        *token.Verifier
	tr       http.RoundTripper
	auditMu  sync.Mutex
	audit    io.Writer
	opLog    io.Writer // operator log, fixed categories only; stderr by default
}

// NewHandler builds the gateway handler. The upstream must be a valid https
// URL and transport must be set (it carries the mTLS client certificate).
func NewHandler(cfg Config, v *token.Verifier, transport http.RoundTripper, audit io.Writer) (http.Handler, error) {
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if transport == nil {
		return nil, errors.New("gateway: transport is required")
	}
	u, err := url.Parse(cfg.UpstreamURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("gateway: upstream URL must be a valid https URL")
	}
	return &handler{cfg: cfg, upstream: u, v: v, tr: transport, audit: audit, opLog: os.Stderr}, nil
}

// countBody counts bytes read from a request body.
type countBody struct {
	io.ReadCloser
	n int64
}

func (c *countBody) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	c.n += int64(n)
	return n, err
}

// countWriter records status and bytes written, and keeps Flush working.
type countWriter struct {
	http.ResponseWriter
	status int
	n      int64
}

func (c *countWriter) WriteHeader(s int) {
	if c.status == 0 {
		c.status = s
	}
	c.ResponseWriter.WriteHeader(s)
}

func (c *countWriter) Write(p []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	n, err := c.ResponseWriter.Write(p)
	c.n += int64(n)
	return n, err
}

func (c *countWriter) Flush()                      { http.NewResponseController(c.ResponseWriter).Flush() }
func (c *countWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	cw := &countWriter{ResponseWriter: w}
	cb := &countBody{ReadCloser: r.Body}
	r.Body = cb
	rec := auditRecord{Method: r.Method, Path: r.URL.EscapedPath()}
	defer func() {
		if cw.status == 0 {
			cw.status = http.StatusOK
		}
		rec.Time = start.UTC().Format(time.RFC3339)
		rec.Status, rec.BytesIn, rec.BytesOut = cw.status, cb.n, cw.n
		rec.Duration = time.Since(start).Milliseconds()
		h.writeAudit(rec)
	}()

	raw, err := ExtractToken(r.Header)
	var c token.Claims
	if err == nil {
		if err = h.v.Verify(r.Context(), raw, &c); err != nil {
			if cat := token.Category(err); cat != "" {
				fmt.Fprintf(h.opLog, "gateway: outage category=%s\n", cat)
			}
		}
	}
	if err != nil || !validClaims(c) {
		http.Error(cw, "unauthorized", http.StatusUnauthorized)
		return
	}
	rec.User, rec.DN, rec.Project, rec.Ref, rec.SHA = c.UserLogin, c.DN, c.ProjectPath, c.Ref, c.SHA
	rec.Pipeline, rec.Job, rec.Runner = c.PipelineID, c.JobID, c.RunnerID

	if r.Header.Get("Upgrade") != "" {
		http.Error(cw, "upgrade not supported", http.StatusBadRequest)
		return
	}
	if !RouteAllowed(r.Method, r.URL.EscapedPath()) {
		http.Error(cw, fmt.Sprintf("route not allowed; batch and other endpoints are served by %s", h.cfg.BatchServiceURL), http.StatusForbidden)
		return
	}
	if r.ContentLength > h.cfg.MaxBodyBytes {
		http.Error(cw, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	r.Body = http.MaxBytesReader(cw, cb, h.cfg.MaxBodyBytes)

	rp := &httputil.ReverseProxy{
		Transport:     h.tr,
		FlushInterval: -1,
		ErrorLog:      log.New(io.Discard, "", 0),
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(h.upstream)
			RewriteHeaders(pr.Out.Header, c)
		},
		ModifyResponse: func(resp *http.Response) error {
			rec.CallID = resp.Header.Get("x-litellm-call-id")
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			var mb *http.MaxBytesError
			if errors.As(err, &mb) {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "bad gateway", http.StatusBadGateway)
		},
	}
	rp.ServeHTTP(cw, r)
}

// validClaims requires a DN and rejects control characters in header-bound claims.
func validClaims(c token.Claims) bool {
	if c.DN == "" {
		return false
	}
	for _, s := range []string{c.DN, c.ProjectPath, c.PipelineID, c.JobID} {
		if strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return false
		}
	}
	return true
}

// writeAudit writes one JSON line. The response may already be streaming, so
// a failure is reported generically to stderr and never fails the request.
func (h *handler) writeAudit(rec auditRecord) {
	b, err := json.Marshal(rec)
	if err == nil && h.audit != nil {
		h.auditMu.Lock()
		_, err = h.audit.Write(append(b, '\n'))
		h.auditMu.Unlock()
	} else if h.audit == nil {
		err = errors.New("no writer")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "gateway: audit write failed")
	}
}
