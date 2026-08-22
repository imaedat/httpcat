package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
)

var version = "0.0.1"

const (
	readHeaderTimeout = 10 * time.Second
	shutdownTimeout   = 5 * time.Second
)

type contextKey int

const (
	_ contextKey = iota
	ctxKeyID
	ctxKeySignalCtx
	ctxKeyEnviron
)

/////////////////////////////////////////////////////////////////////////////
// options
//
type config struct {
	addr string

	cert          string
	key           string
	verifyPeer    bool
	caFile        string
	commonName    string
	websocketMode int

	cmdline []string
	stream  bool

	maxBodyBytes   int64
	maxOutputBytes int64
	maxConnection  int

	readTimeout    time.Duration
	writeTimeout   time.Duration
	commandTimeout time.Duration
}

func parseArgs(args []string) (*config, error) {
	if len(args) < 2 {
		return nil, errors.New("usage: httpcat listen:addr[,cert=file,key=file,verify[=bool],cafile=file] exec:\"command [args...]\"")
	}

	cfg := &config{}
	seenListen := false
	seenExec := false

	for _, arg := range args {
		switch {
		case strings.HasPrefix(arg, "listen:"):
			if seenListen {
				return nil, errors.New("listen may only be specified once")
			}
			seenListen = true
			if err := parseListen(cfg, strings.TrimPrefix(arg, "listen:")); err != nil {
				return nil, fmt.Errorf("invalid listen specification: %w", err)
			}

		case strings.HasPrefix(arg, "exec:"):
			if seenExec {
				return nil, errors.New("exec may only be specified once")
			}
			seenExec = true
			if err := parseExec(cfg, strings.TrimPrefix(arg, "exec:")); err != nil {
				return nil, fmt.Errorf("invalid exec specification: %w", err)
			}

		default:
			return nil, fmt.Errorf("unknown argument: %q", arg)
		}
	}

	if !seenListen {
		return nil, errors.New("listen is required")
	}
	if !seenExec {
		return nil, errors.New("exec is required")
	}

	return cfg, nil
}

func parseListen(cfg *config, spec string) error {
	parts, err := splitQuotedList(spec, ',')
	if err != nil {
		return err
	}
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		return errors.New("listen address must not be empty")
	}

	cfg.addr, err = normalizeListenAddress(strings.TrimSpace(parts[0]))
	if err != nil {
		return err
	}

	seenOptions := make(map[string]struct{}, len(parts)-1)
	for _, rawOption := range parts[1:] {
		option := strings.TrimSpace(rawOption)
		if option == "" {
			return errors.New("listen option must not be empty")
		}

		key, value, hasValue := strings.Cut(option, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if _, exists := seenOptions[key]; exists {
			return fmt.Errorf("listen option %q may only be specified once", key)
		}
		seenOptions[key] = struct{}{}

		switch key {
		case "cert":
			if err := requireOptionValue(key, value, hasValue); err != nil {
				return err
			}
			cfg.cert = value

		case "key":
			if err := requireOptionValue(key, value, hasValue); err != nil {
				return err
			}
			cfg.key = value

		case "cafile":
			if err := requireOptionValue(key, value, hasValue); err != nil {
				return err
			}
			cfg.caFile = value

		case "commonname":
			if err := requireOptionValue(key, value, hasValue); err != nil {
				return err
			}
			cfg.commonName = value

		case "verify":
			if !hasValue || value == "" {
				cfg.verifyPeer = true
				continue
			}
			verify, err := strconv.ParseBool(value)
			if err != nil {
				return fmt.Errorf("invalid verify value: %q: %w", value, err)
			}
			cfg.verifyPeer = verify

		case "readtimeout":
			if err := requireOptionValue(key, value, hasValue); err != nil {
				return err
			}
			timeout, err := time.ParseDuration(value)
			if err != nil {
				return fmt.Errorf("invalid readtimeout value %q", value)
			}
			cfg.readTimeout = timeout

		case "writetimeout":
			if err := requireOptionValue(key, value, hasValue); err != nil {
				return err
			}
			timeout, err := time.ParseDuration(value)
			if err != nil {
				return fmt.Errorf("invalid writetimeout value %q", value)
			}
			cfg.writeTimeout = timeout

		case "maxbody":
			limit, err := parsePositiveValueLimit(key, value, hasValue)
			if err != nil {
				return err
			}
			cfg.maxBodyBytes = limit

		case "maxoutput":
			limit, err := parsePositiveValueLimit(key, value, hasValue)
			if err != nil {
				return err
			}
			cfg.maxOutputBytes = limit

		case "maxconnection":
			maxconn, err := parsePositiveValueLimit(key, value, hasValue)
			if err != nil {
				return err
			}
			cfg.maxConnection = int(maxconn)

		case "websocket":
			if err := requireOptionValue(key, value, hasValue); err != nil {
				return err
			}
			switch strings.ToLower(value) {
			case "upgrade":
				cfg.websocketMode = 1
			case "aware":
				cfg.websocketMode = 2
			default:
				return fmt.Errorf("invalid websocket mode value: %q", value)
			}

		default:
			return fmt.Errorf("unknown listen option: %q", key)
		}
	}

	if (cfg.cert == "") != (cfg.key == "") {
		return errors.New("both cert and key are required for TLS")
	}
	return nil
}

func parseExec(cfg *config, spec string) error {
	parts, err := splitQuotedList(spec, ',')
	if err != nil {
		return err
	}
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		return errors.New("exec command must not be empty")
	}

	cmd, err := splitCommand(strings.TrimSpace(parts[0]))
	if err != nil {
		return fmt.Errorf("invalid exec specification: %w", err)
	}
	if len(cmd) == 0 || cmd[0] == "" {
		return errors.New("exec command must not be empty")
	}
	cfg.cmdline = cmd

	seenOptions := make(map[string]struct{}, len(parts)-1)
	for _, rawOption := range parts[1:] {
		option := strings.TrimSpace(rawOption)
		if option == "" {
			return errors.New("exec option must not be empty")
		}

		key, value, hasValue := strings.Cut(option, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if _, exists := seenOptions[key]; exists {
			return fmt.Errorf("exec option %q may only be specified once", key)
		}
		seenOptions[key] = struct{}{}

		switch key {
		case "stream":
			if !hasValue || value == "" {
				cfg.stream = true
				continue
			}
			stream, err := strconv.ParseBool(value)
			if err != nil {
				return fmt.Errorf("invalid stream value: %q: %w", value, err)
			}
			cfg.stream = stream

		case "timeout":
			if err := requireOptionValue(key, value, hasValue); err != nil {
				return err
			}
			timeout, err := time.ParseDuration(value)
			if err != nil {
				return fmt.Errorf("invalid timeout value %q", value)
			}
			cfg.commandTimeout = timeout

		default:
			return fmt.Errorf("unknown exec option: %q", key)
		}
	}

	return nil
}

func requireOptionValue(key, value string, hasValue bool) error {
	if !hasValue || value == "" {
		return fmt.Errorf("option %q requires a value", key)
	}
	return nil
}

func parsePositiveValueLimit(key, value string, hasValue bool) (int64, error) {
	if err := requireOptionValue(key, value, hasValue); err != nil {
		return 0, err
	}
	limit, err := strconv.ParseInt(value, 10, 64)
	if err != nil || limit <= 0 {
		return 0, fmt.Errorf("option %q must be a positive value", key)
	}
	return limit, nil
}

func normalizeListenAddress(addr string) (string, error) {
	if !strings.Contains(addr, ":") {
		port, err := strconv.Atoi(addr)
		if err != nil || port < 0 || port > 65535 {
			return "", fmt.Errorf("invalid port: %q", addr)
		}
		return ":" + addr, nil
	}

	_, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return "", fmt.Errorf("invalid listen address %q: expected host:port", addr)
	}
	return addr, nil
}

func splitQuotedList(value string, sep rune) ([]string, error) {
	var parts []string
	var part strings.Builder
	quoted := false
	runes := []rune(value)

	for i := 0; i < len(runes); i++ {
		curr := runes[i]
		if curr == '\\' && i+1 < len(runes) {
			next := runes[i+1]
			if next == '"' || (!quoted && next == sep) {
				part.WriteRune(next)
				i++
				continue
			}
		}
		if curr == '"' {
			quoted = !quoted
			continue
		}
		if curr == sep && !quoted {
			parts = append(parts, part.String())
			part.Reset()
			continue
		}
		part.WriteRune(curr)
	}

	if quoted {
		return nil, errors.New("unterminated double quote")
	}
	parts = append(parts, part.String())
	return parts, nil
}

func splitCommand(value string) ([]string, error) {
	var parts []string
	var part strings.Builder
	var quote rune
	tokenStarted := false
	runes := []rune(value)

	for i := 0; i < len(runes); i++ {
		curr := runes[i]
		if curr == '\\' && i+1 < len(runes) {
			next := runes[i+1]
			if (quote == 0 && (unicode.IsSpace(next) || next == '\'' || next == '"')) ||
				(quote != 0 && next == quote) {
				part.WriteRune(next)
				tokenStarted = true
				i++
				continue
			}
		}

		if curr == '\'' || curr == '"' {
			if quote == 0 {
				quote = curr
				tokenStarted = true
				continue
			}
			if quote == curr {
				quote = 0
				continue
			}
		}

		if unicode.IsSpace(curr) && quote == 0 {
			if tokenStarted {
				parts = append(parts, part.String())
				part.Reset()
				tokenStarted = false
			}
			continue
		}

		part.WriteRune(curr)
		tokenStarted = true
	}

	if quote != 0 {
		return nil, errors.New("unterminated quote")
	}
	if tokenStarted {
		parts = append(parts, part.String())
	}
	return parts, nil
}

func buildTLSConfig(cfg *config) (*tls.Config, error) {
	if cfg.cert == "" {
		return nil, nil
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if !cfg.verifyPeer {
		tlsConfig.ClientAuth = tls.NoClientCert
		return tlsConfig, nil
	}

	tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	if cfg.caFile == "" {
		var err error
		tlsConfig.ClientCAs, err = x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("load system CA pool: %w", err)
		}
		if tlsConfig.ClientCAs == nil {
			tlsConfig.ClientCAs = x509.NewCertPool()
		}
	} else {
		caPEM, err := os.ReadFile(cfg.caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file %q: %w", cfg.caFile, err)
		}
		tlsConfig.ClientCAs = x509.NewCertPool()
		if !tlsConfig.ClientCAs.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("CA file %q does not contain a valid certificate", cfg.caFile)
		}
	}

	if cfg.commonName != "" {
		tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("client certificate is required")
			}
			cert := state.PeerCertificates[0]
			err := cert.VerifyHostname(cfg.commonName)
			if err == nil {
				return nil
			}
			if strings.EqualFold(cert.Subject.CommonName, cfg.commonName) {
				return nil
			}
			return err
		}
	}

	return tlsConfig, nil
}

/////////////////////////////////////////////////////////////////////////////
// handler
//
type execHandler struct {
	config  *config
	rootCtx context.Context
	sem     chan struct{}
}

func newID() string {
	var b [16]byte
	now := time.Now()
	ms := uint64(now.UnixNano() / int64(time.Millisecond))
	nsWithinMs := now.Nanosecond() % int(time.Millisecond)
	randA := uint16((uint64(nsWithinMs) * 4096) / uint64(time.Millisecond))
	binary.BigEndian.PutUint32(b[0:4], uint32(ms>>16))
	binary.BigEndian.PutUint16(b[4:6], uint16(ms))
	binary.BigEndian.PutUint16(b[6:8], randA)
	b[6] = (b[6] & 0x0f) | 0x70
	if _, err := rand.Read(b[8:16]); err != nil {
		panic(err)
	}
	b[8] = (b[8] & 0x3f) | 0x80

	var out [36]byte
	hex.Encode(out[0:8], b[0:4])
	out[8] = '-'
	hex.Encode(out[9:13], b[4:6])
	out[13] = '-'
	hex.Encode(out[14:18], b[6:8])
	out[18] = '-'
	hex.Encode(out[19:23], b[8:10])
	out[23] = '-'
	hex.Encode(out[24:36], b[10:16])
	return string(out[:])
}

// custom response writer
type countingResponseWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *countingResponseWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *countingResponseWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

func (w *countingResponseWriter) Flush() {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *countingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, errors.New("http.Hijacker is not supported")
}

func (w *countingResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (h *execHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id := r.Header.Get("X-Request-ID")
	if id == "" {
		id = newID()
	}
	log.Printf("[%v] request started, remote=%v, method=%v, path=%v",
		id, r.RemoteAddr, r.Method, r.URL.RequestURI())
	ctx := context.WithValue(r.Context(), ctxKeyID, id)
	crw := &countingResponseWriter{ResponseWriter: w}
	startedAt := time.Now()

	err := h.serve(ctx, r, crw)
	result := "completed"
	if 400 <= crw.status && crw.status < 500 {
		result = "rejected"
	} else if 500 <= crw.status {
		result = "failed"
	}
	log.Printf("[%v] request %v, status=%v, duration=%v, bytes=%v, err=%v",
		id, result, crw.status, time.Since(startedAt), crw.bytes, err)
}

func (h *execHandler) serve(ctx context.Context, r *http.Request, w *countingResponseWriter) error {
	if h.sem != nil {
		select {
		case h.sem <- struct{}{}:
			defer func() { <-h.sem }()
		default:
			http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
			return fmt.Errorf("too many requests (limit=%v)", h.config.maxConnection)
		}
	}

	ctx = context.WithValue(ctx, ctxKeySignalCtx, h.rootCtx)
	ctx = context.WithValue(ctx, ctxKeyEnviron, buildCGIEnv(r))

	if h.config.websocketMode >= 1 {
		upgrade, status, key_or_err := isWebSocketRequest(r, w)
		if upgrade {
			if status != http.StatusOK {
				log.Printf("[%v] websocket rejected, status=%v, reason=%v",
					ctx.Value(ctxKeyID).(string), status, key_or_err)
				http.Error(w, http.StatusText(status), status)
				return errors.New(key_or_err)
			}
			return serveWebSocket(ctx, h.config, key_or_err, w)
		}
	}

	var body io.ReadCloser
	if h.config.maxBodyBytes == 0 {
		body = r.Body
	} else {
		if r.ContentLength > h.config.maxBodyBytes {
			http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge),
				http.StatusRequestEntityTooLarge)
			return fmt.Errorf("request entity too large (content_length=%v, limit=%v)",
				r.ContentLength, h.config.maxBodyBytes)
		}
		body = http.MaxBytesReader(w, r.Body, h.config.maxBodyBytes)
	}
	defer body.Close()

	return execCommand(ctx, h.config, body, w)
}

func buildCGIEnv(r *http.Request) []string {
	env := make(map[string]string, 32)
	env["GATEWAY_INTERFACE"] = "CGI/1.1"
	env["SERVER_SOFTWARE"] = "httpcat"
	env["REQUEST_METHOD"] = r.Method
	env["REQUEST_URI"] = r.URL.RequestURI()
	env["PATH_INFO"] = r.URL.Path
	env["QUERY_STRING"] = r.URL.RawQuery
	env["SERVER_PROTOCOL"] = r.Proto
	env["SCRIPT_NAME"] = ""

	serverName, serverPort := splitHostPort(r.Host)
	if localAddr, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		localHost, localPort := splitHostPort(localAddr.String())
		if serverName == "" {
			serverName = localHost
		}
		if serverPort == "" {
			serverPort = localPort
		}
	}
	env["SERVER_NAME"] = serverName
	env["SERVER_PORT"] = serverPort

	remoteAddr, remotePort := splitHostPort(r.RemoteAddr)
	env["REMOTE_ADDR"] = remoteAddr
	env["REMOTE_PORT"] = remotePort

	if r.ContentLength >= 0 {
		env["CONTENT_LENGTH"] = strconv.FormatInt(r.ContentLength, 10)
	}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		env["CONTENT_TYPE"] = ct
	}
	if r.TLS != nil {
		env["HTTPS"] = "on"
		if len(r.TLS.PeerCertificates) > 0 {
			env["HTTPS_X509_COMMONNAME"] = r.TLS.PeerCertificates[0].Subject.CommonName
			env["HTTPS_X509_SAN_DNS"] = strings.Join(r.TLS.PeerCertificates[0].DNSNames, ",")
		}
	} else {
		env["HTTPS"] = "off"
	}

	for name := range r.Header {
		key := "HTTP_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
		if key == "HTTP_CONTENT_TYPE" || key == "HTTP_CONTENT_LENGTH" || key == "HTTP_PROXY" {
			continue
		}
		sep := ", "
		if strings.EqualFold(name, "Cookie") {
			sep = "; "
		}
		value := strings.Join(r.Header.Values(name), sep)
		if existing, ok := env[key]; ok && existing != "" {
			env[key] = existing + sep + value
		} else {
			env[key] = value
		}
	}

	baseEnv := os.Environ()
	result := make([]string, 0, len(baseEnv)+len(env))
	for _, entry := range baseEnv {
		key, _, found := strings.Cut(entry, "=")
		if found && !isCGIEnvKey(key) {
			result = append(result, entry)
		}
	}
	for key, value := range env {
		result = append(result, key+"="+value)
	}
	return result
}

func splitHostPort(addr string) (string, string) {
	host, port, err := net.SplitHostPort(addr)
	if err == nil {
		return host, port
	}
	return strings.Trim(addr, "[]"), ""
}

func isCGIEnvKey(key string) bool {
	upperKey := strings.ToUpper(key)
	if strings.HasPrefix(upperKey, "HTTP_") {
		return true
	}
	switch upperKey {
	case "AUTH_TYPE", "CONTENT_LENGTH", "CONTENT_TYPE", "GATEWAY_INTERFACE", "HTTPS",
		"PATH_INFO", "PATH_TRANSLATED", "QUERY_STRING", "REMOTE_ADDR", "REMOTE_HOST",
		"REMOTE_IDENT", "REMOTE_PORT", "REMOTE_USER", "REQUEST_METHOD", "REQUEST_URI",
		"SCRIPT_NAME", "SERVER_NAME", "SERVER_PORT", "SERVER_PROTOCOL", "SERVER_SOFTWARE":
		return true
	default:
		return false
	}
}

// Request Reader
type errorTrackingReader struct {
	reader  io.Reader
	err     error
	onError func()
}

func (r *errorTrackingReader) Read(buffer []byte) (int, error) {
	count, err := r.reader.Read(buffer)
	if err != nil && !errors.Is(err, io.EOF) {
		r.err = err
		if r.onError != nil {
			r.onError()
		}
	}
	return count, err
}

// Command Output Writer
type outputWriter interface {
	io.Writer
	Err() error
	BytesOut() int64
}

// for normal output
type bufferWriter struct {
	buffer  bytes.Buffer
	limit   int64
	bytes   int64
	err     error
	onLimit func()
}

func (b *bufferWriter) Write(data []byte) (int, error) {
	if b.limit == 0 {
		n, err := b.buffer.Write(data)
		b.bytes += int64(n)
		return n, err
	}

	remaining := b.limit - int64(b.buffer.Len())
	if int64(len(data)) <= remaining {
		n, err := b.buffer.Write(data)
		b.bytes += int64(n)
		return n, err
	}

	written := 0
	if remaining > 0 {
		written, _ = b.buffer.Write(data[:int(remaining)])
	}
	b.err = fmt.Errorf("exec output too large (limit=%v)", b.limit)
	if b.onLimit != nil {
		b.onLimit()
	}
	b.bytes += int64(written)
	return written, b.err
}

func (b *bufferWriter) Err() error {
	return b.err
}

func (b *bufferWriter) BytesOut() int64 {
	return b.bytes
}

// for stream output
type streamWriter struct {
	writer  *countingResponseWriter
	bytes   int64
	err     error
	started bool
	onError func()
}

func (w *streamWriter) Write(data []byte) (int, error) {
	if len(data) > 0 {
		w.started = true
	}
	n, err := w.writer.Write(data)
	w.bytes += int64(n)
	if err != nil {
		if w.err == nil {
			w.err = err
			if w.onError != nil {
				w.onError()
			}
		}
		return n, err
	}
	w.writer.Flush()
	return n, nil
}

func (w *streamWriter) Err() error {
	return w.err
}

func (w *streamWriter) BytesOut() int64 {
	return w.bytes
}

func (w *streamWriter) Started() bool {
	return w.started
}

// Command Process
type commandProcess struct {
	sigCtx   context.Context
	ctx      context.Context
	cancel   context.CancelFunc
	cmd      *exec.Cmd
	doneCh   chan struct{}
	waitErr  error
	duration time.Duration
	exitCode int
}

func newCommandProcess(ctx context.Context, cfg *config, applyTimeout bool) *commandProcess {
	var cmdCtx context.Context
	var cancel context.CancelFunc
	if applyTimeout && cfg.commandTimeout > 0 {
		cmdCtx, cancel = context.WithTimeout(ctx, cfg.commandTimeout)
	} else {
		cmdCtx, cancel = context.WithCancel(ctx)
	}
	cmd := exec.CommandContext(cmdCtx, cfg.cmdline[0], cfg.cmdline[1:]...)
	cmd.Env = ctx.Value(ctxKeyEnviron).([]string)
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return &commandProcess{
		sigCtx: ctx.Value(ctxKeySignalCtx).(context.Context),
		ctx:    cmdCtx,
		cancel: cancel,
		cmd:    cmd,
	}
}

func (p *commandProcess) Start() error {
	if err := p.cmd.Start(); err != nil {
		return err
	}
	startedAt := time.Now()
	log.Printf("[%v] command started, pid=%v, cmd=%v",
		p.ctx.Value(ctxKeyID).(string), p.cmd.Process.Pid, p.cmd.Args)

	p.doneCh = make(chan struct{})
	processDone := make(chan struct{})
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		var err error
		select {
		case <-p.sigCtx.Done():
			err = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
		case <-p.ctx.Done():
			err = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
		case <-processDone:
			if p.ctx.Err() != nil {
				err = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
			}
		}
		if err != nil && !errors.Is(err, syscall.ESRCH) {
			log.Printf("[%v] kill process group failed: %v", p.ctx.Value(ctxKeyID).(string), err)
		}
	}()

	go func() {
		p.waitErr = p.cmd.Wait()
		p.duration = time.Since(startedAt)
		if p.waitErr == nil {
			p.exitCode = 0
		} else if e, ok := p.waitErr.(*exec.ExitError); ok {
			if w, ok := e.Sys().(syscall.WaitStatus); ok {
				if s := w.Signal(); s > 0 {
					p.exitCode = 127 + int(s)
				} else {
					p.exitCode = w.ExitStatus()
				}
			} else {
				p.exitCode = e.ExitCode()
			}
		} else {
			p.exitCode = 255
		}
		close(processDone)
		<-watchDone
		close(p.doneCh)
	}()

	return nil
}

func (p *commandProcess) Done() <-chan struct{} {
	return p.doneCh
}

func (p *commandProcess) Wait() error {
	<-p.doneCh
	return p.waitErr
}

func (p *commandProcess) Stop() {
	p.cancel()
}

func execCommand(ctx context.Context, cfg *config, body io.Reader, w *countingResponseWriter) error {
	proc := newCommandProcess(ctx, cfg, !cfg.stream)
	defer proc.Stop()

	errReader := &errorTrackingReader{reader: body, onError: proc.Stop}
	proc.cmd.Stdin = errReader

	var outWriter outputWriter
	if cfg.stream {
		outWriter = &streamWriter{writer: w, onError: proc.Stop}
		w.Header().Set("Content-Type", "application/octet-stream")
	} else {
		outWriter = &bufferWriter{limit: cfg.maxOutputBytes, onLimit: proc.Stop}
	}
	proc.cmd.Stdout = outWriter

	if err := proc.Start(); err != nil {
		log.Printf("[%v] exec failed, reason=%v", ctx.Value(ctxKeyID).(string), err)
		return err
	}
	cmdErr := proc.Wait()

	var execErr error
	if outWriter.Err() != nil {
		execErr = outWriter.Err()
	} else if errReader.err != nil {
		execErr = fmt.Errorf("read request body: %w", errReader.err)
	} else if proc.ctx.Err() != nil {
		execErr = proc.ctx.Err()
	} else if cmdErr != nil {
		execErr = fmt.Errorf("command failed: %w", cmdErr)
	} else {
		log.Printf("[%v] command completed, pid=%v, exit=%v, duration=%v, bytes_out=%v",
			ctx.Value(ctxKeyID).(string), proc.cmd.Process.Pid, proc.exitCode, proc.duration,
			outWriter.BytesOut())
	}

	if execErr != nil {
		if s, ok := outWriter.(*streamWriter); ok && s.Started() {
			log.Printf("[%v] exec failed after streaming response started: %v",
				ctx.Value(ctxKeyID).(string), execErr)
		} else {
			handleExecError(proc.ctx, w, execErr)
		}
		return execErr
	}

	if cfg.stream {
		return nil
	}
	return writeResponse(proc.ctx, w, outWriter.(*bufferWriter))
}

func handleExecError(ctx context.Context, w *countingResponseWriter, err error) {
	log.Printf("[%v] command failed, reason=%v", ctx.Value(ctxKeyID).(string), err)
	if !errors.Is(err, context.Canceled) || ctx.Err() == nil {
		status := http.StatusBadGateway
		// var maxBytesError *http.MaxBytesError
		// if errors.As(err, &maxBytesError) {
		if strings.Contains(err.Error(), "http: request body too large") {
			status = http.StatusRequestEntityTooLarge
		} else if errors.Is(err, context.DeadlineExceeded) ||
			errors.Is(ctx.Err(), context.DeadlineExceeded) {
			status = http.StatusGatewayTimeout
		}
		http.Error(w, http.StatusText(status), status)
	}
}

func writeResponse(ctx context.Context, w *countingResponseWriter, b *bufferWriter) error {
	resp, err := parseCGIResponse(b.buffer.Bytes())
	if err != nil {
		log.Printf("[%v] parse GCI response failed: %v", ctx.Value(ctxKeyID).(string), err)
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return err
	}

	for n, vs := range resp.headers {
		for _, v := range vs {
			w.Header().Add(n, v)
		}
	}
	if statusAllowsBody(resp.status) {
		w.Header().Set("Content-Length", strconv.Itoa(len(resp.body)))
	}

	w.WriteHeader(resp.status)
	if len(resp.body) > 0 {
		_, err := w.Write(resp.body)
		if err != nil {
			log.Printf("[%v] write response failed: %v", ctx.Value(ctxKeyID).(string), err)
		}
	}
	return nil
}

type execResponse struct {
	status  int
	headers http.Header
	body    []byte
}

func parseCGIResponse(data []byte) (*execResponse, error) {
	headerPart, body, hasHeaders := splitExecOutput(data)
	if !hasHeaders {
		return &execResponse{status: http.StatusOK, headers: make(http.Header), body: data}, nil
	}

	hasStatusLine, status := false, http.StatusOK
	if firstLine, remainder := takeFirstLine(headerPart); strings.HasPrefix(firstLine, "HTTP/") {
		parts := strings.SplitN(firstLine, " ", 3)
		if len(parts) < 2 {
			return nil, fmt.Errorf("invalid HTTP status line %q", firstLine)
		}
		if _, _, ok := http.ParseHTTPVersion(parts[0]); !ok {
			return nil, fmt.Errorf("invalid HTTP version in status line %q", firstLine)
		}
		parsedStatus, err := parseStatusCode(parts[1])
		if err != nil {
			return nil, err
		}
		headerPart = remainder
		hasStatusLine, status = true, parsedStatus
	}

	headerInput := make([]byte, 0, len(headerPart)+2)
	headerInput = append(headerInput, headerPart...)
	headerInput = append(headerInput, '\n', '\n')
	mimeHeaders, err :=
		textproto.NewReader(bufio.NewReader(bytes.NewReader(headerInput))).ReadMIMEHeader()
	if err != nil {
		return nil, fmt.Errorf("invalid HTTP headers: %w", err)
	}
	headers := http.Header(mimeHeaders)

	statusValues := headers.Values("Status")
	if hasStatusLine && len(statusValues) > 0 {
		return nil, errors.New("response contains both an HTTP status line and a Status header")
	}
	if len(statusValues) > 1 {
		return nil, errors.New("response contains multiple Status headers")
	}
	if len(statusValues) == 1 {
		fields := strings.Fields(statusValues[0])
		if len(fields) == 0 {
			return nil, errors.New("empty CGI Status header")
		}
		status, err = parseStatusCode(fields[0])
		if err != nil {
			return nil, err
		}
	}
	headers.Del("Status")

	if !hasStatusLine && len(statusValues) == 0 && headers.Get("Location") != "" {
		status = http.StatusFound
	}
	if !statusAllowsBody(status) && len(body) > 0 {
		return nil, fmt.Errorf("status %d must not include a response body", status)
	}
	sanitizeCGIHeaders(headers)

	return &execResponse{status: status, headers: headers, body: body}, nil
}

func splitExecOutput(data []byte) ([]byte, []byte, bool) {
	sepIdx, sepLen := -1, 0
	for _, sep := range [][]byte{[]byte("\r\n\r\n"), []byte("\n\n")} {
		if i := bytes.Index(data, sep); i >= 0 && (sepIdx < 0 || i < sepIdx) {
			sepIdx, sepLen = i, len(sep)
		}
	}
	if sepIdx < 0 {
		return nil, data, false
	}

	headerPart := data[:sepIdx]
	firstLine, _ := takeFirstLine(headerPart)
	if !strings.HasPrefix(firstLine, "HTTP/") && !strings.Contains(firstLine, ":") {
		return nil, data, false
	}
	return headerPart, data[sepIdx+sepLen:], true
}

func takeFirstLine(data []byte) (string, []byte) {
	lineEnd := bytes.IndexByte(data, '\n')
	if lineEnd < 0 {
		return strings.TrimSuffix(string(data), "\r"), nil
	}
	line := strings.TrimSuffix(string(data[:lineEnd]), "\r")
	return line, data[lineEnd+1:]
}

func parseStatusCode(value string) (int, error) {
	if len(value) != 3 {
		return 0, fmt.Errorf("invalid HTTP status code %q", value)
	}
	status, err := strconv.Atoi(value)
	if err != nil || status < 200 || status > 599 {
		return 0, fmt.Errorf("invalid HTTP status code %q", value)
	}
	return status, nil
}

func statusAllowsBody(status int) bool {
	return status != http.StatusNoContent && status != http.StatusResetContent &&
		status != http.StatusNotModified
}

func sanitizeCGIHeaders(headers http.Header) {
	for _, vs := range headers.Values("Connection") {
		for _, token := range strings.Split(vs, ",") {
			if name := textproto.TrimString(token); name != "" {
				headers.Del(name)
			}
		}
	}
	for _, name := range []string{"Connection", "Content-Length", "Keep-Alive",
		"Proxy-Authenticate", "Proxy-Authorization", "Proxy-Connection", "TE",
		"Trailer", "Transfer-Encoding", "Upgrade"} {
		headers.Del(name)
	}
}

/////////////////////////////////////////////////////////////////////////////
// WebSocket
//
func isWebSocketRequest(r *http.Request, w *countingResponseWriter) (bool, int, string) {
	if !headerContainsToken(r.Header.Values("Upgrade"), "websocket") {
		return false, 0, ""
	}

	if r.Method != http.MethodGet {
		return true, http.StatusMethodNotAllowed, "method not allowed"
	}

	if !headerContainsToken(r.Header.Values("Connection"), "Upgrade") {
		return true, http.StatusBadRequest, "missing Connection: Upgrade"
	}

	if !webSocketOriginAllowed(r) {
		return true, http.StatusForbidden, "mismatched Origin"
	}

	if r.Header.Get("Sec-WebSocket-Version") != "13" {
		w.Header().Set("Sec-WebSocket-Version", "13")
		return true, http.StatusUpgradeRequired, "bad websocket version"
	}

	keys := r.Header.Values("Sec-WebSocket-Key")
	if len(keys) != 1 {
		return true, http.StatusBadRequest, "multiple websocket keys"
	}
	key := strings.TrimSpace(keys[0])
	if key == "" {
		return true, http.StatusBadRequest, "empty websocket key"
	}
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(decoded) != 16 {
		return true, http.StatusBadRequest, "bad websocket key"
	}

	return true, http.StatusOK, key
}

func headerContainsToken(values []string, wanted string) bool {
	for _, value := range values {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), wanted) {
				return true
			}
		}
	}
	return false
}

func webSocketOriginAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}

	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	scheme, defaultPort := "http", "80"
	if r.TLS != nil {
		scheme, defaultPort = "https", "443"
	}
	if !strings.EqualFold(u.Scheme, scheme) {
		return false
	}
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		host, port = r.Host, defaultPort
	}
	originPort := u.Port()
	if originPort == "" {
		originPort = defaultPort
	}
	return strings.EqualFold(u.Hostname(), host) && originPort == port
}

// websocket writer / reader
type countingWriter interface {
	io.WriteCloser
	BytesOut() int64
}

type wsRawWriter struct {
	io.WriteCloser
	bytes int64
}

func (w *wsRawWriter) Write(b []byte) (int, error) {
	n, err := w.WriteCloser.Write(b)
	w.bytes += int64(n)
	return n, err
}

func (w *wsRawWriter) BytesOut() int64 {
	return w.bytes
}

// TODO? countingReader

type wsPayloadWriter struct {
	to    io.Writer
	bytes int64
	mu    sync.Mutex
}

func (w *wsPayloadWriter) Close() error {
	if c, ok := w.to.(io.Closer); ok {
		if err := c.Close(); err != nil {
			return err
		}
	}
	return nil
}

func (w *wsPayloadWriter) Write(buffer []byte) (int, error) {
	if err := w.WriteFrame(0x2, buffer); err != nil {
		return 0, err
	}
	return len(buffer), nil
}

func (w *wsPayloadWriter) WriteFrame(opcode byte, payload []byte) error {
	var hdr [10]byte
	hdr[0] = 0x80 | opcode
	n := 2
	length := len(payload)
	switch {
	case length <= 125:
		hdr[1] = byte(length)
	case length <= 0xffff:
		hdr[1] = 126
		binary.BigEndian.PutUint16(hdr[2:4], uint16(length))
		n = 4
	default:
		hdr[1] = 127
		binary.BigEndian.PutUint64(hdr[2:10], uint64(length))
		n = 10
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if _, err := w.writeFull(hdr[:n]); err != nil {
		return err
	}
	written, err := w.writeFull(payload)
	w.bytes += written
	return err
}

func (w *wsPayloadWriter) writeFull(b []byte) (int64, error) {
	var total int64 = 0
	for len(b) > 0 {
		n, err := w.to.Write(b)
		total += int64(n)
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
		b = b[n:]
	}
	return total, nil
}

func (w *wsPayloadWriter) BytesOut() int64 {
	return w.bytes
}

type wsPayloadReader struct {
	from       io.Reader
	to         *wsPayloadWriter
	remaining  int64
	mask       [4]byte
	maskIdx    uint8
	fragmented bool
	bytes      int64
}

func (r *wsPayloadReader) Read(buffer []byte) (int, error) {
	if r.remaining == 0 {
		for {
			isDataFrame, err := r.readHeader()
			if err != nil {
				return 0, err
			}
			if isDataFrame && r.remaining > 0 {
				break
			}
		}
	}

	if int64(len(buffer)) > r.remaining {
		buffer = buffer[:r.remaining]
	}

	n, err := r.from.Read(buffer)
	if n > 0 {
		r.remaining -= int64(n)
		r.unmaskPayload(buffer)
	}
	return n, err
}

func (r *wsPayloadReader) readHeader() (bool, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r.from, hdr[:]); err != nil {
		return false, err
	}

	if hdr[0]&0x70 != 0 {
		return false, errors.New("websocket: unsupported RSV bits")
	}
	if hdr[1]&0x80 == 0 {
		return false, errors.New("websocket: client frame not masked")
	}

	length := uint64(hdr[1] & 0x7f)
	switch length {
	case 126:
		var buf [2]byte
		if _, err := io.ReadFull(r.from, buf[:]); err != nil {
			return false, err
		}
		length = uint64(buf[0])<<8 | uint64(buf[1])
		if length < 126 {
			return false, errors.New("websocket: payload length not minimally encoded")
		}
	case 127:
		var buf [8]byte
		if _, err := io.ReadFull(r.from, buf[:]); err != nil {
			return false, err
		}
		length = binary.BigEndian.Uint64(buf[:])
		if length&(1<<63) != 0 || length <= 65535 {
			return false, errors.New("websocket: invalid payload length")
		}
	}
	if length > uint64(^uint(0)>>1) {
		return false, errors.New("websocket: payload length too large")
	}

	if _, err := io.ReadFull(r.from, r.mask[:]); err != nil {
		return false, err
	}
	r.maskIdx = 0

	return r.handleOpcode(hdr[0], length)
}

func (r *wsPayloadReader) handleOpcode(firstByte byte, length uint64) (bool, error) {
	fin := firstByte&0x80 != 0
	opcode := firstByte & 0x0f
	switch opcode {
	case 0x0:
		if !r.fragmented {
			return false, errors.New("websocket: unexpected continuation frame")
		}
	case 0x1, 0x2:
		if r.fragmented {
			return false, errors.New("websocket: new data frame during fragmented message")
		}
	case 0x8, 0x9, 0xa:
		if !fin || length == 1 || length > 125 {
			return false, errors.New("websocket: invalid control frame")
		}
		p := make([]byte, length)
		if _, err := io.ReadFull(r.from, p); err != nil {
			return false, err
		}
		r.unmaskPayload(p)

		switch opcode {
		case 0x8:
			_ = r.to.WriteFrame(0x8, p)
			return false, io.EOF
		case 0x9:
			if err := r.to.WriteFrame(0xa, p); err != nil {
				return false, err
			}
		}
		return false, nil
	default:
		return false, errors.New("websocket: unsupported opcode")
	}

	r.fragmented = !fin
	r.remaining = int64(length)
	return true, nil
}

func (r *wsPayloadReader) unmaskPayload(p []byte) {
	for i := 0; i < len(p); i, r.maskIdx = i+1, r.maskIdx+1 {
		r.maskIdx &= 3
		p[i] ^= r.mask[r.maskIdx]
	}
	r.bytes += int64(len(p))
}

// websocket serve entry
func serveWebSocket(ctx context.Context, cfg *config, key string, w *countingResponseWriter) error {
	conn, rw, err := w.Hijack()
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Time{})

	h := sha1.New()
	h.Write([]byte(key))
	h.Write([]byte("258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	accept := base64.StdEncoding.EncodeToString(h.Sum(nil))

	if _, err = fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"+
		"Connection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept); err == nil {
		err = rw.Flush()
	}
	if err != nil {
		log.Printf("[%v] Upgrade output failed: %v", ctx.Value(ctxKeyID).(string), err)
		return err
	}
	log.Printf("[%v] websocket upgraded", ctx.Value(ctxKeyID).(string))
	w.status = http.StatusSwitchingProtocols

	if cfg.websocketMode >= 2 {
		toPeer := &wsPayloadWriter{to: conn}
		return pipeCommand(ctx, cfg, &wsPayloadReader{from: rw.Reader, to: toPeer}, toPeer)
	} else {
		return pipeCommand(ctx, cfg, rw.Reader, &wsRawWriter{WriteCloser: conn})
	}
}

func pipeCommand(ctx context.Context, cfg *config, fromPeer io.Reader, toPeer countingWriter) error {
	proc := newCommandProcess(ctx, cfg, false)
	defer proc.Stop()

	toCmd, err := proc.cmd.StdinPipe()
	if err != nil {
		log.Printf("[%v] command stdin pipe failed: %v", ctx.Value(ctxKeyID).(string), err)
		return err
	}
	defer toCmd.Close()

	fromCmd, err := proc.cmd.StdoutPipe()
	if err != nil {
		log.Printf("[%v] command stdout pipe failed: %v", ctx.Value(ctxKeyID).(string), err)
		return err
	}
	defer fromCmd.Close()

	if err := proc.Start(); err != nil {
		log.Printf("[%v] exec failed, reason=%v", ctx.Value(ctxKeyID).(string), err)
		return err
	}

	var bytes_in, bytes_out int64
	copyCh := make(chan error, 2)
	go func() {
		var err error
		bytes_in, err = io.Copy(toCmd, fromPeer)
		copyCh <- err
	}()
	go func() {
		var err error
		bytes_out, err = io.Copy(toPeer, fromCmd)
		if err == nil && cfg.websocketMode >= 2 {
			toPeer.(*wsPayloadWriter).WriteFrame(0x8, []byte{0x03, 0xe8})
		}
		copyCh <- err
	}()

	copyErr := <-copyCh
	proc.Stop()

	_ = toPeer.Close()
	_ = toCmd.Close()
	_ = fromCmd.Close()

	<-copyCh
	cmdErr := proc.Wait()

	if copyErr != nil && !errors.Is(copyErr, io.EOF) && !errors.Is(copyErr, os.ErrClosed) {
		log.Printf("[%v] copy failed, reason=%v", ctx.Value(ctxKeyID).(string), copyErr)
		err = copyErr
	}
	if cmdErr != nil && !errors.Is(proc.ctx.Err(), context.Canceled) {
		log.Printf("[%v] command failed, reason=%v", ctx.Value(ctxKeyID).(string), cmdErr)
		if err == nil {
			err = cmdErr
		}
	} else {
		log.Printf("[%v] command completed, pid=%v, exit=%v, duration=%v, bytes_in=%v, bytes_out=%v",
			proc.ctx.Value(ctxKeyID).(string), proc.cmd.Process.Pid, proc.exitCode, proc.duration,
			bytes_in, bytes_out)
	}
	return err
}

/////////////////////////////////////////////////////////////////////////////
// main & server
//
func runServer(cfg *config) error {
	tlsConfig, err := buildTLSConfig(cfg)
	if err != nil {
		return err
	}

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	handler := &execHandler{config: cfg, rootCtx: sigCtx}
	if cfg.maxConnection > 0 {
		handler.sem = make(chan struct{}, cfg.maxConnection)
	}

	server := &http.Server{
		Addr:              cfg.addr,
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       cfg.readTimeout,
		WriteTimeout:      cfg.writeTimeout,
		IdleTimeout:       time.Minute,
		MaxHeaderBytes:    1 << 20,
		TLSConfig:         tlsConfig,
	}

	srvCh := make(chan error, 1)
	go func() {
		if tlsConfig == nil {
			log.Printf("listening on %s", cfg.addr)
			srvCh <- server.ListenAndServe()
		} else {
			log.Printf("listening on %s (TLS)", cfg.addr)
			srvCh <- server.ListenAndServeTLS(cfg.cert, cfg.key)
		}
	}()

	select {
	case srvErr := <-srvCh:
		if errors.Is(srvErr, http.ErrServerClosed) {
			return nil
		}
		return srvErr
	case <-sigCtx.Done():
		log.Printf("shutting down: %v", sigCtx.Err())
	}

	signaledAt := time.Now()
	srvCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := server.Shutdown(srvCtx); err != nil {
		_ = server.Close()
		<-srvCh
		return fmt.Errorf("shut down HTTP server: %w", err)
	}

	srvErr := <-srvCh
	if srvErr != nil && !errors.Is(srvErr, http.ErrServerClosed) {
		return srvErr
	}
	log.Printf("shutdown completed, duration=%v", time.Since(signaledAt))
	return nil
}

func main() {
	cfg, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := runServer(cfg); err != nil {
		log.Printf("server failed: %v", err)
		os.Exit(1)
	}
}
