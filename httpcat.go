package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/textproto"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
)

var version = "0.0.1"

const (
	defaultMaxOutputBytes = int64(64 << 20)
	readHeaderTimeout     = 10 * time.Second
	shutdownTimeout       = 5 * time.Second
)

/////////////////////////////////////////////////////////////////////////////
// options
//
type config struct {
	addr string

	cert       string
	key        string
	verifyPeer bool
	caFile     string
	commonName string

	command string
	args    []string

	maxBodyBytes   int64
	maxOutputBytes int64

	readTimeout  time.Duration
	writeTimeout time.Duration
	// timeout time.Duration
}

func parseArgs(args []string) (*config, error) {
	if len(args) < 2 {
		return nil, errors.New("usage: httpcat listen:addr[,cert=file,key=file,verify[=bool],cafile=file] exec:\"command [args...]\"")
	}

	cfg := &config{
		maxOutputBytes: defaultMaxOutputBytes,
	}
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
			parts, err := splitCommand(strings.TrimSpace(strings.TrimPrefix(arg, "exec:")))
			if err != nil {
				return nil, fmt.Errorf("invalid exec specification: %w", err)
			}
			if len(parts) == 0 || parts[0] == "" {
				return nil, errors.New("exec command must not be empty")
			}
			cfg.command = parts[0]
			cfg.args = parts[1:]

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
			limit, err := parsePositiveBytesLimit(key, value, hasValue)
			if err != nil {
				return err
			}
			cfg.maxBodyBytes = limit

		case "maxoutput":
			limit, err := parsePositiveBytesLimit(key, value, hasValue)
			if err != nil {
				return err
			}
			cfg.maxOutputBytes = limit

		default:
			return fmt.Errorf("unknown listen option: %q", key)
		}
	}

	if (cfg.cert == "") != (cfg.key == "") {
		return errors.New("both cert and key are required for TLS")
	}
	if cfg.cert == "" && (cfg.verifyPeer || cfg.caFile != "" || cfg.commonName != "") {
		return errors.New("verify, cafile, and commonname require TLS cert and key")
	}
	if !cfg.verifyPeer && (cfg.caFile != "" || cfg.commonName != "") {
		return errors.New("cafile and commonname require verify")
	}
	return nil
}

func requireOptionValue(key, value string, hasValue bool) error {
	if !hasValue || value == "" {
		return fmt.Errorf("listen option %q requires a value", key)
	}
	return nil
}

func parsePositiveBytesLimit(key, value string, hasValue bool) (int64, error) {
	if err := requireOptionValue(key, value, hasValue); err != nil {
		return 0, err
	}
	limit, err := strconv.ParseInt(value, 10, 64)
	if err != nil || limit <= 0 {
		return 0, fmt.Errorf("listen option %q must be a positive byte count", key)
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

	clientCAs, err := loadClientCAs(cfg.caFile)
	if err != nil {
		return nil, err
	}
	tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	tlsConfig.ClientCAs = clientCAs

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

func loadClientCAs(caFile string) (*x509.CertPool, error) {
	if caFile == "" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("load system CA pool: %w", err)
		}
		if pool == nil {
			pool = x509.NewCertPool()
		}
		return pool, nil
	}

	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA file %q: %w", caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("CA file %q does not contain a valid certificate", caFile)
	}
	return pool, nil
}

/////////////////////////////////////////////////////////////////////////////
// handler
//
type execHandler struct {
	config *config
}

func (h *execHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("connected from %s: %s %s", r.RemoteAddr, r.Method, r.URL.RequestURI())

	var body io.ReadCloser
	if h.config.maxBodyBytes == 0 {
		body = r.Body
	} else {
		if r.ContentLength > h.config.maxBodyBytes {
			http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge),
				http.StatusRequestEntityTooLarge)
			return
		}
		body = http.MaxBytesReader(w, r.Body, h.config.maxBodyBytes)
	}
	defer body.Close()

	ctx := r.Context()
	resp, err := execCommand(ctx, h.config, buildCGIEnv(os.Environ(), r), body)
	if err != nil {
		log.Printf("exec command failed: %v", err)
		if errors.Is(err, context.Canceled) && r.Context().Err() != nil {
			return
		}
		status := execErrorStatus(ctx, err)
		http.Error(w, http.StatusText(status), status)
		return
	}

	if err := writeResponse(w, resp); err != nil {
		log.Printf("write response failed: %v", err)
	}
}

func execErrorStatus(ctx context.Context, err error) int {
	// var maxBytesError *http.MaxBytesError
	// if errors.As(err, &maxBytesError) {
	if err.Error() == "http: request body too large" {
		return http.StatusRequestEntityTooLarge
	}
	if errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return http.StatusGatewayTimeout
	}
	return http.StatusBadGateway
}

func buildCGIEnv(base []string, r *http.Request) []string {
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

	headerNames := make([]string, 0, len(r.Header))
	for name := range r.Header {
		headerNames = append(headerNames, name)
	}
	sort.Strings(headerNames)
	for _, name := range headerNames {
		envName := "HTTP_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
		if envName == "HTTP_CONTENT_TYPE" || envName == "HTTP_CONTENT_LENGTH" ||
			envName == "HTTP_PROXY" {
			continue
		}
		sep := ", "
		if strings.EqualFold(name, "Cookie") {
			sep = "; "
		}
		value := strings.Join(r.Header.Values(name), sep)
		if existing, ok := env[envName]; ok && existing != "" {
			env[envName] = existing + sep + value
		} else {
			env[envName] = value
		}
	}

	return mergeEnv(base, env)
}

func splitHostPort(addr string) (string, string) {
	host, port, err := net.SplitHostPort(addr)
	if err == nil {
		return host, port
	}
	return strings.Trim(addr, "[]"), ""
}

func mergeEnv(base []string, env map[string]string) []string {
	result := make([]string, 0, len(base)+len(env))
	for _, entry := range base {
		key, _, found := strings.Cut(entry, "=")
		if !found || isCGIEnvKey(key) {
			continue
		}
		result = append(result, entry)
	}

	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		result = append(result, key+"="+env[key])
	}
	return result
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

type limitedBuffer struct {
	buffer   bytes.Buffer
	limit    int64
	exceeded bool
	onLimit  func()
}

var errOutputTooLarge = errors.New("exec output exceeds configured limit")

func (b *limitedBuffer) Write(data []byte) (int, error) {
	remaining := b.limit - int64(b.buffer.Len())
	if int64(len(data)) <= remaining {
		return b.buffer.Write(data)
	}

	written := 0
	if remaining > 0 {
		written, _ = b.buffer.Write(data[:int(remaining)])
	}
	b.exceeded = true
	if b.onLimit != nil {
		b.onLimit()
	}
	return written, errOutputTooLarge
}

type execResponse struct {
	status  int
	headers http.Header
	body    []byte
}

func execCommand(ctx context.Context, cfg *config, env []string, body io.Reader) (*execResponse, error) {
	cmdCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	reqBody := &errorTrackingReader{reader: body, onError: cancel}
	cmdOut := &limitedBuffer{limit: cfg.maxOutputBytes, onLimit: cancel}
	cmd := exec.CommandContext(cmdCtx, cfg.command, cfg.args...)
	cmd.Env = env
	cmd.Stdin = reqBody
	cmd.Stdout = cmdOut
	cmd.Stderr = os.Stderr

	cmdErr := cmd.Run()
	if cmdOut.exceeded {
		return nil, errOutputTooLarge
	}
	if reqBody.err != nil {
		return nil, fmt.Errorf("read request body: %w", reqBody.err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if cmdErr != nil {
		return nil, fmt.Errorf("command failed: %w", cmdErr)
	}

	resp, err := parseCGIResponse(cmdOut.buffer.Bytes())
	if err != nil {
		return nil, fmt.Errorf("parse CGI response: %w", err)
	}
	return resp, nil
}

func parseCGIResponse(data []byte) (*execResponse, error) {
	headerPart, body, hasHeaders := splitExecOutput(data)
	if !hasHeaders {
		return &execResponse{status: http.StatusOK, headers: make(http.Header), body: data}, nil
	}

	status := http.StatusOK
	hasStatusLine := false
	if firstLine, remainder := takeFirstLine(headerPart); strings.HasPrefix(firstLine, "HTTP/") {
		parsedStatus, err := parseHTTPStatusLine(firstLine)
		if err != nil {
			return nil, err
		}
		status = parsedStatus
		headerPart = remainder
		hasStatusLine = true
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
		status, err = parseCGIStatus(statusValues[0])
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
	sepIdx := -1
	sepLen := 0
	for _, sep := range [][]byte{[]byte("\r\n\r\n"), []byte("\n\n")} {
		if i := bytes.Index(data, sep); i >= 0 && (sepIdx < 0 || i < sepIdx) {
			sepIdx = i
			sepLen = len(sep)
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

func parseHTTPStatusLine(line string) (int, error) {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return 0, fmt.Errorf("invalid HTTP status line %q", line)
	}
	if _, _, ok := http.ParseHTTPVersion(parts[0]); !ok {
		return 0, fmt.Errorf("invalid HTTP version in status line %q", line)
	}
	return parseStatusCode(parts[1])
}

func parseCGIStatus(value string) (int, error) {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return 0, errors.New("empty CGI Status header")
	}
	return parseStatusCode(fields[0])
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
	for _, name := range []string{
		"Connection",
		"Content-Length",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Proxy-Connection",
		"TE",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	} {
		headers.Del(name)
	}
}

func writeResponse(w http.ResponseWriter, r *execResponse) error {
	for n, vs := range r.headers {
		for _, v := range vs {
			w.Header().Add(n, v)
		}
	}
	if statusAllowsBody(r.status) {
		w.Header().Set("Content-Length", strconv.Itoa(len(r.body)))
	}

	w.WriteHeader(r.status)
	if len(r.body) == 0 {
		return nil
	}
	_, err := w.Write(r.body)
	return err
}

func runServer(cfg *config) error {
	tlsConfig, err := buildTLSConfig(cfg)
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr:              cfg.addr,
		Handler:           &execHandler{config: cfg},
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       cfg.readTimeout,
		WriteTimeout:      cfg.writeTimeout,
		IdleTimeout:       time.Minute,
		MaxHeaderBytes:    1 << 20,
		TLSConfig:         tlsConfig,
	}

	serveErrors := make(chan error, 1)
	go func() {
		if tlsConfig != nil {
			log.Printf("listening on %s (TLS)", cfg.addr)
			serveErrors <- server.ListenAndServeTLS(cfg.cert, cfg.key)
			return
		}
		log.Printf("listening on %s", cfg.addr)
		serveErrors <- server.ListenAndServe()
	}()

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case serveErr := <-serveErrors:
		if errors.Is(serveErr, http.ErrServerClosed) {
			return nil
		}
		return serveErr

	case <-sigCtx.Done():
		log.Print("shutting down")
	}

	srvCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := server.Shutdown(srvCtx); err != nil {
		_ = server.Close()
		<-serveErrors
		return fmt.Errorf("shut down HTTP server: %w", err)
	}

	serveErr := <-serveErrors
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return serveErr
	}
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
