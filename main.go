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
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

/////////////////////////////////////////////////////////////////////////////
// options
//
type Config struct {
	Addr string

	Cert       string
	Key        string
	VerifyPeer bool
	CAFile     string
	CommonName string

	Command string
	Args    []string

	Timeout time.Duration
}

func parseArgs(args []string) (*Config, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("usage: httpcat listen:addr[,options] exec:\"command\"")
	}

	cfg := &Config{Timeout: 30 * time.Second}

	for _, arg := range args {
		switch {
		case strings.HasPrefix(arg, "listen:"):
			if err := parseListen(cfg, strings.TrimPrefix(arg, "listen:")); err != nil {
				return nil, err
			}

		case strings.HasPrefix(arg, "exec:"):
			cmd := strings.TrimPrefix(arg, "exec:")
			cmd = strings.TrimSpace(cmd)
			cmd = trimQuote(cmd)
			parts := splitCommand(cmd)
			if len(parts) == 0 {
				return nil, fmt.Errorf("empty command")
			}
			cfg.Command = parts[0]
			cfg.Args = parts[1:]

		default:
			return nil, fmt.Errorf("unknown argument: %s", arg)
		}
	}

	if cfg.Addr == "" {
		return nil, fmt.Errorf("listen is required")
	}

	if cfg.Command == "" {
		return nil, fmt.Errorf("exec is required")
	}

	return cfg, nil
}

func parseListen(cfg *Config, spec string) error {
	parts := splitCommaOptions(spec)
	if len(parts) == 0 {
		return fmt.Errorf("empty listen spec")
	}
	addr := parts[0]

	switch {
	case strings.HasPrefix(addr, ":"):
		cfg.Addr = addr

	case strings.HasPrefix(addr, "["):
		// IPv6: [::1]:8080
		cfg.Addr = addr

	case strings.Contains(addr, ":"):
		// host:port
		cfg.Addr = addr

	default:
		// port only
		if _, err := strconv.Atoi(addr); err != nil {
			return fmt.Errorf("invalid port: %s", addr)
		}
		cfg.Addr = ":" + addr
	}

	for _, opt := range parts[1:] {
		var key, value string
		pair := strings.SplitN(opt, "=", 2)
		key = pair[0]
		if len(pair) == 2 {
			value = pair[1]
		}

		switch key {
		case "cert":
			cfg.Cert = value

		case "key":
			cfg.Key = value

		case "cafile":
			cfg.CAFile = value

		case "commonname":
			cfg.CommonName = value

		case "verify":
			if value == "" {
				cfg.VerifyPeer = true
			} else {
				b, err := strconv.ParseBool(value)
				if err != nil {
					return fmt.Errorf("invalid verify value: %q", value)
				}
				cfg.VerifyPeer = b
			}

		default:
			return fmt.Errorf("unknown listen option: %s", key)
		}
	}

	if (cfg.Cert != "" && cfg.Key == "") || (cfg.Cert == "" && cfg.Key != "") {
		return fmt.Errorf("both cert and key are required for TLS")
	}

	return nil
}

func splitCommaOptions(s string) []string {
	var result []string
	var buf strings.Builder

	quoted := false
	for _, r := range s {
		switch r {
		case '"':
			quoted = !quoted
			buf.WriteRune(r)

		case ',':
			if quoted {
				buf.WriteRune(r)
			} else {
				result = append(result, buf.String())
				buf.Reset()
			}

		default:
			buf.WriteRune(r)
		}
	}

	if buf.Len() > 0 {
		result = append(result, buf.String())
	}

	return result
}

func trimQuote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func splitCommand(s string) []string {
	var result []string
	var buf strings.Builder

	quoted := false
	for _, r := range s {
		switch r {
		case '"':
			quoted = !quoted

		case ' ':
			if quoted {
				buf.WriteRune(r)
			} else if buf.Len() > 0 {
				result = append(result, buf.String())
				buf.Reset()
			}

		default:
			buf.WriteRune(r)
		}
	}

	if buf.Len() > 0 {
		result = append(result, buf.String())
	}

	return result
}

func buildTLSConfig(cfg *Config) (*tls.Config, error) {
	if cfg.Cert == "" || cfg.Key == "" {
		return nil, nil
	}

	tlsConfig := &tls.Config{}
	if cfg.VerifyPeer {
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		if cfg.CAFile == "" {
			pool, err := x509.SystemCertPool()
			if err != nil {
				return nil, err
			}
			tlsConfig.ClientCAs = pool
		} else {
			caPEM, err := os.ReadFile(cfg.CAFile)
			if err != nil {
				return nil, err
			}
			pool := x509.NewCertPool()
			if ok := pool.AppendCertsFromPEM(caPEM); !ok {
				return nil, fmt.Errorf("failed to parse CA file")
			}
			tlsConfig.ClientCAs = pool
		}
	} else {
		tlsConfig.ClientAuth = tls.NoClientCert
		if cfg.CAFile != "" {
			log.Printf("warning: cafile ignored because verify is disabled")
		}
		if cfg.CommonName != "" {
			log.Printf("warning: commonname ignored because verify is disabled")
		}
	}
	return tlsConfig, nil
}

/////////////////////////////////////////////////////////////////////////////
// handler
//
type CGIHandler struct {
	Config *Config
}

func (h *CGIHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("connected from %v: %v %v", r.RemoteAddr, r.Method, r.URL)

	if h.Config.VerifyPeer && h.Config.CommonName != "" {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		cert := r.TLS.PeerCertificates[0]
		if !strings.EqualFold(cert.Subject.CommonName, h.Config.CommonName) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
	}

	ctx := r.Context()
	if h.Config.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, h.Config.Timeout)
		defer cancel()
	}

	env := buildEnv(r)
	resp, err := runCGI(ctx, h.Config, env, r.Body)
	if err != nil {
		log.Printf("exec error: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeResponse(w, resp)
}

func buildEnv(r *http.Request) []string {
	env := make([]string, 0, 32)
	add := func(k, v string) {
		env = append(env, k+"="+v)
	}

	add("REQUEST_METHOD", r.Method)
	add("REQUEST_URI", r.URL.RequestURI())
	add("PATH_INFO", r.URL.Path)
	add("QUERY_STRING", r.URL.RawQuery)
	add("SERVER_PROTOCOL", r.Proto)

	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
		port = ""
	}
	add("SERVER_NAME", host)
	add("SERVER_PORT", port)

	if addr, port, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		add("REMOTE_ADDR", addr)
		add("REMOTE_PORT", port)
	}

	if r.ContentLength >= 0 {
		add("CONTENT_LENGTH", strconv.FormatInt(r.ContentLength, 10))
	}

	if ct := r.Header.Get("Content-Type"); ct != "" {
		add("CONTENT_TYPE", ct)
	}

	if r.TLS != nil {
		add("HTTPS", "on")
	} else {
		add("HTTPS", "off")
	}

	for k, v := range r.Header {
		key := "HTTP_" + strings.ToUpper(strings.ReplaceAll(k, "-", "_"))
		// CGI では Content 系は専用変数なので除外
		if key == "HTTP_CONTENT_TYPE" || key == "HTTP_CONTENT_LENGTH" {
			continue
		}

		add(key, strings.Join(v, ","))
	}

	return env
}

type CGIResponse struct {
	Status  int
	Headers http.Header
	Body    []byte
}

func runCGI(
	ctx context.Context,
	cfg *Config,
	env []string,
	body io.Reader,
) (*CGIResponse, error) {

	cmd := exec.CommandContext(ctx, cfg.Command, cfg.Args...)
	cmd.Env = append(os.Environ(), env...)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	defer stdin.Close()

	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	errOut, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	go func() {
		_, _ = io.Copy(os.Stderr, errOut)
	}()

	go func() {
		_, _ = io.Copy(stdin, body)
		_ = stdin.Close()
	}()

	data, err := io.ReadAll(out)
	if err != nil {
		return nil, err
	}

	err = cmd.Wait()
	if err != nil {
		return nil, fmt.Errorf("command failed: %w", err)
	}

	return parseCGIResponse(data)
}

func parseCGIResponse(data []byte) (*CGIResponse, error) {
	resp := &CGIResponse{
		Status:  200,
		Headers: make(http.Header),
	}

	// ヘッダ終了位置検索
	idx := bytes.Index(data, []byte("\r\n\r\n"))
	sepLen := 4
	if idx < 0 {
		idx = bytes.Index(data, []byte("\n\n"))
		sepLen = 2
	}

	if idx < 0 {
		// ヘッダ無しの場合
		resp.Body = data
		return resp, nil
	}

	headerPart := data[:idx]
	resp.Body = data[idx+sepLen:]
	scanner := bufio.NewScanner(bytes.NewReader(headerPart))

	first := true
	for scanner.Scan() {
		line := scanner.Text()
		if first {
			first = false

			// CGI 形式ではない HTTP status line
			if strings.HasPrefix(line, "HTTP/") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					code, err := strconv.Atoi(fields[1])
					if err == nil {
						resp.Status = code
					}
				}
				continue
			}
		}

		pos := strings.IndexByte(line, ':')
		if pos < 0 {
			continue
		}

		key := strings.TrimSpace(line[:pos])
		val := strings.TrimSpace(line[pos+1:])
		if strings.EqualFold(key, "Status") {
			fields := strings.Fields(val)
			if len(fields) > 0 {
				code, err := strconv.Atoi(fields[0])
				if err == nil {
					resp.Status = code
				}
			}
			continue
		}

		resp.Headers.Add(key, val)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return resp, nil
}

func writeResponse(w http.ResponseWriter, resp *CGIResponse) {
	for k, v := range resp.Headers {
		for _, x := range v {
			w.Header().Add(k, x)
		}
	}

	if w.Header().Get("Content-Length") == "" {
		w.Header().Set("Content-Length", strconv.Itoa(len(resp.Body)))
	}
	w.WriteHeader(resp.Status)
	_, _ = w.Write(resp.Body)
}

func main() {
	cfg, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	tlsConfig, err := buildTLSConfig(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           &CGIHandler{Config: cfg},
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         tlsConfig,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		log.Println("shutting down")
		server.Shutdown(ctx)
	}()

	if tlsConfig != nil {
		log.Printf("listening on %s (w/ tls)", cfg.Addr)
		err = server.ListenAndServeTLS(cfg.Cert, cfg.Key)
	} else {
		log.Printf("listening on %s", cfg.Addr)
		err = server.ListenAndServe()
	}

	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
