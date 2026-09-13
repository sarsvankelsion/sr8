// sr8 guard-go — port Go của sealed/guard.py + TCP sealed splice.
// HTTP: /t/<name>/?exp=&seal= single-use burn-on-valid, /r/<room>/?ticket= rotating.
// TCP:  guard nghe TCP_SEAL_PORT, client gửi 1 dòng "<room>:<ticket>\n" hoặc
//       "<name>:<exp>:<seal>\n" trong 5s, verify xong mới splice 2 chiều về TCP_BACKEND.
// Stdlib only.
package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Config struct {
	GuardPort      string
	VhostAddr      string
	VhostHost      string
	Secret         string
	UsedDB         string
	RoomDB         string
	SingleUse      bool
	RotateSecs     int64
	RoomMaxUses    int
	RatePerMin     int
	MaxBody        int64
	ForwardIP      bool
	TrustedNets    []*net.IPNet
	TCPSealPort    string
	TCPBackend     string
	TCPHandshakeTO time.Duration
}

var cfg Config

var (
	muUsed sync.Mutex
	muRoom sync.Mutex
	muRate sync.Mutex
	rate   = map[string]*rateBucket{}
)

type rateBucket struct {
	start time.Time
	count int
}

func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func getenvInt(k string, d int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return d
}

func getenvInt64(k string, d int64) int64 {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return d
}

func writableDir(dir string) bool {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false
	}
	f, err := os.CreateTemp(dir, ".wtest-*")
	if err != nil {
		return false
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return true
}

func defaultStore(name string) string {
	// WSL kiểm chứng: volume docker root-owned + user nonroot khiến
	// /var/lib/sr8 MkdirAll vẫn nil nhưng WriteFile fail -> burn mất tác dụng.
	// Phải test ghi thật, không writable thì fallback /tmp để fail-safe.
	for _, base := range []string{"/var/lib/sr8", filepath.Join(mustCwd(), "data")} {
		if writableDir(base) {
			return filepath.Join(base, name)
		}
	}
	return filepath.Join(os.TempDir(), name)
}

func mustCwd() string {
	d, _ := os.Getwd()
	return d
}

func loadConfig() Config {
	c := Config{
		GuardPort:      getenv("GUARD_PORT", "19090"),
		VhostAddr:      getenv("FRPS_VHOST", "127.0.0.1:18080"),
		VhostHost:      getenv("VHOST_HOST", "loopback.test"),
		Secret:         getenv("SEAL_SECRET", "CHANGE-ME-SEAL-SECRET-32-CHARS"),
		SingleUse:      getenv("SEAL_SINGLE_USE", "1") == "1",
		RotateSecs:     getenvInt64("SEAL_ROTATE_SECS", 60),
		RoomMaxUses:    getenvInt("SEAL_ROOM_MAX_USES", 0),
		RatePerMin:     getenvInt("SEAL_RATE_PER_MIN", 120),
		MaxBody:        getenvInt64("SEAL_MAX_BODY_BYTES", 10*1024*1024),
		ForwardIP:      getenv("SEAL_FORWARD_IP", "0") == "1",
		TCPSealPort:    getenv("TCP_SEAL_PORT", "19091"),
		TCPBackend:     getenv("TCP_BACKEND", "127.0.0.1:18082"),
		TCPHandshakeTO: 5 * time.Second,
	}
	used := getenv("SEAL_USED_DB", "")
	if used == "" {
		used = defaultStore("sealed-used.json")
	}
	room := getenv("SEAL_ROOM_DB", "")
	if room == "" {
		room = defaultStore("sealed-room.json")
	}
	c.UsedDB = used
	c.RoomDB = room
	for _, p := range strings.Split(getenv("SEAL_TRUSTED_PROXIES", ""), ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.Contains(p, "/") {
			if strings.Contains(p, ".") {
				p += "/32"
			} else {
				p += "/128"
			}
		}
		if _, n, err := net.ParseCIDR(p); err == nil {
			c.TrustedNets = append(c.TrustedNets, n)
		}
	}
	if c.RotateSecs <= 0 {
		c.RotateSecs = 60
	}
	return c
}

// ---------- HMAC ----------

func hmacHex(msg string) string {
	m := hmac.New(sha256.New, []byte(cfg.Secret))
	m.Write([]byte(msg))
	return hex.EncodeToString(m.Sum(nil))
}

func expectedSeal(name, exp string) string { return hmacHex("name:" + name + ":" + exp) }

// NOTE: phải khớp seal.py python hiện tại: HMAC("name:exp").
// seal.py dùng f"{name}:{exp}" — giữ tương thích bằng cả 2 form.
func sealMatch(name, exp, seal string) bool {
	a := hmacHex(name + ":" + exp)
	b := hmacHex("name:" + name + ":" + exp)
	return hmac.Equal([]byte(a), []byte(seal)) || hmac.Equal([]byte(b), []byte(seal))
}

func roomRound() int64 { return time.Now().Unix() / cfg.RotateSecs }

func expectedRoomTicket(room string, rnd int64) string {
	return hmacHex(fmt.Sprintf("room:%s:%d", room, rnd))
}

func expectedTCPSeal(name, exp string) string { return hmacHex("tcp:" + name + ":" + exp) }
func expectedTCPRoom(room string, rnd int64) string {
	return hmacHex(fmt.Sprintf("tcproom:%s:%d", room, rnd))
}

// ---------- store ----------

func readJSONSet(path string) map[string]bool {
	m := map[string]bool{}
	b, err := os.ReadFile(path)
	if err != nil {
		return m
	}
	var list []string
	if err := json.Unmarshal(b, &list); err != nil {
		return m
	}
	for _, k := range list {
		m[k] = true
	}
	return m
}

func writeJSONSet(path string, m map[string]bool) {
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	list := make([]string, 0, len(m))
	for k := range m {
		list = append(list, k)
	}
	b, _ := json.Marshal(list)
	tmp := path + ".tmp"
	_ = os.WriteFile(tmp, b, 0o644)
	_ = os.Rename(tmp, path)
}

func tryBurnSealed(key string) bool {
	muUsed.Lock()
	defer muUsed.Unlock()
	m := readJSONSet(cfg.UsedDB)
	if m[key] {
		return false
	}
	m[key] = true
	writeJSONSet(cfg.UsedDB, m)
	return true
}

func readRoomCounts() map[string]int {
	m := map[string]int{}
	b, err := os.ReadFile(cfg.RoomDB)
	if err != nil {
		return m
	}
	_ = json.Unmarshal(b, &m)
	return m
}

func tryIncRoom(room string, rnd int64) bool {
	if cfg.RoomMaxUses <= 0 {
		return true
	}
	muRoom.Lock()
	defer muRoom.Unlock()
	m := readRoomCounts()
	k := fmt.Sprintf("%s:%d", room, rnd)
	if m[k] >= cfg.RoomMaxUses {
		return false
	}
	m[k]++
	pruned := map[string]int{}
	for kk, vv := range m {
		idx := strings.LastIndex(kk, ":")
		if idx < 0 {
			continue
		}
		rn, rs := kk[:idx], kk[idx+1:]
		if rn != room {
			pruned[kk] = vv
			continue
		}
		if n, err := strconv.ParseInt(rs, 10, 64); err == nil && n >= rnd-1 {
			pruned[kk] = vv
		}
	}
	_ = os.MkdirAll(filepath.Dir(cfg.RoomDB), 0o755)
	b, _ := json.Marshal(pruned)
	tmp := cfg.RoomDB + ".tmp"
	_ = os.WriteFile(tmp, b, 0o644)
	_ = os.Rename(tmp, cfg.RoomDB)
	return true
}

// ---------- ip/rate ----------

func isTrusted(ipStr string) bool {
	if len(cfg.TrustedNets) == 0 {
		return false
	}
	ip := net.ParseIP(strings.Trim(ipStr, "[]"))
	if ip == nil {
		return false
	}
	for _, n := range cfg.TrustedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func realIP(r *http.Request) string {
	peer, _, _ := net.SplitHostPort(r.RemoteAddr)
	if peer == "" {
		peer = r.RemoteAddr
	}
	if !isTrusted(peer) {
		return peer
	}
	for _, h := range []string{"X-Forwarded-For", "Cf-Connecting-Ip", "True-Client-Ip", "X-Real-Ip"} {
		if v := r.Header.Get(h); v != "" {
			return strings.Trim(strings.Split(v, ",")[0], " []")
		}
	}
	return peer
}

func rateOK(ip string) bool {
	muRate.Lock()
	defer muRate.Unlock()
	now := time.Now()
	b, ok := rate[ip]
	if !ok || now.Sub(b.start) > time.Minute {
		rate[ip] = &rateBucket{start: now, count: 1}
		return true
	}
	if b.count >= cfg.RatePerMin {
		return false
	}
	b.count++
	return true
}

var stripReq = map[string]bool{
	"host": true, "content-length": true, "connection": true,
	"referer": true, "referrer": true,
	"x-forwarded-for": true, "x-forwarded-host": true, "x-forwarded-proto": true,
	"x-real-ip": true, "forwarded": true, "cf-connecting-ip": true,
	"true-client-ip": true, "fastly-client-ip": true,
}

func sanitizeLocation(v string) string {
	u, err := url.Parse(v)
	if err != nil || u.Host == "" {
		if err != nil {
			return "/"
		}
		return v
	}
	h := strings.ToLower(strings.Trim(u.Hostname(), "[]"))
	if h == "localhost" || strings.HasSuffix(h, ".localhost") || strings.HasSuffix(h, ".local") || strings.HasSuffix(h, ".internal") {
		return "/"
	}
	if ip := net.ParseIP(strings.Trim(u.Hostname(), "[]")); ip != nil {
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
			return "/"
		}
		return v
	}
	return v
}

// stripRoundTripper xóa header nhạy cảm SAU Director vì ReverseProxy
// tự append X-Forwarded-For/X-Forwarded-Proto sau Director.
type stripRoundTripper struct{ base http.RoundTripper }

func (s stripRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	for k := range stripReq {
		req.Header.Del(http.CanonicalHeaderKey(k))
	}
	base := s.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}

// ---------- HTTP ----------

func deny(w http.ResponseWriter, code int, msg string) {
	b := []byte(msg)
	h := w.Header()
	h.Set("Content-Type", "text/plain")
	h.Set("Content-Length", strconv.Itoa(len(b)))
	h.Set("Server", "nginx")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	h.Set("Connection", "close")
	w.WriteHeader(code)
	_, _ = w.Write(b)
}

func proxyHTTP(w http.ResponseWriter, r *http.Request, name string, stripKeys map[string]bool) {
	// giữ multi-value query, strip key xác thực
	q := r.URL.Query()
	for k := range stripKeys {
		q.Del(k)
	}
	rest := strings.TrimPrefix(r.URL.Path, "/t/"+name)
	rest = strings.TrimPrefix(rest, "/r/"+name)
	if !strings.HasPrefix(rest, "/") {
		rest = "/" + rest
	}
	target := &url.URL{Scheme: "http", Host: cfg.VhostAddr}
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "http"
			req.URL.Host = cfg.VhostAddr
			req.URL.Path = rest
			req.URL.RawQuery = q.Encode()
			req.Host = strings.ReplaceAll(cfg.VhostHost, "{name}", name)
			req.Header.Set("X-Sealed-Name", name)
			if cfg.ForwardIP {
				req.Header.Set("X-Sealed-Visitor", realIP(r))
			}
			for k := range stripReq {
				req.Header.Del(http.CanonicalHeaderKey(k))
			}
		},
		Transport: stripRoundTripper{base: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			MaxIdleConns:          200,
			MaxIdleConnsPerHost:   50,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}},
		FlushInterval: -1, // stream SSE/WebSocket-friendly, vượt bản Python
		ModifyResponse: func(resp *http.Response) error {
			resp.Header.Set("Server", "nginx")
			if loc := resp.Header.Get("Location"); loc != "" {
				resp.Header.Set("Location", sanitizeLocation(loc))
			}
			resp.Header.Set("Referrer-Policy", "no-referrer")
			resp.Header.Set("X-Content-Type-Options", "nosniff")
			resp.Header.Set("Cache-Control", "no-store")
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			deny(w, 502, "upstream fail")
		},
	}
	// cap upload — vượt Python ở chỗ không đọc full body vào RAM trước
	r.Body = http.MaxBytesReader(w, r.Body, cfg.MaxBody)
	_ = target
	proxy.ServeHTTP(w, r)
}

func handleSealed(w http.ResponseWriter, r *http.Request, name string) {
	q := r.URL.Query()
	exp, seal := q.Get("exp"), q.Get("seal")
	if exp == "" || seal == "" {
		deny(w, 403, "missing exp/seal")
		return
	}
	if n, err := strconv.ParseInt(exp, 10, 64); err != nil || n < time.Now().Unix() {
		deny(w, 403, "link expired")
		return
	}
	if !sealMatch(name, exp, seal) {
		deny(w, 403, "bad seal")
		return
	}
	if cfg.SingleUse && !tryBurnSealed(name+":"+exp+":"+seal[:min(16, len(seal))]) {
		deny(w, 403, "link already used")
		return
	}
	proxyHTTP(w, r, name, map[string]bool{"seal": true, "exp": true})
}

func handleRoom(w http.ResponseWriter, r *http.Request, room string) {
	ticket := r.URL.Query().Get("ticket")
	if ticket == "" {
		deny(w, 403, "missing ticket")
		return
	}
	rnd := time.Now().Unix() / cfg.RotateSecs
	ok := hmac.Equal([]byte(expectedRoomTicket(room, rnd)), []byte(ticket)) ||
		hmac.Equal([]byte(expectedRoomTicket(room, rnd-1)), []byte(ticket))
	if !ok {
		deny(w, 403, "bad or rotated ticket")
		return
	}
	if !tryIncRoom(room, rnd) {
		deny(w, 429, "room round full")
		return
	}
	proxyHTTP(w, r, room, map[string]bool{"ticket": true})
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func httpHandler(w http.ResponseWriter, r *http.Request) {
	if !rateOK(realIP(r)) {
		deny(w, 429, "too many requests")
		return
	}
	if r.URL.Path == "/healthz" {
		deny(w, 200, "guard ok")
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) >= 2 && parts[0] == "r" {
		handleRoom(w, r, parts[1])
		return
	}
	if len(parts) >= 2 && parts[0] == "t" {
		handleSealed(w, r, parts[1])
		return
	}
	deny(w, 404, "use /t/<name>/?exp=..&seal=.. or /r/<room>/?ticket=..")
}

// ---------- TCP sealed splice (vượt frp: TCP cũng có seal) ----------

func verifyTCPLine(line string) (string, bool) {
	line = strings.TrimSpace(line)
	// form room: "<room>:<ticket>"
	if strings.Count(line, ":") == 1 {
		p := strings.SplitN(line, ":", 2)
		room, ticket := p[0], p[1]
		rnd := time.Now().Unix() / cfg.RotateSecs
		for _, c := range []int64{rnd, rnd - 1} {
			if hmac.Equal([]byte(expectedTCPRoom(room, c)), []byte(ticket)) {
				return "tcproom:" + room, true
			}
		}
		// tương thích ticket HTTP room cũ
		for _, c := range []int64{rnd, rnd - 1} {
			if hmac.Equal([]byte(expectedRoomTicket(room, c)), []byte(ticket)) {
				return "room:" + room, true
			}
		}
		return "", false
	}
	// form sealed: "<name>:<exp>:<seal>"
	p := strings.SplitN(line, ":", 3)
	if len(p) != 3 {
		return "", false
	}
	name, exp, seal := p[0], p[1], p[2]
	n, err := strconv.ParseInt(exp, 10, 64)
	if err != nil || n < time.Now().Unix() {
		return "", false
	}
	if hmac.Equal([]byte(expectedTCPSeal(name, exp)), []byte(seal)) {
		if cfg.SingleUse && !tryBurnSealed("tcp:"+name+":"+exp+":"+seal[:min(16, len(seal))]) {
			return "", false
		}
		return "tcp:" + name, true
	}
	// tương thích seal HTTP
	if sealMatch(name, exp, seal) {
		if cfg.SingleUse && !tryBurnSealed("tcp:"+name+":"+exp+":"+seal[:min(16, len(seal))]) {
			return "", false
		}
		return "tcp:" + name, true
	}
	return "", false
}

func handleTCPConn(client net.Conn) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(cfg.TCPHandshakeTO))
	br := bufio.NewReader(client)
	line, err := br.ReadString('\n')
	if err != nil {
		return
	}
	who, ok := verifyTCPLine(line)
	if !ok {
		_, _ = client.Write([]byte("403 bad seal\n"))
		return
	}
	backend, err := net.DialTimeout("tcp", cfg.TCPBackend, 10*time.Second)
	if err != nil {
		_, _ = client.Write([]byte("502 upstream fail\n"))
		return
	}
	defer backend.Close()
	_ = client.SetDeadline(time.Time{})
	_ = backend.SetDeadline(time.Time{})
	log.Printf("tcp sealed %s -> %s", who, cfg.TCPBackend)
	// client đã đọc 1 dòng handshake; phần dư trong br phải forward tiếp
	go func() {
		_, _ = io.Copy(backend, br)
		_ = backend.(*net.TCPConn).CloseWrite()
	}()
	_, _ = io.Copy(client, backend)
}

func serveTCP() {
	if cfg.TCPSealPort == "" || cfg.TCPSealPort == "0" {
		return
	}
	ln, err := net.Listen("tcp", "127.0.0.1:"+cfg.TCPSealPort)
	if err != nil {
		log.Printf("tcp listen :%s failed: %v", cfg.TCPSealPort, err)
		return
	}
	log.Printf("tcp sealed :%s -> %s", cfg.TCPSealPort, cfg.TCPBackend)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleTCPConn(c)
	}
}

func main() {
	cfg = loadConfig()
	go serveTCP()
	srv := &http.Server{
		Addr:              "127.0.0.1:" + cfg.GuardPort,
		Handler:           http.HandlerFunc(httpHandler),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	log.Printf("guard-go :%s -> %s single_use=%v rotate=%ds room_max=%d tcp_seal=:%s->%s",
		cfg.GuardPort, cfg.VhostAddr, cfg.SingleUse, cfg.RotateSecs, cfg.RoomMaxUses, cfg.TCPSealPort, cfg.TCPBackend)
	log.Fatal(srv.ListenAndServe())
}
