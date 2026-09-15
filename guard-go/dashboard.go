// sr8 admin dashboard — tích hợp thẳng vào guard-go, stdlib only.
// Phục vụ trên cùng GUARD_PORT dưới /admin/ (guard chỉ bind 127.0.0.1,
// muốn public thì đi qua Caddy + ADMIN_TOKEN).
//
// Endpoints:
//   GET  /admin/                UI quản trị (HTML inline, không dep ngoài)
//   GET  /admin/api/status      trạng thái guard + frps ports + counters
//   POST /admin/api/mint        {name, ttl} -> sealed link /t/
//   POST /admin/api/room        {room} -> room ticket link /r/
//   POST /admin/api/toggle      {mode: open|sealed} -> đổi SEAL_MODE runtime (+persist .env)
//   GET  /admin/api/logs        200 request gần nhất (không gồm poll status/logs/healthz)
//   GET  /admin/api/frps        port-check frps + raw /api/serverinfo nếu có FRPS_DASH_USER/PASS
package main

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------- stats + recent logs ----------

type counters struct {
	total  atomic.Int64
	sealOK atomic.Int64
	sealNO atomic.Int64
	roomOK atomic.Int64
	roomNO atomic.Int64
	openOK atomic.Int64
	tcpOK  atomic.Int64
	tcpNO  atomic.Int64
}

var stats counters

type logEntry struct {
	TS     string `json:"ts"`
	IP     string `json:"ip"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Code   int    `json:"code"`
	Kind   string `json:"kind"`
}

var (
	muLogs   sync.Mutex
	recent   = make([]logEntry, 0, 200)
	skipLog  = map[string]bool{"/healthz": true, "/admin/api/logs": true, "/admin/api/status": true}
)

func pushLog(e logEntry) {
	muLogs.Lock()
	defer muLogs.Unlock()
	recent = append(recent, e)
	if len(recent) > 200 {
		recent = recent[len(recent)-200:]
	}
}

func kindOf(path string, code int) string {
	switch {
	case strings.HasPrefix(path, "/t/"):
		if code == 200 {
			return "seal-ok"
		}
		return "seal-deny"
	case strings.HasPrefix(path, "/r/"):
		if code == 200 {
			return "room-ok"
		}
		return "room-deny"
	case strings.HasPrefix(path, "/admin"):
		return "admin"
	default:
		if code == 200 {
			return "open-ok"
		}
		return "other"
	}
}

type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (r *statusRecorder) WriteHeader(c int) {
	if r.code == 0 {
		r.code = c
	}
	r.ResponseWriter.WriteHeader(c)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.code == 0 {
		r.WriteHeader(http.StatusOK)
	}
	return r.ResponseWriter.Write(b)
}

func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// withStats bọc handler chính: ghi counter + recent log, không buffer body.
func withStats(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		code := rec.code
		if code == 0 {
			code = 200
		}
		stats.total.Add(1)
		k := kindOf(r.URL.Path, code)
		switch k {
		case "seal-ok":
			stats.sealOK.Add(1)
		case "seal-deny":
			stats.sealNO.Add(1)
		case "room-ok":
			stats.roomOK.Add(1)
		case "room-deny":
			stats.roomNO.Add(1)
		case "open-ok":
			stats.openOK.Add(1)
		}
		if !skipLog[r.URL.Path] {
			pushLog(logEntry{
				TS:     time.Now().Format("15:04:05"),
				IP:     realIP(r),
				Method: r.Method,
				Path:   r.URL.Path,
				Code:   code,
				Kind:   k,
			})
		}
	})
}

func tcpStats(ok bool) {
	if ok {
		stats.tcpOK.Add(1)
	} else {
		stats.tcpNO.Add(1)
	}
}

// ---------- admin auth ----------

func adminAuth(r *http.Request) bool {
	if cfg.AdminToken == "" {
		return true // guard bind localhost: chỉ tin cậy khi chưa public
	}
	tok := r.URL.Query().Get("token")
	if tok == "" {
		tok = r.Header.Get("X-Admin-Token")
	}
	if tok == "" {
		if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
			tok = strings.TrimPrefix(h, "Bearer ")
		}
	}
	if tok == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(tok), []byte(cfg.AdminToken)) == 1
}

func adminDeny(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"unauthorized: set ?token= or X-Admin-Token"}`))
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	b, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(b)
}

// ---------- helpers ----------

func publicBase(r *http.Request) string {
	if b := strings.TrimRight(cfg.PublicBase, "/"); b != "" {
		return b
	}
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func checkPort(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func setSealMode(mode string) string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != "open" && mode != "sealed" {
		return ""
	}
	muCfg.Lock()
	cfg.SealMode = mode
	muCfg.Unlock()
	persistSealMode(mode)
	return mode
}

func persistSealMode(mode string) {
	path := getenv("ADMIN_ENV_FILE", "")
	if path == "" {
		return
	}
	b, err := readFileLimit(path, 64*1024)
	lines := []string{}
	if err == nil {
		for _, ln := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(strings.TrimSpace(ln), "SEAL_MODE=") {
				continue
			}
			lines = append(lines, ln)
		}
	}
	lines = append(lines, "SEAL_MODE="+mode)
	_ = writeFileAtomic(path, []byte(strings.Join(lines, "\n")))
}

func readFileLimit(path string, n int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, n))
}

func writeFileAtomic(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ---------- frps proxies ----------

func frpsGET(path string) (any, int, error) {
	req, err := http.NewRequest("GET", "http://"+cfg.FrpsDashAddr+path, nil)
	if err != nil {
		return nil, 0, err
	}
	if cfg.FrpsDashUser != "" {
		req.SetBasicAuth(cfg.FrpsDashUser, cfg.FrpsDashPass)
	}
	cli := &http.Client{Timeout: 5 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	var raw any
	if err := json.Unmarshal(b, &raw); err != nil {
		return string(b), resp.StatusCode, nil
	}
	return raw, resp.StatusCode, nil
}

func frpsProxies() map[string]any {
	res := map[string]any{"dash": cfg.FrpsDashAddr, "reachable": checkPort(cfg.FrpsDashAddr)}
	if !checkPort(cfg.FrpsDashAddr) {
		res["note"] = "frps dashboard unreachable (bind 127.0.0.1:7500?)"
		return res
	}
	for _, ep := range []string{"/api/serverinfo", "/api/proxy/tcp", "/api/proxy/http", "/api/proxy/https", "/api/proxy/stcp", "/api/proxy/udp"} {
		key := strings.TrimPrefix(ep, "/api/")
		if v, code, err := frpsGET(ep); err == nil {
			res[key] = map[string]any{"http_code": code, "data": v}
		} else {
			res[key] = map[string]any{"error": err.Error()}
		}
	}
	return res
}

// ---------- admin routes ----------

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	if !adminAuth(r) {
		adminDeny(w)
		return
	}
	p := r.URL.Path
	switch {
	case p == "/admin" || p == "/admin/":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(dashboardHTML))
	case p == "/admin/api/status":
		used := readJSONSet(cfg.UsedDB)
		rooms := readRoomCounts()
		writeJSON(w, 200, map[string]any{
			"mode":       currentMode(),
			"version":    cfg.Version,
			"uptime_s":   int64(time.Since(cfg.StartTime).Seconds()),
			"guard_port": cfg.GuardPort,
			"vhost":      cfg.VhostAddr,
			"tcp_seal":   cfg.TCPSealPort + "->" + cfg.TCPBackend,
			"frps": map[string]any{
				"bind":      checkPort(cfg.FrpsBindAddr),
				"bind_addr": cfg.FrpsBindAddr,
				"bind_7000": checkPort("127.0.0.1:7000"),
				"vhost":     checkPort(cfg.VhostAddr),
				"dash":      checkPort(cfg.FrpsDashAddr),
				"dash_addr": cfg.FrpsDashAddr,
				// giữ key cũ để UI/test cũ không gãy
				"dash_7500": checkPort(cfg.FrpsDashAddr),
			},
			"counters": map[string]any{
				"total": stats.total.Load(), "seal_ok": stats.sealOK.Load(),
				"seal_deny": stats.sealNO.Load(), "room_ok": stats.roomOK.Load(),
				"room_deny": stats.roomNO.Load(), "open_ok": stats.openOK.Load(),
				"tcp_ok": stats.tcpOK.Load(), "tcp_deny": stats.tcpNO.Load(),
			},
			"store": map[string]any{"used_links": len(used), "room_rounds": len(rooms)},
		})
	case p == "/admin/api/mint" && r.Method == "POST":
		var in struct {
			Name string `json:"name"`
			TTL  int64  `json:"ttl"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&in); err != nil {
			writeJSON(w, 400, map[string]any{"error": "bad json"})
			return
		}
		in.Name = strings.Trim(in.Name, "/ ")
		if in.Name == "" || strings.Contains(in.Name, "/") || strings.Contains(in.Name, "?") {
			writeJSON(w, 400, map[string]any{"error": "bad name"})
			return
		}
		if in.TTL <= 0 || in.TTL > 30*24*3600 {
			in.TTL = 300
		}
		exp := time.Now().Unix() + in.TTL
		expS := strconv.FormatInt(exp, 10)
		seal := hmacHex(in.Name + ":" + expS) // khớp seal.py
		writeJSON(w, 200, map[string]any{
			"name": in.Name, "exp": exp, "ttl": in.TTL, "seal": seal,
			"link": fmt.Sprintf("%s/t/%s/?exp=%s&seal=%s", publicBase(r), in.Name, expS, seal),
		})
	case p == "/admin/api/room" && r.Method == "POST":
		var in struct {
			Room string `json:"room"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&in); err != nil {
			writeJSON(w, 400, map[string]any{"error": "bad json"})
			return
		}
		in.Room = strings.Trim(in.Room, "/ ")
		if in.Room == "" || strings.Contains(in.Room, "/") || strings.Contains(in.Room, "?") {
			writeJSON(w, 400, map[string]any{"error": "bad room"})
			return
		}
		rnd := roomRound()
		ticket := expectedRoomTicket(in.Room, rnd)
		writeJSON(w, 200, map[string]any{
			"room": in.Room, "round": rnd, "rotate_secs": cfg.RotateSecs, "ticket": ticket,
			"link": fmt.Sprintf("%s/r/%s/?ticket=%s", publicBase(r), in.Room, ticket),
		})
	case p == "/admin/api/toggle" && r.Method == "POST":
		var in struct {
			Mode string `json:"mode"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&in); err != nil {
			writeJSON(w, 400, map[string]any{"error": "bad json"})
			return
		}
		if m := setSealMode(in.Mode); m == "" {
			writeJSON(w, 400, map[string]any{"error": "mode must be open|sealed"})
			return
		} else {
			writeJSON(w, 200, map[string]any{"mode": m})
		}
	case p == "/admin/api/logs":
		n := 50
		if q := r.URL.Query().Get("limit"); q != "" {
			if v, err := strconv.Atoi(q); err == nil && v > 0 && v <= 200 {
				n = v
			}
		}
		muLogs.Lock()
		out := make([]logEntry, 0, n)
		if len(recent) > 0 {
			from := len(recent) - n
			if from < 0 {
				from = 0
			}
			for i := len(recent) - 1; i >= from; i-- {
				out = append(out, recent[i])
			}
		}
		muLogs.Unlock()
		writeJSON(w, 200, map[string]any{"logs": out})
	case p == "/admin/api/proxies":
		writeJSON(w, 200, frpsProxies())
	case p == "/admin/api/frps":
		res := map[string]any{"dash": cfg.FrpsDashAddr, "reachable": checkPort(cfg.FrpsDashAddr)}
		if cfg.FrpsDashUser != "" {
			req, _ := http.NewRequest("GET", "http://"+cfg.FrpsDashAddr+"/api/serverinfo", nil)
			req.SetBasicAuth(cfg.FrpsDashUser, cfg.FrpsDashPass)
			cli := &http.Client{Timeout: 5 * time.Second}
			if resp, err := cli.Do(req); err == nil {
				b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
				_ = resp.Body.Close()
				var raw any
				if json.Unmarshal(b, &raw) == nil {
					res["serverinfo"] = raw
				} else {
					res["serverinfo_raw"] = string(b)
				}
				res["http_code"] = resp.StatusCode
			} else {
				res["error"] = err.Error()
			}
		} else {
			res["note"] = "set FRPS_DASH_USER/PASS to read frps serverinfo"
		}
		writeJSON(w, 200, res)
	default:
		writeJSON(w, 404, map[string]any{"error": "unknown admin endpoint"})
	}
}

const dashboardHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>sr8 dashboard</title>
<style>
*{box-sizing:border-box}body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#0b1220;color:#e2e8f0;margin:0;padding:16px}
h1{font-size:22px;margin:0 0 4px}.sub{color:#94a3b8;font-size:13px;margin-bottom:16px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin-bottom:16px}
.card{background:#111c33;border:1px solid #1e293b;border-radius:10px;padding:12px}
.card h3{margin:0 0 8px;font-size:13px;color:#94a3b8;text-transform:uppercase;letter-spacing:.06em}
.big{font-size:24px;font-weight:700}.ok{color:#4ade80}.bad{color:#f87171}.warn{color:#fbbf24}
.row{display:flex;gap:8px;flex-wrap:wrap;margin:6px 0}
input,button,select{background:#0b1220;border:1px solid #334155;color:#e2e8f0;border-radius:8px;padding:8px 10px;font-size:14px}
input{flex:1;min-width:140px}button{cursor:pointer;background:#1d4ed8;border-color:#1d4ed8}button:hover{background:#2563eb}
button.danger{background:#7f1d1d;border-color:#7f1d1d}button.ghost{background:transparent}
a{color:#7dd3fc}table{width:100%;border-collapse:collapse;font-size:13px}td,th{padding:6px 8px;border-bottom:1px solid #1e293b;text-align:left}
.mono{font-family:ui-monospace,Consolas,monospace;font-size:12px;word-break:break-all}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:700}
.badge.open{background:#14532d;color:#4ade80}.badge.sealed{background:#422006;color:#fbbf24}
#tok{max-width:280px}footer{color:#64748b;font-size:12px;margin-top:16px}
</style></head><body>
<h1>sr8 dashboard</h1>
<div class="sub">guard reverse-proxy + sealed links · <span id="ver"></span> · uptime <span id="up">-</span></div>
<div class="row">
<input id="tok" type="password" placeholder="ADMIN_TOKEN (?token= works too)">
<button class="ghost" onclick="saveTok()">save token</button>
<span id="mode" class="badge sealed">-</span>
</div>
<div class="grid">
<div class="card"><h3>requests</h3><div class="big" id="c-total">-</div><div class="sub" id="c-break"></div></div>
<div class="card"><h3>frps</h3><div id="f-ports" class="mono">-</div><div class="sub">dash: <span id="f-dash">-</span></div></div>
<div class="card"><h3>store</h3><div class="big" id="s-used">-</div><div class="sub">used links · <span id="s-room">-</span> room rounds</div></div>
<div class="card"><h3>mode</h3><div class="row">
<button onclick="toggle('open')">open</button>
<button onclick="toggle('sealed')">sealed</button>
</div><div class="sub">open = no seal needed · sealed = HMAC links</div></div>
</div>
<div class="grid">
<div class="card"><h3>mint sealed link /t/</h3>
<div class="row"><input id="m-name" placeholder="name (e.g. demo)"><input id="m-ttl" placeholder="ttl sec" value="300" style="max-width:110px"><button onclick="mint()">mint</button></div>
<div id="m-out" class="mono"></div></div>
<div class="card"><h3>room ticket /r/ (rotates <span id="rot">-</span>s)</h3>
<div class="row"><input id="r-room" placeholder="room (e.g. team)"><button onclick="room()">ticket</button></div>
<div id="r-out" class="mono"></div></div>
</div>
<div class="card"><h3>tunnels (frps proxies)</h3><div id="prox" class="mono">-</div></div>
<div class="card"><h3>recent requests</h3><table><thead><tr><th>time</th><th>ip</th><th>m</th><th>path</th><th>code</th><th>kind</th></tr></thead><tbody id="logs"></tbody></table></div>
<footer>sr8 · guard-go dashboard · frps dashboard: <span id="f-link">-</span></footer>
<script>
let TOK=localStorage.getItem('sr8tok')||new URLSearchParams(location.search).get('token')||'';
document.getElementById('tok').value=TOK;
function saveTok(){TOK=document.getElementById('tok').value;localStorage.setItem('sr8tok',TOK);refresh();}
function api(p,opt){opt=opt||{};opt.headers=Object.assign({},opt.headers||{});
if(TOK){opt.headers['X-Admin-Token']=TOK;}
return fetch(p,opt).then(r=>r.json());}
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;');}
function refresh(){
api('/admin/api/status').then(d=>{
document.getElementById('ver').textContent=d.version||'';
document.getElementById('up').textContent=Math.floor(d.uptime_s/3600)+'h '+Math.floor(d.uptime_s%3600/60)+'m';
let m=document.getElementById('mode');m.textContent=d.mode;m.className='badge '+d.mode;
document.getElementById('c-total').textContent=d.counters.total;
document.getElementById('c-break').textContent='seal '+d.counters.seal_ok+'/'+d.counters.seal_deny+' · room '+d.counters.room_ok+'/'+d.counters.room_deny+' · tcp '+d.counters.tcp_ok+'/'+d.counters.tcp_deny;
let bindUp=(d.frps.bind!==undefined?d.frps.bind:d.frps.bind_7000);
let dashUp=(d.frps.dash!==undefined?d.frps.dash:d.frps.dash_7500);
let bindAddr=d.frps.bind_addr||'127.0.0.1:7000';
document.getElementById('f-ports').innerHTML=esc(bindAddr)+' '+(bindUp?'<span class=ok>up</span>':'<span class=bad>down</span>')+' · vhost '+(d.frps.vhost?'<span class=ok>up</span>':'<span class=bad>down</span>');
document.getElementById('f-dash').textContent=dashUp?'up':'down';
document.getElementById('s-used').textContent=d.store.used_links;
document.getElementById('s-room').textContent=d.store.room_rounds;
document.getElementById('f-link').textContent=d.frps.dash_7500?'127.0.0.1:7500 (ssh tunnel)':'-';
}).catch(e=>{});
api('/admin/api/logs?limit=30').then(d=>{
document.getElementById('logs').innerHTML=(d.logs||[]).map(l=>'<tr><td>'+esc(l.ts)+'</td><td class=mono>'+esc(l.ip)+'</td><td>'+esc(l.method)+'</td><td class=mono>'+esc(l.path)+'</td><td>'+l.code+'</td><td>'+esc(l.kind)+'</td></tr>').join('');
}).catch(e=>{});
api('/admin/api/proxies').then(d=>{
let rows=[];
for(let k of ['proxy/tcp','proxy/http','proxy/https','proxy/stcp','proxy/udp']){
let g=d[k];if(!g||!g.data)continue;let arr=g.data.proxies||g.data;
if(!Array.isArray(arr))continue;
arr.forEach(p=>rows.push('<tr><td>'+esc(p.name||'?')+'</td><td>'+esc(p.type||k)+'</td><td class=mono>'+esc(p.localPort||p.local_port||'')+'</td><td class=mono>'+esc(p.remotePort||p.remote_port||p.subdomain||p.customDomains||'')+'</td><td>'+esc(p.status||'')+'</td></tr>'));
}
document.getElementById('prox').innerHTML=rows.length?'<table><thead><tr><th>name</th><th>type</th><th>local</th><th>remote/domain</th><th>status</th></tr></thead><tbody>'+rows.join('')+'</tbody></table>':'no proxies registered';
}).catch(e=>{});
}
function mint(){let n=document.getElementById('m-name').value,t=document.getElementById('m-ttl').value||'300';
api('/admin/api/mint',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:n,ttl:parseInt(t)})}).then(d=>{
document.getElementById('m-out').innerHTML=d.link?'<a href="'+esc(d.link)+'" target=_blank>'+esc(d.link)+'</a>':'<span class=bad>'+esc(d.error||'?')+'</span>';});}
function room(){let r=document.getElementById('r-room').value;
api('/admin/api/room',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({room:r})}).then(d=>{
document.getElementById('rot').textContent=d.rotate_secs||'-';
document.getElementById('r-out').innerHTML=d.link?'<a href="'+esc(d.link)+'" target=_blank>'+esc(d.link)+'</a><br>round '+d.round:'<span class=bad>'+esc(d.error||'?')+'</span>';});}
function toggle(m){api('/admin/api/toggle',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mode:m})}).then(refresh);}
refresh();setInterval(refresh,5000);
</script></body></html>`
