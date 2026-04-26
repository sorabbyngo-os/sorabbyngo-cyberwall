"""
Sorabbyngo Cyberwall — Threat Dashboard Server
Lightweight asyncio HTTP + WebSocket server embedded in the daemon.
Access: http://localhost:8888
"""
import asyncio
import json
import logging
import time
from collections import deque
from typing import Set

from cyberwall.core.event_bus import EventBus, ThreatEvent, ThreatLevel

logger = logging.getLogger("cyberwall.dashboard")

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8888
MAX_HISTORY  = 500

HTML = None  # loaded lazily from _render_html()


class DashboardServer:
    def __init__(self, bus: EventBus, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT):
        self.bus  = bus
        self.host = host
        self.port = port
        self._ws_clients: Set[asyncio.Queue] = set()
        self._history: deque = deque(maxlen=MAX_HISTORY)
        self._stats = {
            "total_events": 0, "blocked_ips": 0,
            "critical_count": 0, "high_count": 0,
            "start_time": time.time(),
        }
        self._running = False
        bus.subscribe("*", self._on_event)

    async def _on_event(self, event: ThreatEvent):
        record = {
            "ts":          event.timestamp,
            "source":      event.source,
            "threat_type": event.threat_type,
            "level":       event.level.name,
            "score":       round(event.score, 2),
            "description": event.description[:120],
            "blocked":     event.blocked,
            "quarantined": event.quarantined,
            "node_id":     (event.node_id or "")[:12],
            "data": {
                k: str(v)[:80]
                for k, v in (event.data or {}).items()
                if k in ("src_ip", "pid", "path", "rule", "detection")
            },
        }
        self._history.append(record)
        self._stats["total_events"] += 1
        if event.level >= ThreatLevel.CRITICAL:
            self._stats["critical_count"] += 1
        elif event.level >= ThreatLevel.HIGH:
            self._stats["high_count"] += 1
        if event.blocked:
            self._stats["blocked_ips"] += 1

        msg = json.dumps({"type": "event", "data": record}) + "\n"
        dead = set()
        for q in self._ws_clients:
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                dead.add(q)
        self._ws_clients -= dead

    async def start(self):
        self._running = True
        try:
            server = await asyncio.start_server(
                self._handle_connection, self.host, self.port
            )
            logger.info(f"Dashboard running — http://localhost:{self.port}")
            async with server:
                await server.serve_forever()
        except OSError as e:
            logger.warning(f"Dashboard failed to start on :{self.port} — {e}")

    def stop(self):
        self._running = False

    async def _handle_connection(self, reader, writer):
        try:
            raw = await asyncio.wait_for(reader.read(4096), timeout=10)
            if not raw:
                return
            req = raw.decode(errors="replace")
            line0 = req.splitlines()[0] if req.splitlines() else ""
            parts = line0.split()
            path = parts[1].split("?")[0] if len(parts) > 1 else "/"

            if "upgrade: websocket" in req.lower():
                await self._handle_ws(reader, writer, req)
                return

            if path in ("/", "/index.html"):
                body = _render_html().encode()
                _http(writer, 200, "text/html", body)
            elif path == "/api/stats":
                s = {**self._stats, "uptime_s": int(time.time() - self._stats["start_time"])}
                _http(writer, 200, "application/json", json.dumps(s).encode())
            elif path == "/api/events":
                _http(writer, 200, "application/json",
                      json.dumps(list(self._history)[-100:]).encode())
            else:
                _http(writer, 404, "text/plain", b"not found")
        except Exception as e:
            logger.debug(f"Dashboard conn error: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _handle_ws(self, reader, writer, req):
        import base64, hashlib, struct
        key = next(
            (l.split(":",1)[1].strip() for l in req.splitlines()
             if "Sec-WebSocket-Key" in l), ""
        )
        accept = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
        ).decode()
        writer.write((
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
        ).encode())
        await writer.drain()

        q: asyncio.Queue = asyncio.Queue(maxsize=200)
        self._ws_clients.add(q)

        # Send history
        init = json.dumps({
            "type": "history",
            "data": list(self._history)[-100:],
            "stats": {**self._stats, "uptime_s": int(time.time()-self._stats["start_time"])},
        }) + "\n"
        _ws_frame(writer, init)
        await writer.drain()

        try:
            while self._running:
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=5.0)
                    _ws_frame(writer, msg)
                    await writer.drain()
                except asyncio.TimeoutError:
                    _ws_frame(writer, json.dumps({"type":"ping"})+"\n")
                    await writer.drain()
        except Exception:
            pass
        finally:
            self._ws_clients.discard(q)
            try: writer.close()
            except Exception: pass


def _http(writer, status, ct, body):
    r = (
        f"HTTP/1.1 {status} {'OK' if status==200 else 'Not Found'}\r\n"
        f"Content-Type: {ct}; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\nAccess-Control-Allow-Origin: *\r\n\r\n"
    ).encode() + body
    writer.write(r)


def _ws_frame(writer, msg: str):
    import struct
    data = msg.encode()
    n = len(data)
    if n < 126:
        writer.write(struct.pack("BB", 0x81, n) + data)
    elif n < 65536:
        writer.write(struct.pack("!BBH", 0x81, 126, n) + data)
    else:
        writer.write(struct.pack("!BBQ", 0x81, 127, n) + data)


def _render_html() -> str:
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sorabbyngo Cyberwall</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<style>
:root{--bg:#0d0f14;--sf:#151821;--bd:#1e2330;--tx:#c8cdd8;--mu:#5a6070;
  --red:#e84040;--ora:#e8800a;--yel:#d4a017;--grn:#2ea87e;--blu:#3d8be8;--pur:#7c5cbf}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--tx);font-family:"SF Mono","Fira Code",monospace;
  font-size:13px;min-height:100vh}
header{display:flex;align-items:center;justify-content:space-between;
  padding:14px 24px;border-bottom:1px solid var(--bd);background:var(--sf)}
.logo{font-size:15px;font-weight:700;color:#fff;letter-spacing:.04em}
.logo span{color:var(--red)}
.dot{width:8px;height:8px;border-radius:50%;background:var(--grn);
  display:inline-block;margin-right:6px;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));
  gap:12px;padding:16px 24px}
.card{background:var(--sf);border:1px solid var(--bd);border-radius:8px;padding:14px 16px}
.cl{font-size:11px;color:var(--mu);text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px}
.cv{font-size:26px;font-weight:700;color:#fff}
.cv.r{color:var(--red)}.cv.o{color:var(--ora)}.cv.g{color:var(--grn)}.cv.b{color:var(--blu)}
.main{display:grid;grid-template-columns:1fr 320px;gap:12px;padding:0 24px 16px}
.cc{background:var(--sf);border:1px solid var(--bd);border-radius:8px;padding:16px}
.cc h3{font-size:11px;color:var(--mu);text-transform:uppercase;letter-spacing:.08em;margin-bottom:12px}
.cw{position:relative;height:210px}
.feed{background:var(--sf);border:1px solid var(--bd);border-radius:8px;
  display:flex;flex-direction:column;overflow:hidden}
.fh{padding:10px 16px;border-bottom:1px solid var(--bd);font-size:11px;
  color:var(--mu);text-transform:uppercase;letter-spacing:.08em;
  display:flex;justify-content:space-between}
.fl{overflow-y:auto;flex:1;max-height:520px}
.fi{padding:7px 16px;border-bottom:1px solid var(--bd);
  display:grid;grid-template-columns:64px 1fr auto;gap:8px;align-items:start}
.fi:hover{background:rgba(255,255,255,.02)}
.badge{font-size:10px;font-weight:700;padding:2px 5px;border-radius:3px;text-align:center}
.CRITICAL{background:rgba(232,64,64,.15);color:var(--red)}
.HIGH{background:rgba(232,128,10,.15);color:var(--ora)}
.MEDIUM{background:rgba(212,160,23,.15);color:var(--yel)}
.LOW{background:rgba(46,168,126,.15);color:var(--grn)}
.INFO{background:rgba(90,96,112,.15);color:var(--mu)}
.ft{font-weight:600;color:#e0e4f0;font-size:12px}
.fd{color:var(--mu);font-size:11px;margin-top:2px;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:200px}
.ftm{font-size:10px;color:var(--mu);white-space:nowrap}
.blk{font-size:10px;color:var(--red);border:1px solid var(--red);
  border-radius:3px;padding:1px 4px;margin-left:4px}
.bars{display:grid;grid-template-columns:1fr 1fr;gap:12px;padding:0 24px 24px}
.ws{font-size:11px;color:var(--mu)}
</style>
</head>
<body>
<header>
  <div class="logo">SORABBYNGO <span>CYBERWALL</span></div>
  <div><span class="dot" id="dot"></span><span class="ws" id="ws">connecting...</span></div>
</header>
<div class="grid">
  <div class="card"><div class="cl">Total events</div><div class="cv b" id="s-tot">0</div></div>
  <div class="card"><div class="cl">Critical</div><div class="cv r" id="s-crit">0</div></div>
  <div class="card"><div class="cl">High</div><div class="cv o" id="s-high">0</div></div>
  <div class="card"><div class="cl">Blocked IPs</div><div class="cv r" id="s-blk">0</div></div>
  <div class="card"><div class="cl">Uptime</div><div class="cv g" id="s-up">0s</div></div>
</div>
<div class="main">
  <div class="cc"><h3>Threat timeline (60s)</h3><div class="cw"><canvas id="tl"></canvas></div></div>
  <div class="feed">
    <div class="fh"><span>Live alerts</span><span id="fc">0 events</span></div>
    <div class="fl" id="fl"></div>
  </div>
</div>
<div class="bars">
  <div class="cc"><h3>By threat type</h3><div class="cw"><canvas id="tc"></canvas></div></div>
  <div class="cc"><h3>Severity</h3><div class="cw"><canvas id="lc"></canvas></div></div>
</div>
<script>
const LC={CRITICAL:"#e84040",HIGH:"#e8800a",MEDIUM:"#d4a017",LOW:"#2ea87e",INFO:"#5a6070"};
const TC=["#3d8be8","#e84040","#e8800a","#2ea87e","#7c5cbf","#d4a017","#e84477","#45b0d4"];
let typeCnt={},lvlCnt={},fc=0;
const tl={labels:[],crit:[],high:[],med:[]};
for(let i=59;i>=0;i--){tl.labels.push(i?`-${i}s`:"now");tl.crit.push(0);tl.high.push(0);tl.med.push(0);}
Chart.defaults.color="#5a6070";Chart.defaults.borderColor="#1e2330";
Chart.defaults.font.family="SF Mono,Fira Code,monospace";Chart.defaults.font.size=11;
const tlC=new Chart(document.getElementById("tl"),{type:"line",data:{labels:tl.labels,datasets:[
  {label:"Critical",data:tl.crit,borderColor:"#e84040",backgroundColor:"rgba(232,64,64,.08)",fill:true,tension:.3,pointRadius:0,borderWidth:1.5},
  {label:"High",data:tl.high,borderColor:"#e8800a",backgroundColor:"rgba(232,128,10,.08)",fill:true,tension:.3,pointRadius:0,borderWidth:1.5},
  {label:"Medium",data:tl.med,borderColor:"#d4a017",backgroundColor:"rgba(212,160,23,.06)",fill:true,tension:.3,pointRadius:0,borderWidth:1.5},
]},options:{responsive:true,maintainAspectRatio:false,animation:false,
  plugins:{legend:{position:"top",labels:{boxWidth:10,padding:10}}},
  scales:{x:{grid:{color:"#1e2330"},ticks:{maxTicksLimit:8}},
          y:{grid:{color:"#1e2330"},beginAtZero:true,ticks:{precision:0}}}}});
const tyC=new Chart(document.getElementById("tc"),{type:"bar",
  data:{labels:[],datasets:[{data:[],backgroundColor:TC,borderRadius:3,borderSkipped:false}]},
  options:{responsive:true,maintainAspectRatio:false,animation:false,
    plugins:{legend:{display:false}},
    scales:{x:{grid:{color:"#1e2330"}},y:{grid:{color:"#1e2330"},beginAtZero:true,ticks:{precision:0}}}}});
const lvC=new Chart(document.getElementById("lc"),{type:"doughnut",
  data:{labels:["Critical","High","Medium","Low","Info"],
    datasets:[{data:[0,0,0,0,0],backgroundColor:["#e84040","#e8800a","#d4a017","#2ea87e","#5a6070"],
      borderWidth:0,hoverOffset:4}]},
  options:{responsive:true,maintainAspectRatio:false,animation:false,
    plugins:{legend:{position:"right",labels:{boxWidth:10,padding:8}}}}});
function updStats(s){
  document.getElementById("s-tot").textContent=s.total_events||0;
  document.getElementById("s-crit").textContent=s.critical_count||0;
  document.getElementById("s-high").textContent=s.high_count||0;
  document.getElementById("s-blk").textContent=s.blocked_ips||0;
  const u=s.uptime_s||0,h=Math.floor(u/3600),m=Math.floor(u%3600/60),sec=u%60;
  document.getElementById("s-up").textContent=h?`${h}h ${m}m`:m?`${m}m ${sec}s`:`${sec}s`;
}
function updType(){
  const s=Object.entries(typeCnt).sort((a,b)=>b[1]-a[1]).slice(0,8);
  tyC.data.labels=s.map(([k])=>k.replace(/_/g," "));
  tyC.data.datasets[0].data=s.map(([,v])=>v);tyC.update("none");
}
function updLvl(){
  lvC.data.datasets[0].data=["CRITICAL","HIGH","MEDIUM","LOW","INFO"].map(l=>lvlCnt[l]||0);
  lvC.update("none");
}
function addEvent(e,prepend=true){
  const list=document.getElementById("fl");
  const t=new Date(e.ts).toLocaleTimeString();
  const d=document.createElement("div");d.className="fi";
  d.innerHTML=`<span class="badge ${e.level}">${e.level}</span>
    <div><div class="ft">${e.threat_type.replace(/_/g," ")}${e.blocked?'<span class="blk">BLOCKED</span>':""}</div>
    <div class="fd">${e.description}</div></div>
    <span class="ftm">${t}</span>`;
  if(prepend){list.insertBefore(d,list.firstChild);if(list.children.length>200)list.removeChild(list.lastChild);}
  else list.appendChild(d);
  fc++;document.getElementById("fc").textContent=`${fc} events`;
}
function addTl(level){
  const i=tl.crit.length-1;
  if(level==="CRITICAL")tl.crit[i]++;
  else if(level==="HIGH")tl.high[i]++;
  else if(level==="MEDIUM")tl.med[i]++;
  tlC.update("none");
}
function connect(){
  const ws=new WebSocket(`ws://${location.host}/ws`);
  ws.onopen=()=>{
    document.getElementById("dot").style.background="#2ea87e";
    const el=document.getElementById("ws");el.textContent="live";el.style.color="#2ea87e";
  };
  ws.onmessage=({data})=>{
    let m;try{m=JSON.parse(data.trim());}catch{return;}
    if(m.type==="history"){
      if(m.stats)updStats(m.stats);
      (m.data||[]).forEach(e=>{typeCnt[e.threat_type]=(typeCnt[e.threat_type]||0)+1;
        lvlCnt[e.level]=(lvlCnt[e.level]||0)+1;addEvent(e,false);});
      updType();updLvl();
      const l=document.getElementById("fl");l.scrollTop=l.scrollHeight;
    }else if(m.type==="event"){
      const e=m.data;addTl(e.level);
      typeCnt[e.threat_type]=(typeCnt[e.threat_type]||0)+1;
      lvlCnt[e.level]=(lvlCnt[e.level]||0)+1;
      addEvent(e,true);updType();updLvl();
      if(e.level==="CRITICAL"){document.body.style.outline="2px solid #e84040";
        setTimeout(()=>document.body.style.outline="",300);}
    }else if(m.type==="ping"){
      fetch("/api/stats").then(r=>r.json()).then(updStats).catch(()=>{});
    }
  };
  ws.onclose=()=>{
    document.getElementById("dot").style.background="#e84040";
    document.getElementById("ws").textContent="reconnecting...";
    setTimeout(connect,3000);
  };
}
setInterval(()=>{
  tl.labels.shift();tl.labels.push("now");
  tl.crit.shift();tl.crit.push(0);
  tl.high.shift();tl.high.push(0);
  tl.med.shift();tl.med.push(0);
  tlC.update("none");
},1000);
setInterval(()=>fetch("/api/stats").then(r=>r.json()).then(updStats).catch(()=>{}),5000);
connect();
</script>
</body>
</html>"""
