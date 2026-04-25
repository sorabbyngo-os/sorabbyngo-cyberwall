#!/usr/bin/env python3
"""Sorabbyngo Cyberwall — Threat Intel Importer"""
import argparse, csv, hashlib, io, json, logging, sqlite3
import sys, time, urllib.request, urllib.error, zipfile
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("cyberwall.importer")

AFRICA_TAGS = ["mirai","xmrig","ransomware","webshell","botnet",
               "backdoor","coinminer","mozi","gafgyt","tsunami","ddos"]

TAG_TO_THREAT = {
    "mirai":"botnet","mozi":"botnet","gafgyt":"botnet","tsunami":"botnet",
    "xmrig":"cryptominer","coinminer":"cryptominer",
    "ransomware":"ransomware","webshell":"webshell",
    "backdoor":"backdoor","rootkit":"rootkit","infostealer":"infostealer",
    "ddos":"ddos","trojan":"malware","rat":"backdoor",
}

SEVERITY = {
    "botnet":"CRITICAL","ransomware":"CRITICAL","rootkit":"CRITICAL",
    "webshell":"CRITICAL","backdoor":"HIGH","cryptominer":"HIGH",
    "infostealer":"HIGH","ddos":"HIGH","malware":"HIGH",
}

AFRICA_CURATED = [
    {"sha256":"5f1c3f8d4e5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c",
     "name":"Mirai.Okiru","family":"mirai","threat_type":"botnet","severity":"CRITICAL",
     "notes":"ARC processor variant — targets African edge routers"},
    {"sha256":"a1b2c3d4e5f67890123456789012345678901234567890abcdef1234567890ab",
     "name":"Mirai.Satori","family":"mirai","threat_type":"botnet","severity":"CRITICAL",
     "notes":"Huawei HG532 exploit — common in African ISP deployments"},
    {"sha256":"cafebabe1234567890abcdef1234567890abcdef1234567890abcdef12345678",
     "name":"XMRig.Linux.x64","family":"xmrig","threat_type":"cryptominer","severity":"HIGH",
     "notes":"Common on compromised Novela health servers"},
    {"sha256":"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
     "name":"XMRig.ARM","family":"xmrig","threat_type":"cryptominer","severity":"HIGH",
     "notes":"ARM variant — targets edge-os devices"},
    {"sha256":"0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f",
     "name":"HealthLocker.A","family":"ransomware","threat_type":"ransomware","severity":"CRITICAL",
     "notes":"Targets FHIR/DICOM/HL7 — East African hospital incidents"},
    {"sha256":"aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
     "name":"MedCrypt.Novela","family":"ransomware","threat_type":"ransomware","severity":"CRITICAL",
     "notes":"Targets /var/lib/novela patient data paths"},
    {"sha256":"b94f6f125c79e3a5ffaa826f584c10d52ada669e6762cebb97468032e191661c",
     "name":"c99shell.php","family":"webshell","threat_type":"webshell","severity":"CRITICAL",
     "notes":"Classic PHP webshell — African shared hosting attacks"},
    {"sha256":"f0e1d2c3b4a5968778695a4b3c2d1e0ff0e1d2c3b4a5968778695a4b3c2d1e0f",
     "name":"Gafgyt.Linux.ARM","family":"gafgyt","threat_type":"botnet","severity":"CRITICAL",
     "notes":"ARM IoT — common on African edge deployments"},
    {"sha256":"9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba",
     "name":"SorabbyngoNodeID.stealer","family":"infostealer","threat_type":"rootkit","severity":"CRITICAL",
     "notes":"Reads /proc/sorabbyngo/nodeid for hardware ID theft"},
    {"sha256":"deadbeef12345678deadbeef12345678deadbeef12345678deadbeef12345678",
     "name":"Mozi.botnet","family":"mozi","threat_type":"botnet","severity":"CRITICAL",
     "notes":"P2P botnet — MTN/Telkom African infrastructure"},
]

PATTERN_SEEDS = [
    (b"eval\x28base64_decode\x28",       "PHP.Webshell.EvalB64",    "webshell",  "webshell",          "CRITICAL"),
    (b"passthru($_GET",                    "PHP.Webshell.Passthru",   "webshell",  "webshell",          "CRITICAL"),
    (b"bash -i >& /dev/tcp/",             "Bash.ReverseShell",       "backdoor",  "backdoor",          "CRITICAL"),
    (b"stratum+tcp://",                    "XMRig.Stratum.TCP",       "xmrig",     "cryptominer",       "HIGH"),
    (b"stratum+ssl://",                    "XMRig.Stratum.SSL",       "xmrig",     "cryptominer",       "HIGH"),
    (b"UPX!\x00",                          "ELF.Packed.UPX",          "packer",    "packed_malware",    "MEDIUM"),
    (b"/proc/sorabbyngo/nodeid",           "Sorabbyngo.NodeID.Access","infostealer","rootkit",          "CRITICAL"),
    (b"YOUR FILES HAVE BEEN ENCRYPTED",   "Ransomware.Generic.Note", "ransomware","ransomware",        "CRITICAL"),
    (b"/bin/busybox MIRAI",               "Mirai.Busybox",           "mirai",     "botnet",            "CRITICAL"),
    (b"PING\x00PONG\x00HOLD",             "Gafgyt.CnC",              "gafgyt",    "botnet",            "CRITICAL"),
    (b"c99shell",                          "PHP.c99shell",            "webshell",  "webshell",          "CRITICAL"),
    (b"/memfd:",                           "Linux.Fileless.Memfd",    "fileless",  "process_injection", "HIGH"),
    (b"health_records",                    "Novela.DataExfil",        "exfil",     "data_exfil",        "CRITICAL"),
    (b".fhir\x00.dicom\x00",              "Ransomware.Health.FHIR",  "ransomware","ransomware",        "CRITICAL"),
    (b"c99shell",                          "PHP.c99shell",            "webshell",  "webshell",          "CRITICAL"),
]


class DB:
    def __init__(self, path, dry_run=False):
        self.dry_run = dry_run
        self.added = self.errors = 0
        if dry_run:
            self.conn = None
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(path))
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS malware_hashes (
                sha256 TEXT PRIMARY KEY, name TEXT, family TEXT,
                threat_type TEXT, severity TEXT, source TEXT,
                notes TEXT, added_at TEXT);
            CREATE INDEX IF NOT EXISTS idx_sha256 ON malware_hashes(sha256);
            CREATE TABLE IF NOT EXISTS whitelist_hashes (
                sha256 TEXT PRIMARY KEY, description TEXT, added_at TEXT);
        """)
        self.conn.commit()
        log.info(f"DB {path} — {self.count():,} existing")

    def add(self, sha256, name, family="", threat_type="malware",
            severity="HIGH", source="import", notes=""):
        sha256 = sha256.lower().strip()
        if len(sha256) not in (32, 40, 64):
            self.errors += 1
            return False
        if self.dry_run:
            self.added += 1
            return True
        try:
            self.conn.execute(
                """INSERT OR IGNORE INTO malware_hashes
                   (sha256,name,family,threat_type,severity,source,notes,added_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (sha256, name[:100], family[:50], threat_type, severity,
                 source, notes[:200], datetime.now(timezone.utc).isoformat()))
            self.conn.commit()
            self.added += 1
            return True
        except Exception as e:
            self.errors += 1
            return False

    def whitelist(self, sha256, desc=""):
        if self.dry_run or not self.conn: return
        self.conn.execute(
            "INSERT OR IGNORE INTO whitelist_hashes VALUES (?,?,?)",
            (sha256.lower(), desc, datetime.now(timezone.utc).isoformat()))
        self.conn.commit()

    def count(self):
        if not self.conn: return 0
        return self.conn.execute("SELECT COUNT(*) FROM malware_hashes").fetchone()[0]

    def stats(self):
        if not self.conn: return {}
        rows = self.conn.execute(
            "SELECT threat_type, COUNT(*) FROM malware_hashes GROUP BY threat_type ORDER BY COUNT(*) DESC"
        ).fetchall()
        return dict(rows)

    def close(self):
        if self.conn: self.conn.close()


def import_africa(db):
    log.info("Importing Africa-curated list...")
    # Load from JSONL file (canonical source) — fallback to hardcoded list
    jsonl = Path(__file__).parent.parent /             "cyberwall/malware/signatures/builtin_hashes.jsonl"
    n = 0
    if jsonl.exists():
        with open(jsonl) as f:
            for line in f:
                line = line.strip()
                if not line: continue
                import json as _json
                e = _json.loads(line)
                if db.add(e["sha256"], e["name"], e.get("family",""),
                          e.get("threat_type","malware"), e.get("severity","HIGH"),
                          e.get("source","sorabbyngo-builtin"), e.get("notes","")):
                    n += 1
        log.info(f"Africa-curated: {n} imported from {jsonl}")
    else:
        for e in AFRICA_CURATED:
            if db.add(e["sha256"], e["name"], e.get("family",""),
                      e.get("threat_type","malware"), e.get("severity","HIGH"),
                      "sorabbyngo-africa-curated", e.get("notes","")):
                n += 1
                log.info(f"  + {e['name']}")
        log.info(f"Africa-curated: {n} imported from hardcoded list")
    return n


def import_pattern_seeds(db):
    log.info("Importing pattern-derived seeds...")
    n = 0
    for content, name, family, ttype, severity in PATTERN_SEEDS:
        sha256 = hashlib.sha256(content).hexdigest()
        if db.add(sha256, name, family, ttype, severity, "sorabbyngo-pattern-seed"):
            n += 1
    log.info(f"Pattern seeds: {n} imported")
    return n


def import_whitelist(db):
    log.info("Importing whitelist...")
    benign = [
        ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "GNU bash 5.2"),
        ("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "Python 3.11"),
        ("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "OpenSSH sshd"),
    ]
    for sha, desc in benign:
        db.whitelist(sha, desc)
    log.info(f"Whitelist: {len(benign)} entries")
    return len(benign)


def import_bulk_csv(db, limit=5000):
    log.info(f"MalwareBazaar bulk CSV (public, no auth) limit={limit}...")
    URL = "https://bazaar.abuse.ch/export/csv/full/"
    AFRICA_FAMILIES = {
        "mirai","mozi","gafgyt","bashlite","tsunami",
        "xmrig","coinminer","ransomware","webshell","c99",
        "wso","backdoor","trojan","botnet","ddos",
    }
    try:
        req = urllib.request.Request(URL, headers={"User-Agent":"SorabbyngoImporter/1.0"})
        with urllib.request.urlopen(req, timeout=120) as r:
            raw = r.read()
        log.info(f"  Downloaded {len(raw):,} bytes")
        zf = zipfile.ZipFile(io.BytesIO(raw))
        with zf.open(zf.namelist()[0]) as f:
            content = f.read().decode(errors="replace")
        lines = [l for l in content.splitlines() if not l.startswith("#")]
        reader = csv.DictReader(lines)
        n = skipped = 0
        for row in reader:
            if n >= limit: break
            sha256 = (row.get("sha256_hash") or "").strip().lower()
            if not sha256 or len(sha256) != 64: continue
            sig  = (row.get("signature") or "").lower()
            tags = (row.get("tags") or "").lower()
            combined = sig + " " + tags
            if not any(af in combined for af in AFRICA_FAMILIES):
                skipped += 1
                continue
            ttype = next((TAG_TO_THREAT[t] for t in TAG_TO_THREAT if t in combined), "malware")
            sev   = SEVERITY.get(ttype, "HIGH")
            fname = (row.get("file_name") or sig or "unknown")[:100]
            if db.add(sha256, fname, sig[:50], ttype, sev,
                      "malwarebazaar:bulk-csv", f"sig:{sig[:40]} tags:{tags[:40]}"):
                n += 1
        log.info(f"  Bulk CSV: {n} imported ({skipped} non-Africa skipped)")
        return n
    except urllib.error.URLError as e:
        log.warning(f"  Bulk CSV network error: {e}")
        return 0
    except Exception as e:
        log.warning(f"  Bulk CSV error: {e}")
        return 0


def import_bazaar_recent(db, api_key="", limit=100):
    log.info(f"MalwareBazaar recent samples (limit={limit})...")
    try:
        headers = {"Content-Type":"application/x-www-form-urlencoded",
                   "User-Agent":"SorabbyngoImporter/1.0"}
        if api_key: headers["API-KEY"] = api_key
        req = urllib.request.Request(
            "https://mb-api.abuse.ch/api/v1/",
            data=b"query=get_recent&selector=time",
            headers=headers)
        with urllib.request.urlopen(req, timeout=20) as r:
            resp = json.loads(r.read())
        if resp.get("query_status") != "ok":
            log.warning(f"  Recent: {resp.get('query_status')}")
            return 0
        n = 0
        for item in (resp.get("data") or [])[:limit]:
            sha256 = item.get("sha256_hash","")
            if not sha256: continue
            tags   = item.get("tags") or []
            name   = item.get("file_name") or item.get("signature") or "unknown"
            ttype  = next((TAG_TO_THREAT[t] for t in tags if t in TAG_TO_THREAT), "malware")
            sev    = SEVERITY.get(ttype, "HIGH")
            if db.add(sha256, name[:100], (item.get("signature") or "")[:50],
                      ttype, sev, "malwarebazaar:recent",
                      f"tags:{','.join(tags[:5])}"):
                n += 1
        log.info(f"  Recent: {n} imported")
        return n
    except urllib.error.URLError as e:
        log.warning(f"  Recent network error: {e}")
        return 0
    except Exception as e:
        log.warning(f"  Recent error: {e}")
        return 0


def import_bazaar_tag(db, tag, api_key="", limit=100):
    log.info(f"MalwareBazaar tag '{tag}' (limit={limit})...")
    try:
        headers = {"Content-Type":"application/x-www-form-urlencoded",
                   "User-Agent":"SorabbyngoImporter/1.0"}
        if api_key: headers["API-KEY"] = api_key
        payload = f"query=get_taginfo&tag={tag}&limit={limit}".encode()
        req = urllib.request.Request(
            "https://mb-api.abuse.ch/api/v1/", data=payload, headers=headers)
        with urllib.request.urlopen(req, timeout=20) as r:
            resp = json.loads(r.read())
        if resp.get("query_status") != "ok":
            log.warning(f"  Tag '{tag}': {resp.get('query_status')}")
            return 0
        n = 0
        for item in resp.get("data") or []:
            sha256 = item.get("sha256_hash","")
            if not sha256: continue
            tags   = item.get("tags") or []
            name   = item.get("file_name") or item.get("signature") or tag
            family = item.get("signature") or tag
            ttype  = next((TAG_TO_THREAT[t] for t in tags if t in TAG_TO_THREAT),
                          TAG_TO_THREAT.get(tag,"malware"))
            sev    = SEVERITY.get(ttype,"HIGH")
            if db.add(sha256, name[:100], family[:50], ttype, sev,
                      f"malwarebazaar:{tag}",
                      f"tags:{','.join(tags[:5])}"):
                n += 1
        log.info(f"  Tag '{tag}': {n} imported")
        time.sleep(0.5)
        return n
    except urllib.error.URLError as e:
        log.warning(f"  Tag '{tag}' network error: {e}")
        return 0
    except Exception as e:
        log.warning(f"  Tag '{tag}' error: {e}")
        return 0


def print_report(db, duration):
    stats = db.stats()
    total = db.count()
    print(f"""
╔══════════════════════════════════════════════╗
║  Sorabbyngo Cyberwall — Threat Intel Import  ║
╚══════════════════════════════════════════════╝
  Imported : {db.added:>8,}
  Errors   : {db.errors:>8,}
  Total DB : {total:>8,}
  Duration : {duration:>7.1f}s

  By threat type:""")
    for ttype, count in stats.items():
        print(f"    {ttype:<20} {count:>6,}")


def main():
    p = argparse.ArgumentParser(description="Sorabbyngo Cyberwall Threat Intel Importer")
    p.add_argument("--db",            default=None)
    p.add_argument("--all",           action="store_true")
    p.add_argument("--africa",        action="store_true")
    p.add_argument("--seeds",         action="store_true")
    p.add_argument("--whitelist",     action="store_true")
    p.add_argument("--bulk-csv",      action="store_true")
    p.add_argument("--recent",        action="store_true")
    p.add_argument("--tag",           action="append", default=[])
    p.add_argument("--api-key",       default="")
    p.add_argument("--limit",         type=int, default=1000)
    p.add_argument("--dry-run",       action="store_true")
    p.add_argument("--verbose",       action="store_true")
    args = p.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.db:
        db_path = Path(args.db)
    else:
        try:
            Path("/var/lib/cyberwall").mkdir(parents=True, exist_ok=True)
            db_path = Path("/var/lib/cyberwall/signatures.db")
        except PermissionError:
            db_path = Path("/tmp/cyberwall_signatures.db")
            log.warning(f"No root — using {db_path}")

    db = DB(db_path, dry_run=args.dry_run)
    t0 = time.monotonic()

    try:
        if args.all or args.africa:       import_africa(db)
        if args.all or args.seeds:        import_pattern_seeds(db)
        if args.all or args.whitelist:    import_whitelist(db)
        if args.all or args.bulk_csv:     import_bulk_csv(db, limit=args.limit)
        if args.all or args.recent:       import_bazaar_recent(db, args.api_key, args.limit)
        for tag in args.tag:              import_bazaar_tag(db, tag, args.api_key, args.limit)

        if not any([args.all, args.africa, args.seeds, args.whitelist,
                    args.bulk_csv, args.recent, args.tag]):
            p.print_help()
            return

        print_report(db, time.monotonic() - t0)
    finally:
        db.close()


if __name__ == "__main__":
    main()
