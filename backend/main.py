from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import requests
import sqlite3
import json
import re
from datetime import datetime
from typing import Optional

app = FastAPI(title="ThreatLens TIP", docs_url=None, redoc_url=None, openapi_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = "threatlens.db"
ADMIN_SECRET = "threatlens2024"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS lookups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT, type TEXT, timestamp TEXT,
        result TEXT, severity TEXT, recommendation TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY, value TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS custom_sources (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT, endpoint TEXT, api_key TEXT,
        header_name TEXT, enabled INTEGER DEFAULT 1
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS malicious_targets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT UNIQUE, type TEXT, severity TEXT,
        added_at TEXT, source TEXT
    )""")
    for k in ["virustotal_key","abuseipdb_key","shodan_key"]:
        c.execute("INSERT OR IGNORE INTO settings (key,value) VALUES (?,?)",(k,""))
    conn.commit()
    conn.close()

def get_setting(key):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT value FROM settings WHERE key=?",(key,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else ""

def save_lookup(target, target_type, result, severity, recommendation):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO lookups (target,type,timestamp,result,severity,recommendation) VALUES (?,?,?,?,?,?)",
        (target, target_type, datetime.utcnow().isoformat(), json.dumps(result), severity, recommendation))
    conn.commit()
    conn.close()

def is_malicious_in_db(target):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT severity FROM malicious_targets WHERE target=?",(target,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None

def add_to_malicious_db(target, target_type, severity, source="auto"):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO malicious_targets (target,type,severity,added_at,source) VALUES (?,?,?,?,?)",
        (target, target_type, severity, datetime.utcnow().isoformat(), source))
    conn.commit()
    conn.close()

def detect_type(target):
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
        return "ip"
    return "domain"

# ── Raw API calls - return full response ─────────────────────────────────────

def check_virustotal(target, target_type):
    key = get_setting("virustotal_key")
    if not key:
        return {"error": "No API key configured"}
    try:
        if target_type == "ip":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
        else:
            url = f"https://www.virustotal.com/api/v3/domains/{target}"
        r = requests.get(url, headers={"x-apikey": key}, timeout=10)
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def check_abuseipdb(target, target_type):
    if target_type != "ip":
        return {"error": "AbuseIPDB only supports IPs"}
    key = get_setting("abuseipdb_key")
    if not key:
        return {"error": "No API key configured"}
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": target, "maxAgeInDays": 90, "verbose": True},
            timeout=10
        )
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def check_shodan(target, target_type):
    if target_type != "ip":
        return {"error": "Shodan only supports IPs"}
    key = get_setting("shodan_key")
    if not key:
        return {"error": "No API key configured"}
    try:
        r = requests.get(
            f"https://api.shodan.io/shodan/host/{target}?key={key}",
            timeout=10
        )
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def check_custom_sources(target):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT name, endpoint, api_key, header_name FROM custom_sources WHERE enabled=1")
    sources = c.fetchall()
    conn.close()
    results = {}
    for name, endpoint, api_key, header_name in sources:
        try:
            url = endpoint.replace("{ip}", target).replace("{target}", target)
            headers = {}
            if api_key and header_name:
                headers[header_name] = api_key
            r = requests.get(url, headers=headers, timeout=10)
            results[name] = r.json()
        except Exception as e:
            results[name] = {"error": str(e)}
    return results

def calculate_severity(vt_raw, abuse_raw, shodan_raw):
    score = 0
    try:
        stats = vt_raw.get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
        score += stats.get("malicious", 0) * 10
        score += stats.get("suspicious", 0) * 5
        rep = vt_raw.get("data",{}).get("attributes",{}).get("reputation", 0)
        if rep < -10: score += 20
    except: pass
    try:
        abuse_score = abuse_raw.get("data",{}).get("abuseConfidenceScore", 0)
        score += abuse_score
        reports = abuse_raw.get("data",{}).get("totalReports", 0)
        score += reports * 2
    except: pass
    try:
        vulns = shodan_raw.get("vulns", {})
        score += len(vulns) * 10
        ports = shodan_raw.get("ports", [])
        for p in ports:
            if p in [22, 23, 3389, 445, 1433, 3306]: score += 5
    except: pass

    if score >= 80: return "CRITICAL", "Block"
    elif score >= 50: return "HIGH", "Block"
    elif score >= 20: return "MEDIUM", "Investigate"
    else: return "LOW", "Monitor"

# ── Models ────────────────────────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    ip: Optional[str] = None
    target: Optional[str] = None

class MaliciousRequest(BaseModel):
    target: str
    severity: Optional[str] = "HIGH"

class CustomSourceRequest(BaseModel):
    name: str
    endpoint: str
    api_key: Optional[str] = ""
    header_name: Optional[str] = "Authorization"

class AdminSettingsRequest(BaseModel):
    virustotal_key: Optional[str] = ""
    abuseipdb_key: Optional[str] = ""
    shodan_key: Optional[str] = ""

# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.on_event("startup")
def startup():
    init_db()

@app.post("/analyze/ip")
def analyze_ip(req: AnalyzeRequest):
    target = (req.ip or req.target or "").strip()
    if not target:
        raise HTTPException(400, "No target provided")

    target_type = detect_type(target)

    # Check malicious DB - but still query all APIs
    known_severity = is_malicious_in_db(target)

    # Always query all APIs - full raw response every time
    vt = check_virustotal(target, target_type)
    abuse = check_abuseipdb(target, target_type)
    shodan = check_shodan(target, target_type)
    custom = check_custom_sources(target)

    severity, recommendation = calculate_severity(vt, abuse, shodan)

    # If in malicious DB, override severity to blocked
    if known_severity:
        severity = known_severity
        recommendation = "Block"

    # Auto-save HIGH/CRITICAL to malicious DB
    if severity in ["HIGH", "CRITICAL"]:
        add_to_malicious_db(target, target_type, severity, source="auto")

    # Build threat score
    score = 0
    try:
        stats = vt.get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
        score += stats.get("malicious",0) * 10
        score += stats.get("suspicious",0) * 5
    except: pass
    try:
        score += abuse.get("data",{}).get("abuseConfidenceScore",0)
    except: pass
    try:
        score += len(shodan.get("vulns",{})) * 10
    except: pass
    score = min(score, 100)

    # Build indicators
    indicators = []
    try:
        mal = vt.get("data",{}).get("attributes",{}).get("last_analysis_stats",{}).get("malicious",0)
        if mal > 0: indicators.append(f"{mal} malicious detections")
    except: pass
    try:
        conf = abuse.get("data",{}).get("abuseConfidenceScore",0)
        if conf > 30: indicators.append(f"{conf}% abuse confidence")
    except: pass
    try:
        vulns = list(shodan.get("vulns",{}).keys())
        if vulns: indicators.append(f"{len(vulns)} known CVEs")
    except: pass

    # Add known malicious indicator
    if known_severity:
        indicators.insert(0, "Known malicious target — in local blacklist")

    result = {
        "target": target,
        "type": target_type,
        "timestamp": datetime.utcnow().isoformat(),
        "source": "ThreatLens Intelligence",
        "severity": severity,
        "recommendation": recommendation,
        "auto_blocked": bool(known_severity) or severity in ["HIGH","CRITICAL"],
        "threat_score": score,
        "indicators": indicators,
        "virustotal": vt,
        "abuseipdb": abuse,
        "shodan": shodan,
        "custom_sources": custom
    }

    save_lookup(target, target_type, result, severity, recommendation)
    return result

@app.post("/analyze/domain")
def analyze_domain(req: AnalyzeRequest):
    return analyze_ip(req)

@app.get("/history")
def get_history():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id,target,type,timestamp,severity,recommendation FROM lookups ORDER BY id DESC LIMIT 100")
    rows = c.fetchall()
    conn.close()
    return [{"id":r[0],"target":r[1],"type":r[2],"timestamp":r[3],"severity":r[4],"recommendation":r[5]} for r in rows]

@app.get("/history/{id}")
def get_lookup_detail(id: int):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT result FROM lookups WHERE id=?",(id,))
    row = c.fetchone()
    conn.close()
    if not row: raise HTTPException(404,"Not found")
    return json.loads(row[0])

def check_admin(key):
    if key != ADMIN_SECRET:
        raise HTTPException(403, "Forbidden")

@app.get("/admin/settings")
def get_settings(x_admin_key: Optional[str] = Header(None)):
    check_admin(x_admin_key)
    return {k: get_setting(k) for k in ["virustotal_key","abuseipdb_key","shodan_key"]}

@app.post("/admin/settings")
def save_settings(req: AdminSettingsRequest, x_admin_key: Optional[str] = Header(None)):
    check_admin(x_admin_key)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    for key, val in req.dict().items():
        if val: c.execute("INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)",(key,val))
    conn.commit()
    conn.close()
    return {"status": "saved"}

@app.get("/admin/sources")
def get_sources(x_admin_key: Optional[str] = Header(None)):
    check_admin(x_admin_key)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id,name,endpoint,header_name,enabled FROM custom_sources")
    rows = c.fetchall()
    conn.close()
    return [{"id":r[0],"name":r[1],"endpoint":r[2],"header_name":r[3],"enabled":r[4]} for r in rows]

@app.post("/admin/sources")
def add_source(req: CustomSourceRequest, x_admin_key: Optional[str] = Header(None)):
    check_admin(x_admin_key)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO custom_sources (name,endpoint,api_key,header_name) VALUES (?,?,?,?)",
        (req.name, req.endpoint, req.api_key, req.header_name))
    conn.commit()
    conn.close()
    return {"status": "added"}

@app.delete("/admin/sources/{id}")
def delete_source(id: int, x_admin_key: Optional[str] = Header(None)):
    check_admin(x_admin_key)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM custom_sources WHERE id=?",(id,))
    conn.commit()
    conn.close()
    return {"status": "deleted"}

@app.get("/admin/malicious")
def get_malicious(x_admin_key: Optional[str] = Header(None)):
    check_admin(x_admin_key)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id,target,type,severity,added_at,source FROM malicious_targets ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    return [{"id":r[0],"target":r[1],"type":r[2],"severity":r[3],"added_at":r[4],"source":r[5]} for r in rows]

@app.post("/admin/malicious")
def add_malicious(req: MaliciousRequest, x_admin_key: Optional[str] = Header(None)):
    check_admin(x_admin_key)
    target_type = detect_type(req.target)
    add_to_malicious_db(req.target, target_type, req.severity, source="manual")
    return {"status": "added", "target": req.target, "type": target_type}

@app.delete("/admin/malicious/{id}")
def delete_malicious(id: int, x_admin_key: Optional[str] = Header(None)):
    check_admin(x_admin_key)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM malicious_targets WHERE id=?",(id,))
    conn.commit()
    conn.close()
    return {"status": "deleted"}
