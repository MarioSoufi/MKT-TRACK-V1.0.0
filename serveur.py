#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MKT Track - Passerelle API (HTML5/JS + Microsoft SQL Server via pyodbc)
Implemente toutes les routes appelees par index.html :
  GET  /, /lib/*, /api/health, /api/rules, /api/state, /api/audit-log, /api/audit/export
  POST /api/auth/login, /api/auth/verify-admin, /api/auth/change-password,
       /api/presence, /api/state, /api/audit-append, /api/audit-reset, /api/audit-backup
Serveur unique (remplace l'ancien serveur de demonstration). Principes : mots de passe verifies cote serveur (PBKDF2-SHA256 sel, comparaison temps constant),
autorisation controlee cote serveur pour chaque route, Audit Trail ajout-seul chaine par SHA-256,
aucune suppression physique de l'Audit Trail (rotation uniquement), exports generes en memoire.
"""
import os, io, re, csv, json, time, hmac, hashlib, secrets, logging, threading, zipfile
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from dotenv import load_dotenv
import pyodbc

HERE = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.environ.get("APP_ENV_FILE", os.path.join(HERE, "..", "config", ".env"))
load_dotenv(ENV_PATH) if os.path.exists(ENV_PATH) else load_dotenv()

APP_HOST = os.getenv("APP_HOST", "0.0.0.0")
APP_PORT = int(os.getenv("APP_PORT", "8089"))
LOG_FILE_PATH = os.getenv("LOG_FILE_PATH", os.path.join(HERE, "..", "logs", "app_server.log"))
SESSION_TTL = int(os.getenv("SESSION_TTL_SECONDS", "1800"))
MAX_ATTEMPTS, LOCK_SECONDS = 3, 30
PBKDF2_ITER = 260000
MAX_BODY = 5 * 1024 * 1024

os.makedirs(os.path.dirname(os.path.abspath(LOG_FILE_PATH)), exist_ok=True)
logging.basicConfig(filename=LOG_FILE_PATH, level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")

DB_LOCK = threading.RLock()          # ecritures serialisees (chaine d'audit coherente)
SESSIONS = {}                        # token -> dict(login, role, profileKey, last, admin_token)
PRESENCE = {}                        # sessionId -> dict
FAILS = {}                           # login(lower) -> dict(count, until)
STATIC_TYPES = {".js": "application/javascript", ".css": "text/css", ".woff2": "font/woff2",
                ".png": "image/png", ".svg": "image/svg+xml", ".map": "application/json"}


# ----------------------------------------------------------------- SQL
def get_sql_connection():
    driver = os.getenv("SQL_DRIVER", "ODBC Driver 18 for SQL Server")
    server = os.getenv("SQL_SERVER", "localhost,1433")
    database = os.getenv("SQL_DATABASE", "DB_PHARMA_APP")
    encrypt = os.getenv("SQL_ENCRYPT", "yes")
    trust = os.getenv("SQL_TRUST_SERVER_CERTIFICATE", "no")
    if os.getenv("SQL_TRUSTED_CONNECTION", "yes").lower() in ("yes", "true", "1", "sspi"):
        auth = "Trusted_Connection=yes;"
    else:
        auth = f"UID={os.getenv('SQL_UID', '')};PWD={os.getenv('SQL_PWD', '')};"
    cs = (f"DRIVER={{{driver}}};SERVER={server};DATABASE={database};{auth}"
          f"Encrypt={encrypt};TrustServerCertificate={trust};")
    return pyodbc.connect(cs, autocommit=False, timeout=5)


def q(cur, sql, params=()):
    cur.execute(sql, params)
    return cur


def rows(cur):
    cols = [c[0] for c in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


# ----------------------------------------------------------------- mots de passe
def make_hash(client_sha256_hex):
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", client_sha256_hex.lower().encode(), salt.encode(), PBKDF2_ITER)
    return f"pbkdf2_sha256${PBKDF2_ITER}${salt}${dk.hex()}"


def verify_hash(client_sha256_hex, stored):
    try:
        algo, it, salt, exp = str(stored).lower().split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", str(client_sha256_hex).strip().lower().encode(), salt.encode(), int(it))
        return hmac.compare_digest(dk.hex(), exp)
    except Exception:
        return False


# ----------------------------------------------------------------- configuration / etat
def _embedded(name, scalar=False):
    """Lit une constante embarquee dans index.html (amorcage du premier demarrage)."""
    html = open(os.path.join(HERE, "index.html"), encoding="utf-8").read()
    pat = r"const %s = \"([^\"]*)\";" if scalar else r"const %s = (\{.*?\n\});\n"
    m = re.search(pat % name, html, 0 if scalar else re.S)
    if not m:
        return "" if scalar else {}
    return m.group(1) if scalar else json.loads(m.group(1))


DEFAULT_RULES = {"version": 1, "status": "A_APPROUVER", "roundingTolerance": False, "excursionThresholdHours": 24}


def ensure_bootstrap(cur):
    """Premier demarrage : charge profils/equipements/branding embarques + comptes (hash existants)."""
    r = q(cur, "SELECT COUNT(*) FROM dbo.AppConfig").fetchone()[0]
    if r == 0:
        profiles = _embedded("EMBEDDED_PROFILES_DB")
        users = []
        for k, p in profiles.items():
            for op in (p.get("operators") or [{"login": p.get("login"), "passHash": p.get("passHash")}]):
                users.append((op["login"], op["passHash"], k))
            p["operators"] = []
            p.pop("passHash", None)
        cfg = {"profiles": profiles, "enterprise": _embedded("EMBEDDED_ENTERPRISE_CONFIG"), "rules": DEFAULT_RULES}
        q(cur, "INSERT INTO dbo.AppConfig (Id, ConfigJson) VALUES (1, ?)", (json.dumps(cfg, ensure_ascii=False),))
        n = q(cur, "SELECT COUNT(*) FROM dbo.Users").fetchone()[0]
        if n == 0:
            q(cur, "INSERT INTO dbo.Users (Username, PasswordHash, FullName, RoleName) VALUES (?,?,?,?)",
              (_embedded("EMBEDDED_ADMIN_LOGIN", scalar=True) or "Admin", _embedded("EMBEDDED_ADMIN_PASS_HASH", scalar=True), "Administrateur", "ADMIN"))
            for login, ph, key in users:
                q(cur, "INSERT INTO dbo.Users (Username, PasswordHash, FullName, RoleName) VALUES (?,?,?,?)",
                  (login, ph, login, key))
        cur.connection.commit()


def load_cfg(cur):
    return json.loads(q(cur, "SELECT ConfigJson FROM dbo.AppConfig WHERE Id = 1").fetchone()[0])


def get_version(cur):
    return int(q(cur, "SELECT VersionNumber FROM dbo.AppVersion WHERE Id = 1").fetchone()[0])


def bump_version(cur):
    q(cur, "UPDATE dbo.AppVersion SET VersionNumber = VersionNumber + 1, LastModifiedAt = SYSDATETIMEOFFSET() WHERE Id = 1")
    return get_version(cur)


def build_state(cur):
    """Etat envoye aux clients : AUCUN hash de mot de passe n'est expose."""
    cfg = load_cfg(cur)
    profiles = json.loads(json.dumps(cfg["profiles"]))
    users = rows(q(cur, "SELECT Username, RoleName, IsActive FROM dbo.Users ORDER BY UserId"))
    for p in profiles.values():
        p["operators"] = [{"login": u["Username"], "passHash": ""} for u in users
                          if u["RoleName"] == p.get("id") and u["IsActive"]]
        p["login"] = p["operators"][0]["login"] if p["operators"] else ""
        p["passHash"] = ""
    admin = q(cur, "SELECT Username FROM dbo.Users WHERE RoleName = 'ADMIN' ORDER BY UserId").fetchone()
    return {"version": get_version(cur), "adminLogin": admin[0] if admin else "Admin",
            "enterpriseConfig": cfg.get("enterprise", {}), "profilesDb": profiles}


# ----------------------------------------------------------------- audit trail
def audit_append(cur, event, ws="SERVEUR"):
    """Ajout-seul : seq/prevHash/hash calcules par le serveur (meme formule que le client)."""
    ts = str(event.get("timestamp") or datetime.now().strftime("%d/%m/%Y %H:%M:%S"))
    actor = str(event.get("actor", "Système"))[:150]
    service = str(event.get("service", "SYSTÈME"))[:100]
    action = str(event.get("action", ""))[:100]
    details = str(event.get("details", ""))[:500]
    if not action:
        raise ValueError("action manquante")
    last = q(cur, "SELECT EventId, EntryHash FROM dbo.AuditTrail ORDER BY EventId DESC").fetchone()
    seq = (last[0] + 1) if last else 1
    prev = (last[1][:16]) if last and last[1] else "GENESIS_00000000"
    h = hashlib.sha256(f"{seq}|{ts}|{actor}|{service}|{action}|{details}|{prev}".encode()).hexdigest()
    q(cur, """INSERT INTO dbo.AuditTrail (ClientTimestamp, Actor, Service, Action, Details, PrevHash, EntryHash, CorrelationId)
              VALUES (?,?,?,?,?,?,?,?)""",
      (ts, actor, service, action, details, prev, h, f"TX-{ws}-{int(time.time()*1000)}"))
    return {"seq": seq, "timestamp": ts, "actor": actor, "service": service, "action": action,
            "details": details, "prevHash": prev, "hash": h}


def audit_list(cur):
    rs = rows(q(cur, """SELECT EventId, ClientTimestamp, Actor, Service, Action, Details, PrevHash, EntryHash
                        FROM dbo.AuditTrail ORDER BY EventId ASC"""))
    return [{"seq": r["EventId"], "timestamp": r["ClientTimestamp"], "actor": r["Actor"], "service": r["Service"],
             "action": r["Action"], "details": r["Details"], "prevHash": r["PrevHash"], "hash": r["EntryHash"]} for r in rs]


# ----------------------------------------------------------------- HTTP
class Handler(BaseHTTPRequestHandler):
    server_version = "MKTTrack"
    sys_version = ""

    def log_message(self, fmt, *args):
        logging.info("%s - %s", self.address_string(), fmt % args)

    # ---- helpers
    def _send(self, code, body, ctype, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def js(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8"),
                   "application/json; charset=utf-8")

    def ws(self):
        return self.headers.get("X-Client-Workstation", self.client_address[0])

    def session(self, token_qs=None):
        h = self.headers.get("Authorization", "")
        tok = h[7:] if h.startswith("Bearer ") else (token_qs or "")
        s = SESSIONS.get(tok)
        if not s or time.time() - s["last"] > SESSION_TTL:
            SESSIONS.pop(tok, None)
            return None
        s["last"] = time.time()
        return s

    def is_admin(self, s):
        return bool(s and s["role"] == "ADMIN" and s.get("admin_token")
                    and hmac.compare_digest(s["admin_token"], self.headers.get("X-Admin-Token", "")))

    def body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        if n > MAX_BODY:
            raise ValueError("corps trop volumineux")
        raw = self.rfile.read(n).decode("utf-8") if n else "{}"
        d = json.loads(raw or "{}")
        if not isinstance(d, dict):
            raise ValueError("JSON objet attendu")
        return d

    def deny(self, code=401, msg="Authentification requise"):
        self.js(code, {"status": "error", "message": msg})

    # ---- GET
    def do_GET(self):
        u = urlparse(self.path)
        p, qs = u.path, parse_qs(u.query)
        try:
            if p in ("/", "/index.html"):
                return self._send(200, open(os.path.join(HERE, "index.html"), "rb").read(), "text/html; charset=utf-8")
            if p.startswith("/lib/"):
                fp = os.path.normpath(os.path.join(HERE, "lib", p[5:]))
                if not fp.startswith(os.path.join(HERE, "lib")) or not os.path.isfile(fp):
                    return self.js(404, {"error": "introuvable"})
                return self._send(200, open(fp, "rb").read(),
                                  STATIC_TYPES.get(os.path.splitext(fp)[1], "application/octet-stream"),
                                  {"Cache-Control": "public, max-age=86400"})
            if p == "/api/health":
                with get_sql_connection() as conn:
                    q(conn.cursor(), "SELECT 1")
                return self.js(200, {"status": "HEALTHY", "service": "Running", "database": "CONNECTED",
                                     "timestamp_utc": datetime.now(timezone.utc).isoformat()})
            with get_sql_connection() as conn:
                cur = conn.cursor()
                if p == "/api/rules":
                    return self.js(200, load_cfg(cur).get("rules", DEFAULT_RULES))
                if p == "/api/version":
                    return self.js(200, {"version": get_version(cur)})
                s = self.session((qs.get("token") or [""])[0])
                if not s:
                    return self.deny()
                if p == "/api/state":
                    st = build_state(cur)
                    st["auditLog"] = audit_list(cur)
                    return self.js(200, st)
                if p == "/api/audit-log":
                    return self.js(200, {"auditLog": audit_list(cur)})
                if p == "/api/audit/export":
                    fmt = (qs.get("format") or ["csv"])[0]
                    return self.export(cur, fmt)
            self.js(404, {"error": "Route introuvable"})
        except Exception as exc:
            logging.error("GET %s: %s", p, exc)
            self.js(503, {"status": "ERROR", "code": "DB_UNAVAILABLE"})

    def export(self, cur, fmt):
        rs = rows(q(cur, """SELECT EventId, ClientTimestamp, Actor, Service, Action, Details, PrevHash, EntryHash,
                            EventTimestamp FROM dbo.AuditTrail ORDER BY EventId ASC"""))
        head = ["Seq", "Horodatage", "Acteur", "Service", "Action", "Details", "PrevHash", "Hash", "HorodatageServeur"]
        data = [[str(v) if v is not None else "" for v in r.values()] for r in rs]
        if fmt == "xlsx":
            return self._send(200, make_xlsx(head, data),
                              "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                              {"Content-Disposition": 'attachment; filename="Audit_Trail_MKT_Track.xlsx"'})
        out = io.StringIO()
        w = csv.writer(out, delimiter=";")
        w.writerow(head)
        w.writerows(data)
        self._send(200, out.getvalue().encode("utf-8-sig"), "text/csv; charset=utf-8",
                   {"Content-Disposition": 'attachment; filename="Audit_Trail_MKT_Track.csv"'})

    # ---- POST
    def do_POST(self):
        p = urlparse(self.path).path
        try:
            d = self.body()
        except Exception as e:
            return self.js(400, {"status": "error", "message": f"Requete invalide : {e}"})
        try:
            with DB_LOCK, get_sql_connection() as conn:
                cur = conn.cursor()
                try:
                    handler = {
                        "/api/auth/login": self.login, "/api/auth/verify-admin": self.verify_admin,
                        "/api/auth/change-password": self.change_password, "/api/presence": self.presence,
                        "/api/state": self.save_state, "/api/audit-append": self.append,
                        "/api/audit-reset": self.reset, "/api/audit-backup": self.backup,
                    }.get(p)
                    if not handler:
                        return self.js(404, {"error": "Route POST introuvable"})
                    handler(cur, d)
                    conn.commit()
                except Exception:
                    conn.rollback()
                    raise
        except Exception as exc:
            logging.error("POST %s: %s", p, exc)
            self.js(503, {"status": "ERROR", "code": "DB_UNAVAILABLE_ROLLBACK",
                          "message": "Transaction annulee (Rollback) : integrite des donnees preservee."})

    # ---- auth
    def _user(self, cur, login):
        r = q(cur, "SELECT Username, PasswordHash, RoleName, IsActive FROM dbo.Users WHERE LOWER(Username) = ?",
              (str(login).lower(),)).fetchone()
        return r

    def _fail(self, cur, login, why, service="SYSTÈME"):
        f = FAILS.setdefault(login.lower(), {"count": 0, "until": 0})
        f["count"] += 1
        locked = f["count"] >= MAX_ATTEMPTS
        if locked:
            f["until"], f["count"] = time.time() + LOCK_SECONDS, 0
        audit_append(cur, {"actor": login or "?", "service": service,
                           "action": "VERROUILLAGE_SECURITE" if locked else "ECHEC_CONNEXION",
                           "details": f"{why} (poste {self.ws()})"}, self.ws())
        return f, locked

    def login(self, cur, d):
        login, pw = str(d.get("login", "")).strip(), str(d.get("password", "")).lower()
        f = FAILS.get(login.lower())
        if f and f["until"] > time.time():
            return self.js(429, {"status": "locked", "remainingSeconds": int(f["until"] - time.time()) + 1})
        u = self._user(cur, login)
        # verification a cout constant meme si le compte n'existe pas (evite l'enumeration)
        ok = verify_hash(pw, u[1] if u else make_hash("0" * 64)) and u is not None and u[3]
        if not ok:
            f, locked = self._fail(cur, login, "Identifiant ou mot de passe incorrect")
            cur.connection.commit()
            return self.js(401, {"status": "error", "attempts": f["count"] or MAX_ATTEMPTS,
                                 "maxAttempts": MAX_ATTEMPTS, "locked": locked})
        FAILS.pop(login.lower(), None)
        role = u[2]
        cfg = load_cfg(cur)
        keys = list(cfg["profiles"].keys())
        pkey = keys[0] if role == "ADMIN" else role
        pname = cfg["profiles"].get(pkey, {}).get("name", pkey)
        tok, atok = secrets.token_urlsafe(32), (secrets.token_urlsafe(32) if role == "ADMIN" else "")
        SESSIONS[tok] = {"login": u[0], "role": role, "profileKey": pkey, "last": time.time(), "admin_token": atok}
        audit_append(cur, {"actor": u[0], "service": "ADMINISTRATION" if role == "ADMIN" else pname,
                           "action": "CONNEXION", "details": f"Ouverture de session (poste {self.ws()})"}, self.ws())
        st = build_state(cur)
        st["auditLog"] = audit_list(cur)
        self.js(200, {"status": "ok", "token": tok, "adminToken": atok, "login": u[0], "profileKey": pkey,
                      "profileName": pname, "isAdmin": role == "ADMIN", "state": st})

    def verify_admin(self, cur, d):
        s = self.session()
        if not s or s["role"] != "ADMIN":
            return self.deny(403, "Droit administrateur requis")
        u = self._user(cur, s["login"])
        if not verify_hash(str(d.get("password", "")), u[1]):
            self._fail(cur, s["login"], "Echec verification mot de passe administrateur", "ADMINISTRATION")
            return self.js(401, {"status": "error"})
        s["admin_token"] = secrets.token_urlsafe(32)
        self.js(200, {"status": "ok", "adminToken": s["admin_token"]})

    def change_password(self, cur, d):
        s = self.session()
        if not s or str(d.get("login", "")).lower() != s["login"].lower():
            return self.deny(403, "Operation refusee")
        old, new = str(d.get("oldPassword", "")).lower(), str(d.get("newPassword", "")).lower()
        u = self._user(cur, s["login"])
        if not verify_hash(old, u[1]):
            f, locked = self._fail(cur, s["login"], "Echec changement de mot de passe", str(d.get("service", "")))
            if locked:
                for t in [t for t, v in SESSIONS.items() if v is s]:
                    SESSIONS.pop(t, None)
            return self.js(401, {"status": "error", "forceLogout": locked, "auditLog": audit_list(cur)})
        if new == old or len(new) != 64:
            return self.js(400, {"status": "error", "message": "Nouveau mot de passe invalide"})
        q(cur, "UPDATE dbo.Users SET PasswordHash = ? WHERE UserId = (SELECT UserId FROM dbo.Users WHERE LOWER(Username) = ?)",
          (make_hash(new), s["login"].lower()))
        audit_append(cur, {"actor": s["login"], "service": str(d.get("service", "")),
                           "action": "CHANGEMENT_MOT_DE_PASSE", "details": "Mot de passe modifie par l'utilisateur"}, self.ws())
        self.js(200, {"status": "ok", "auditLog": audit_list(cur)})

    # ---- etat / presence / audit
    def presence(self, cur, d):
        s = self.session()
        sid = str(d.get("sessionId", ""))[:64] or self.client_address[0]
        now = time.time()
        if d.get("active") and s:
            PRESENCE[sid] = {"operator": s["login"], "service": str(d.get("service", ""))[:100], "last": now}
        else:
            PRESENCE.pop(sid, None)
        for k in [k for k, v in PRESENCE.items() if now - v["last"] > 20]:
            PRESENCE.pop(k)
        users = [{"operator": v["operator"], "service": v["service"]} for v in PRESENCE.values()]
        cnt = q(cur, "SELECT COUNT(*) FROM dbo.AuditTrail").fetchone()[0]
        self.js(200, {"connectedCount": len(users), "users": users, "version": get_version(cur), "auditCount": cnt})

    def save_state(self, cur, d):
        s = self.session()
        if not s:
            return self.deny()
        if self.is_admin(s) and isinstance(d.get("profilesDb"), dict):
            cfg = load_cfg(cur)
            incoming = d["profilesDb"]
            profiles = {}
            for k, p in incoming.items():
                ops = p.pop("operators", []) or []
                for op in ops:
                    ph = str(op.get("passHash", "")).lower()
                    exists = self._user(cur, op["login"])
                    if len(ph) == 64 and re.fullmatch(r"[0-9a-f]{64}", ph):
                        if exists:
                            q(cur, "UPDATE dbo.Users SET PasswordHash = ?, RoleName = ? WHERE LOWER(Username) = ?",
                              (make_hash(ph), k, op["login"].lower()))
                        else:
                            q(cur, "INSERT INTO dbo.Users (Username, PasswordHash, FullName, RoleName) VALUES (?,?,?,?)",
                              (op["login"], make_hash(ph), op["login"], k))
                    elif not exists:
                        raise ValueError("operateur sans mot de passe valide")
                p.pop("passHash", None)
                p.pop("login", None)
                profiles[k] = p
            cfg["profiles"] = profiles
            if isinstance(d.get("enterpriseConfig"), dict):
                cfg["enterprise"] = d["enterpriseConfig"]
            q(cur, "UPDATE dbo.AppConfig SET ConfigJson = ? WHERE Id = 1", (json.dumps(cfg, ensure_ascii=False),))
            audit_append(cur, {"actor": s["login"], "service": "ADMINISTRATION", "action": "MAJ_CONFIGURATION",
                               "details": "Profils/equipements/branding mis a jour"}, self.ws())
            bump_version(cur)
        st = build_state(cur)
        st["auditLog"] = audit_list(cur)
        self.js(200, st)

    def append(self, cur, d):
        if not self.session():
            return self.deny()
        entry = audit_append(cur, d, self.ws())
        self.js(200, {"status": "ok", "entry": entry, "auditLog": audit_list(cur)})

    def reset(self, cur, d):
        s = self.session()
        if not self.is_admin(s):
            return self.deny(403, "Droit administrateur requis")
        # Immuabilite ALCOA+ : aucune suppression physique. Rotation : le journal actif redemarre ici.
        last = audit_list(cur)
        audit_append(cur, {"actor": s["login"], "service": "ADMINISTRATION", "action": "CONTINUITE_ROTATION_AUDIT_TRAIL",
                           "details": f"Rotation du journal actif ({len(last)} evenement(s) conserves dans SQL Server)"}, self.ws())
        self.js(200, {"status": "ok", "auditLog": audit_list(cur)})

    def backup(self, cur, d):
        s = self.session()
        if not self.is_admin(s):
            return self.deny(403, "Droit administrateur requis")
        n = q(cur, "SELECT COUNT(*) FROM dbo.AuditTrail").fetchone()[0]
        audit_append(cur, {"actor": s["login"], "service": "ADMINISTRATION", "action": "SAUVEGARDE_AUDIT",
                           "details": f"{n} evenement(s) deja persistes dans SQL Server (aucun fichier disque cree)"}, self.ws())
        self.js(200, {"status": "ok", "count": n, "auditLog": audit_list(cur)})


# ----------------------------------------------------------------- xlsx en memoire (stdlib)
def make_xlsx(head, data):
    from xml.sax.saxutils import escape
    def cell(ref, v):
        return f'<c r="{ref}" t="inlineStr"><is><t>{escape(v)}</t></is></c>'
    def col(i):
        return chr(65 + i)
    allrows = [head] + data
    sheet = "".join(f'<row r="{r+1}">' + "".join(cell(f"{col(c)}{r+1}", v) for c, v in enumerate(row)) + "</row>"
                    for r, row in enumerate(allrows))
    files = {
        "[Content_Types].xml": '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>',
        "_rels/.rels": '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>',
        "xl/workbook.xml": '<?xml version="1.0" encoding="UTF-8"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="AuditTrail" sheetId="1" r:id="rId1"/></sheets></workbook>',
        "xl/_rels/workbook.xml.rels": '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>',
        "xl/worksheets/sheet1.xml": f'<?xml version="1.0" encoding="UTF-8"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>{sheet}</sheetData></worksheet>',
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for n, c in files.items():
            z.writestr(n, c)
    return buf.getvalue()


if __name__ == "__main__":
    with get_sql_connection() as c:
        ensure_bootstrap(c.cursor())
    logging.info("Demarrage MKT Track sur %s:%s", APP_HOST, APP_PORT)
    ThreadingHTTPServer((APP_HOST, APP_PORT), Handler).serve_forever()
