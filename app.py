"""
app.py — Advanced Secure Contact Book API (v2)
Features: JWT auth, multi-field contacts, tags, favorites, audit log,
          input validation, search, pagination, CSV export, admin panel.
"""

from flask import Flask, request, jsonify, send_from_directory
import json, os, uuid, time, re, csv, io
from datetime import datetime, timezone
from functools import wraps
import jwt as pyjwt

from crypto_util import (
    load_or_create_key, encrypt, decrypt,
    encrypt_contact, decrypt_contact,
    hash_password, check_password, generate_session_token
)

# ─── App Setup ────────────────────────────────────────────────────────────────

app = Flask(__name__, static_folder="static", static_url_path="")

JWT_SECRET = os.environ.get("JWT_SECRET", generate_session_token())
JWT_EXPIRY  = 3600  # 1 hour

# File paths
KEY_FILE      = "key.key"
USER_DB       = "user_db.json"
CONTACT_DB    = "contact_db.json"
AUDIT_LOG     = "audit_log.json"

# Rate-limit store (simple in-memory; swap for Redis in production)
_rate_store: dict = {}

# ─── Data Layer ───────────────────────────────────────────────────────────────

key = load_or_create_key(KEY_FILE)

def load_json(path: str, default):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default

def save_json(path: str, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def load_users() -> dict:
    return load_json(USER_DB, {})

def save_users(users: dict):
    save_json(USER_DB, users)

def load_contacts() -> list:
    return load_json(CONTACT_DB, [])

def save_contacts(contacts: list):
    save_json(CONTACT_DB, contacts)

def load_audit() -> list:
    return load_json(AUDIT_LOG, [])

def append_audit(username: str, action: str, detail: str = ""):
    log = load_audit()
    log.append({
        "id":        str(uuid.uuid4())[:8],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "username":  username,
        "action":    action,
        "detail":    detail,
    })
    # Keep last 500 entries
    save_json(AUDIT_LOG, log[-500:])

# ─── Initialisation ───────────────────────────────────────────────────────────

def init_db():
    """Create default admin if no users exist."""
    users = load_users()
    if not users:
        pw = hash_password("admin123")
        users["admin"] = {
            "username": "admin",
            "password": pw,
            "role":     "admin",
            "created":  datetime.now(timezone.utc).isoformat(),
        }
        save_users(users)
        print("[INIT] Default admin created — username: admin  password: admin123")

    # Migrate legacy contact_db (list of {name,phone} only)
    contacts = load_contacts()
    migrated = False
    for c in contacts:
        if "id" not in c:
            c["id"]         = str(uuid.uuid4())
            c["email"]      = c.get("email", "")
            c["address"]    = c.get("address", "")
            c["company"]    = c.get("company", "")
            c["notes"]      = c.get("notes", "")
            c["tags"]       = c.get("tags", [])
            c["favorite"]   = c.get("favorite", False)
            c["created"]    = c.get("created", datetime.now(timezone.utc).isoformat())
            c["updated"]    = c.get("updated", datetime.now(timezone.utc).isoformat())
            migrated = True
    if migrated:
        save_contacts(contacts)
        print("[INIT] Migrated legacy contacts to v2 schema")

# ─── Auth / JWT ───────────────────────────────────────────────────────────────

def create_token(username: str, role: str) -> str:
    payload = {
        "sub":  username,
        "role": role,
        "iat":  int(time.time()),
        "exp":  int(time.time()) + JWT_EXPIRY,
    }
    return pyjwt.encode(payload, JWT_SECRET, algorithm="HS256")

def decode_token(token: str) -> dict | None:
    try:
        return pyjwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except pyjwt.ExpiredSignatureError:
        return None
    except pyjwt.InvalidTokenError:
        return None

def require_auth(f):
    """Decorator: validates Bearer JWT token."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Missing token"}), 401
        payload = decode_token(auth[7:])
        if payload is None:
            return jsonify({"error": "Invalid or expired token"}), 401
        request.current_user = payload["sub"]
        request.current_role = payload.get("role", "user")
        return f(*args, **kwargs)
    return wrapper

def require_admin(f):
    @wraps(f)
    @require_auth
    def wrapper(*args, **kwargs):
        if request.current_role != "admin":
            return jsonify({"error": "Admin required"}), 403
        return f(*args, **kwargs)
    return wrapper

# ─── Rate Limiting (simple) ───────────────────────────────────────────────────

def rate_limit(key_fn, limit=10, window=60):
    """Decorator: simple in-memory rate limiter."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            rk   = key_fn()
            now  = time.time()
            hits = [t for t in _rate_store.get(rk, []) if now - t < window]
            if len(hits) >= limit:
                return jsonify({"error": "Too many requests"}), 429
            hits.append(now)
            _rate_store[rk] = hits
            return f(*args, **kwargs)
        return wrapper
    return decorator

# ─── Validation ───────────────────────────────────────────────────────────────

_PHONE_RE = re.compile(r"^[\d\s\+\-\(\)]{7,20}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def validate_contact(data: dict) -> list[str]:
    errors = []
    name  = (data.get("name") or "").strip()
    phone = (data.get("phone") or "").strip()
    email = (data.get("email") or "").strip()

    if not name:
        errors.append("Name is required")
    elif len(name) > 100:
        errors.append("Name must be ≤ 100 characters")

    if not phone:
        errors.append("Phone is required")
    elif not _PHONE_RE.match(phone):
        errors.append("Invalid phone number")

    if email and not _EMAIL_RE.match(email):
        errors.append("Invalid email address")

    tags = data.get("tags", [])
    if not isinstance(tags, list):
        errors.append("Tags must be a list")
    elif len(tags) > 10:
        errors.append("Max 10 tags per contact")

    return errors

# ─── Routes: Auth ─────────────────────────────────────────────────────────────

@app.route("/api/login", methods=["POST"])
@rate_limit(lambda: f"login:{request.remote_addr}", limit=10, window=60)
def login():
    data     = request.get_json(force=True) or {}
    username = (data.get("username") or "").strip()
    password =  data.get("password") or ""

    users = load_users()
    user  = users.get(username)

    if not user or not check_password(password, user["password"]):
        append_audit(username, "LOGIN_FAIL")
        return jsonify({"error": "Invalid credentials"}), 401

    token = create_token(username, user.get("role", "user"))
    append_audit(username, "LOGIN_OK")
    return jsonify({
        "token":    token,
        "username": username,
        "role":     user.get("role", "user"),
        "expires":  JWT_EXPIRY,
    })

@app.route("/api/logout", methods=["POST"])
@require_auth
def logout():
    append_audit(request.current_user, "LOGOUT")
    return jsonify({"status": "ok"})

@app.route("/api/change-password", methods=["POST"])
@require_auth
def change_password():
    data        = request.get_json(force=True) or {}
    old_pw      = data.get("old_password", "")
    new_pw      = data.get("new_password", "")

    if len(new_pw) < 8:
        return jsonify({"error": "Password must be ≥ 8 characters"}), 400

    users = load_users()
    user  = users.get(request.current_user)
    if not user or not check_password(old_pw, user["password"]):
        return jsonify({"error": "Old password incorrect"}), 401

    users[request.current_user]["password"] = hash_password(new_pw)
    save_users(users)
    append_audit(request.current_user, "PASSWORD_CHANGED")
    return jsonify({"status": "ok"})

# ─── Routes: Contacts ─────────────────────────────────────────────────────────

@app.route("/api/contacts", methods=["GET"])
@require_auth
def get_contacts():
    all_contacts = load_contacts()
    contacts     = [c for c in all_contacts if c.get("owner") == request.current_user]
    decrypted    = [decrypt_contact(c, key) for c in contacts]

    # Filter
    q           = (request.args.get("q") or "").lower()
    tag_filter  = request.args.get("tag", "")
    fav_only    = request.args.get("favorites") == "true"

    if q:
        decrypted = [
            c for c in decrypted
            if q in c.get("name","").lower()
            or q in c.get("phone","").lower()
            or q in c.get("email","").lower()
            or q in c.get("company","").lower()
        ]
    if tag_filter:
        decrypted = [c for c in decrypted if tag_filter in c.get("tags", [])]
    if fav_only:
        decrypted = [c for c in decrypted if c.get("favorite")]

    # Sort
    sort_by = request.args.get("sort", "name")
    reverse = request.args.get("order", "asc") == "desc"
    if sort_by == "name":
        decrypted.sort(key=lambda x: x.get("name","").lower(), reverse=reverse)
    elif sort_by == "created":
        decrypted.sort(key=lambda x: x.get("created",""), reverse=reverse)

    # Pagination
    page     = max(int(request.args.get("page", 1)), 1)
    per_page = min(int(request.args.get("per_page", 50)), 200)
    total    = len(decrypted)
    start    = (page - 1) * per_page
    paged    = decrypted[start: start + per_page]

    # Stats
    all_dec  = [decrypt_contact(c, key) for c in contacts]
    all_tags = set()
    for c in all_dec:
        all_tags.update(c.get("tags", []))

    return jsonify({
        "contacts":  paged,
        "total":     total,
        "page":      page,
        "per_page":  per_page,
        "tags":      sorted(all_tags),
        "stats": {
            "total":     len(contacts),
            "favorites": sum(1 for c in contacts if c.get("favorite")),
        }
    })

@app.route("/api/contacts/<contact_id>", methods=["GET"])
@require_auth
def get_contact(contact_id):
    contacts = load_contacts()
    for c in contacts:
        if c["id"] == contact_id and c.get("owner") == request.current_user:
            return jsonify(decrypt_contact(c, key))
    return jsonify({"error": "Not found"}), 404

@app.route("/api/contacts", methods=["POST"])
@require_auth
def add_contact():
    data   = request.get_json(force=True) or {}
    errors = validate_contact(data)
    if errors:
        return jsonify({"error": errors}), 400

    contacts = load_contacts()

    # Duplicate check
    for c in contacts:
        try:
            dec = decrypt_contact(c, key)
            if dec["name"].lower() == data["name"].strip().lower() \
               and dec["phone"] == data["phone"].strip() \
               and c.get("owner") == request.current_user:
                return jsonify({"error": "Duplicate contact"}), 409
        except Exception:
            continue

    new_contact = {
        "id":      str(uuid.uuid4()),
        "owner":   request.current_user,
        "name":    data.get("name","").strip(),
        "phone":   data.get("phone","").strip(),
        "email":   data.get("email","").strip(),
        "address": data.get("address","").strip(),
        "company": data.get("company","").strip(),
        "notes":   data.get("notes","").strip(),
        "tags":    [t.strip() for t in data.get("tags",[]) if t.strip()][:10],
        "favorite":False,
        "created": datetime.now(timezone.utc).isoformat(),
        "updated": datetime.now(timezone.utc).isoformat(),
    }

    enc = encrypt_contact(new_contact, key)
    contacts.append(enc)
    save_contacts(contacts)
    append_audit(request.current_user, "ADD_CONTACT", new_contact["name"])
    return jsonify({"status": "ok", "id": new_contact["id"]}), 201

@app.route("/api/contacts/<contact_id>", methods=["PUT"])
@require_auth
def update_contact(contact_id):
    data     = request.get_json(force=True) or {}
    errors   = validate_contact(data)
    if errors:
        return jsonify({"error": errors}), 400

    contacts = load_contacts()
    for i, c in enumerate(contacts):
        if c["id"] == contact_id and c.get("owner") == request.current_user:
            updated = {
                **c,
                "name":    encrypt(data.get("name","").strip(), key),
                "phone":   encrypt(data.get("phone","").strip(), key),
                "email":   encrypt(data.get("email","").strip(), key),
                "address": encrypt(data.get("address","").strip(), key),
                "company": encrypt(data.get("company","").strip(), key),
                "notes":   encrypt(data.get("notes","").strip(), key),
                "tags":    [t.strip() for t in data.get("tags",[]) if t.strip()][:10],
                "favorite":data.get("favorite", c.get("favorite", False)),
                "updated": datetime.now(timezone.utc).isoformat(),
            }
            contacts[i] = updated
            save_contacts(contacts)
            append_audit(request.current_user, "EDIT_CONTACT",
                         data.get("name",""))
            return jsonify({"status": "ok"})
    return jsonify({"error": "Not found"}), 404

@app.route("/api/contacts/<contact_id>/favorite", methods=["POST"])
@require_auth
def toggle_favorite(contact_id):
    contacts = load_contacts()
    for i, c in enumerate(contacts):
        if c["id"] == contact_id and c.get("owner") == request.current_user:
            contacts[i]["favorite"] = not c.get("favorite", False)
            save_contacts(contacts)
            return jsonify({"favorite": contacts[i]["favorite"]})
    return jsonify({"error": "Not found"}), 404

@app.route("/api/contacts/<contact_id>", methods=["DELETE"])
@require_auth
def delete_contact(contact_id):
    contacts = load_contacts()
    for i, c in enumerate(contacts):
        if c["id"] == contact_id and c.get("owner") == request.current_user:
            dec = decrypt_contact(c, key)
            contacts.pop(i)
            save_contacts(contacts)
            append_audit(request.current_user, "DELETE_CONTACT",
                         dec.get("name",""))
            return jsonify({"status": "ok"})
    return jsonify({"error": "Not found"}), 404

# ─── Routes: Export / Import ──────────────────────────────────────────────────

@app.route("/api/contacts/export/csv", methods=["GET"])
@require_auth
def export_csv():
    contacts  = load_contacts()
    decrypted = [decrypt_contact(c, key) for c in contacts
                  if c.get("owner") == request.current_user] 

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=[
        "name","phone","email","address","company","notes","tags","favorite","created"
    ])
    writer.writeheader()
    for c in decrypted:
        writer.writerow({
            **{k: c.get(k,"") for k in ["name","phone","email","address","company","notes","created"]},
            "tags":     "|".join(c.get("tags",[])),
            "favorite": c.get("favorite", False),
        })
    append_audit(request.current_user, "EXPORT_CSV")
    from flask import Response
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=contacts.csv"}
    )

@app.route("/api/contacts/import/csv", methods=["POST"])
@require_auth
def import_csv():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    f       = request.files["file"]
    stream  = io.StringIO(f.stream.read().decode("utf-8"))
    reader  = csv.DictReader(stream)
    added   = 0
    skipped = 0
    contacts = load_contacts()

    for row in reader:
        name  = (row.get("name") or "").strip()
        phone = (row.get("phone") or "").strip()
        if not name or not phone:
            skipped += 1
            continue

        # Check duplicate
        dup = False
        for c in contacts:
            try:
                dec = decrypt_contact(c, key)
                if dec["name"].lower() == name.lower() and dec["phone"] == phone and c.get("owner") == request.current_user:
                    dup = True
                    break
            except Exception:
                continue
        if dup:
            skipped += 1
            continue

        new_contact = {
            "id":      str(uuid.uuid4()),
            "owner": request.current_user,
            "name":    name,
            "phone":   phone,
            "email":   (row.get("email") or "").strip(),
            "address": (row.get("address") or "").strip(),
            "company": (row.get("company") or "").strip(),
            "notes":   (row.get("notes") or "").strip(),
            "tags":    [t.strip() for t in (row.get("tags","")).split("|") if t.strip()],
            "favorite":str(row.get("favorite","")).lower() == "true",
            "created": datetime.now(timezone.utc).isoformat(),
            "updated": datetime.now(timezone.utc).isoformat(),
        }
        contacts.append(encrypt_contact(new_contact, key))
        added += 1

    save_contacts(contacts)
    append_audit(request.current_user, "IMPORT_CSV",
                 f"added={added} skipped={skipped}")
    return jsonify({"added": added, "skipped": skipped})

# ─── Routes: Audit Log ────────────────────────────────────────────────────────

@app.route("/api/audit", methods=["GET"])
@require_auth
def get_audit():
    log   = load_audit()
    page  = max(int(request.args.get("page", 1)), 1)
    pp    = 50
    total = len(log)
    start = (page - 1) * pp
    return jsonify({
        "log":      list(reversed(log))[start: start + pp],
        "total":    total,
        "page":     page,
        "per_page": pp,
    })

# ─── Routes: Admin ────────────────────────────────────────────────────────────

@app.route("/api/admin/users", methods=["GET"])
@require_admin
def admin_users():
    users = load_users()
    safe  = [{
        "username": u["username"],
        "role":     u.get("role","user"),
        "created":  u.get("created",""),
    } for u in users.values()]
    return jsonify(safe)

@app.route("/api/admin/users", methods=["POST"])
@require_admin
def admin_create_user():
    data     = request.get_json(force=True) or {}
    username = (data.get("username") or "").strip()
    password =  data.get("password") or ""
    role     =  data.get("role","user")

    if not username or len(username) < 3:
        return jsonify({"error": "Username ≥ 3 characters"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password ≥ 8 characters"}), 400
    if role not in ("admin","user"):
        return jsonify({"error": "Invalid role"}), 400

    users = load_users()
    if username in users:
        return jsonify({"error": "Username taken"}), 409

    users[username] = {
        "username": username,
        "password": hash_password(password),
        "role":     role,
        "created":  datetime.now(timezone.utc).isoformat(),
    }
    save_users(users)
    append_audit(request.current_user, "CREATE_USER", username)
    return jsonify({"status": "ok"}), 201

@app.route("/api/admin/users/<username>", methods=["DELETE"])
@require_admin
def admin_delete_user(username):
    if username == request.current_user:
        return jsonify({"error": "Cannot delete yourself"}), 400
    users = load_users()
    if username not in users:
        return jsonify({"error": "Not found"}), 404
    del users[username]
    save_users(users)
    append_audit(request.current_user, "DELETE_USER", username)
    return jsonify({"status": "ok"})

# ─── Routes: Static Frontend ──────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory("static", "index.html")

# ─── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    print("\n+--------------------------------------+")
    print("|  Secure Contact Book v2              |")
    print("|  http://localhost:5000               |")
    print("+--------------------------------------+\n")
    app.run(debug=False, host="0.0.0.0", port=5000)
