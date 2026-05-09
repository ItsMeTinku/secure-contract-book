# 🔐 Secure Contact Book v2

A production-grade encrypted contact manager — upgraded from a basic Tkinter desktop app to a full-stack web application with advanced security, a modern UI, and enterprise-ready features.

---

## What's New in v2

| Feature | v1 (Basic) | v2 (Advanced) |
|---|---|---|
| **UI** | Tkinter desktop | Modern web app (any browser) |
| **Auth** | SHA-256 + plain session | JWT tokens + PBKDF2-HMAC (260k iterations) |
| **Session** | 60s timer thread | JWT expiry + live countdown |
| **Contact fields** | Name, Phone only | + Email, Address, Company, Notes |
| **Organisation** | None | Tags, Favorites, Sorting |
| **Search** | Name/phone only | Multi-field (name, phone, email, company) |
| **Pagination** | None | Paginated list + Load More |
| **Import/Export** | TXT export only | CSV import + export |
| **Audit Log** | None | Full CRUD audit trail (last 500 events) |
| **Multi-user** | Single user | Admin can create/delete users with roles |
| **Rate Limiting** | None | In-memory rate limiter (login: 10/min) |
| **Input Validation** | None | Phone regex, email format, length limits |
| **Duplicate Check** | Name+Phone | Case-insensitive name+phone |
| **API** | Basic Flask | RESTful JSON API with JWT Bearer auth |

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run setup (creates key, admin account, databases)
python setup.py

# 3. Start the server
python app.py

# 4. Open in browser
# http://localhost:5000
```

Default credentials (if you skip setup): **admin / admin123**

---

## Architecture

```
secure_contact_book_v2/
├── app.py            # Flask backend — all API routes
├── crypto_util.py    # Encryption & password hashing utilities
├── setup.py          # First-run setup wizard
├── requirements.txt
├── key.key           # Fernet encryption key (auto-generated) ⚠ BACK UP
├── user_db.json      # User accounts (passwords PBKDF2-hashed)
├── contact_db.json   # Encrypted contact records
├── audit_log.json    # Audit trail (last 500 entries)
└── static/
    └── index.html    # Single-page frontend
```

---

## Security Model

### Password Hashing
- **Algorithm**: PBKDF2-HMAC-SHA256 with a random 32-byte salt
- **Iterations**: 260,000 (OWASP 2024 minimum recommendation)
- **Legacy**: Old SHA-256 hashes are accepted and auto-migrated on next login

### Contact Encryption
- **Algorithm**: Fernet (AES-128-CBC + HMAC-SHA256)
- **Scope**: All sensitive fields encrypted individually at rest: name, phone, email, address, company, notes
- **Key**: Stored in `key.key` — losing this file means losing all data

### Session / JWT
- **Type**: HS256 JWT, signed with a random secret generated at startup
- **Expiry**: 1 hour (configurable via `JWT_EXPIRY` in `app.py`)
- **Transport**: Bearer token in `Authorization` header — no cookies, no CSRF risk

### Rate Limiting
- Login endpoint: 10 attempts per 60 seconds per IP
- Backed by in-memory dict; swap for Redis in production

---

## API Reference

All endpoints (except `/api/login`) require:
```
Authorization: Bearer <token>
```

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/login` | Authenticate, get JWT |
| POST | `/api/logout` | Invalidate session (audit log) |
| POST | `/api/change-password` | Change own password |
| GET | `/api/contacts` | List contacts (query, sort, paginate, filter) |
| GET | `/api/contacts/:id` | Get single contact |
| POST | `/api/contacts` | Add contact |
| PUT | `/api/contacts/:id` | Update contact |
| DELETE | `/api/contacts/:id` | Delete contact |
| POST | `/api/contacts/:id/favorite` | Toggle favorite |
| GET | `/api/contacts/export/csv` | Export all contacts as CSV |
| POST | `/api/contacts/import/csv` | Import contacts from CSV |
| GET | `/api/audit` | Paginated audit log |
| GET | `/api/admin/users` | List users (admin only) |
| POST | `/api/admin/users` | Create user (admin only) |
| DELETE | `/api/admin/users/:username` | Delete user (admin only) |

### Query Parameters for `GET /api/contacts`
| Param | Example | Description |
|---|---|---|
| `q` | `q=john` | Full-text search |
| `tag` | `tag=work` | Filter by tag |
| `favorites` | `favorites=true` | Favorites only |
| `sort` | `sort=name` | Sort field: `name`, `created` |
| `order` | `order=desc` | `asc` or `desc` |
| `page` | `page=2` | Page number |
| `per_page` | `per_page=30` | Results per page (max 200) |

---

## Production Checklist

- [ ] Set `JWT_SECRET` environment variable instead of auto-generated
- [ ] Disable Flask debug mode (`debug=False` is already set)
- [ ] Serve with a production WSGI server (gunicorn, waitress)
- [ ] Put behind HTTPS (nginx/Caddy reverse proxy)
- [ ] Back up `key.key`, `user_db.json`, `contact_db.json` regularly
- [ ] Replace in-memory rate limiter with Redis for multi-process deployments
- [ ] Set `SESSION_COOKIE_SECURE = True` if adding cookie-based auth

---

## CSV Import Format

```csv
name,phone,email,address,company,notes,tags,favorite
Alice Smith,+44 7700 000001,alice@example.com,"London, UK",ACME Corp,VIP client,work|vip,true
Bob Jones,+1 555 000 0000,bob@example.com,,Freelance,,friend,false
```

- **tags**: pipe-separated (`work|vip|friend`)
- **favorite**: `true` or `false`
- All fields except `name` and `phone` are optional
