# Android Bug Bounty — Static Code Review Manual

## Overview

This manual covers static analysis of Android APKs for bug bounty. Static review finds vulnerabilities without running the app: hardcoded secrets, insecure IPC, exported components, crypto flaws, and data leakage. Pair with dynamic testing for full coverage.

---

## Phase 0 — Setup

### Required Tools

```bash
# Core decompilation
sudo apt install apktool jadx dex2jar -y

# Secrets & patterns
pip install trufflehog
sudo apt install gitleaks

# Manifest & component analysis
pip install androguard

# Binary analysis
sudo apt install strings binwalk

# One-time: pull APK from device
adb shell pm list packages | grep target
adb shell pm path com.target.app
adb pull /data/app/com.target.app-1/base.apk ./target.apk

# Or download from APKCombo/APKPure (document source in report)
```

### Decompile Everything

```bash
# Unpack resources + smali
apktool d target.apk -o target_apktool/

# Java decompile (best for logic review)
jadx -d target_jadx/ target.apk

# Legacy jar path
d2j-dex2jar target.apk -o target.jar
# then open in JD-GUI or IntelliJ

# Native libs
find target_apktool/lib/ -name "*.so" | xargs strings > native_strings.txt
```

---

## Phase 1 — Manifest Audit (`AndroidManifest.xml`)

The manifest is the highest-ROI file. Read it first, every time.

### Extract & Read

```bash
cat target_apktool/AndroidManifest.xml
# or jadx output: target_jadx/resources/AndroidManifest.xml
```

### Exported Components Checklist

Every `exported="true"` (or no `exported` attribute + has `<intent-filter>`) is an attack surface.

```bash
# Find all exported components
grep -n 'exported="true"' target_apktool/AndroidManifest.xml

# Find intent-filter components (implicitly exported pre-API 31)
grep -n -A5 '<intent-filter>' target_apktool/AndroidManifest.xml
```

| Component | Risk if Exported | What to Test |
|---|---|---|
| `Activity` | UI hijacking, auth bypass | Can you launch it directly via `adb`? Does it skip auth? |
| `Service` | Privilege escalation, data theft | Can you bind/start and call methods? |
| `BroadcastReceiver` | Intent injection, spoofed broadcasts | Can you send a crafted broadcast? |
| `ContentProvider` | Unauthorized data access, SQL injection | Can you query/insert without permission? |

**PoC — launch exported activity without auth:**
```bash
adb shell am start -n com.target.app/.ui.AdminActivity
adb shell am start -n com.target.app/.ui.DeepLinkActivity -d "target://reset?token=x"
```

**PoC — query exported ContentProvider:**
```bash
adb shell content query --uri content://com.target.app.provider/users
adb shell content query --uri content://com.target.app.provider/users --where "1=1"
```

### Dangerous Permissions

```bash
grep -n 'uses-permission' target_apktool/AndroidManifest.xml
```

Flag these:
- `READ_CONTACTS`, `READ_SMS`, `READ_CALL_LOG` — PII collection
- `RECORD_AUDIO`, `CAMERA` — covert recording risk
- `READ_EXTERNAL_STORAGE` — world-readable data
- `WRITE_SETTINGS` — system tampering
- Custom permissions with `protectionLevel="normal"` — any app can hold them

### `android:debuggable` and `android:allowBackup`

```bash
grep -E 'debuggable|allowBackup|networkSecurityConfig' target_apktool/AndroidManifest.xml
```

- `debuggable="true"` in a production release = Critical (RCE via `adb jdwp`)
- `allowBackup="true"` = user data extractable via `adb backup` without root
- Missing `networkSecurityConfig` = cleartext traffic may be allowed

### `android:usesCleartextTraffic`

```bash
grep -rn 'cleartextTraffic\|usesCleartextTraffic' target_apktool/
```

`true` = HTTP allowed. Check `network_security_config.xml` for per-domain rules.

```bash
find target_apktool/ -name "network_security_config.xml" -exec cat {} \;
```

Flag: `<base-config cleartextTrafficPermitted="true">` with no domain restrictions.

---

## Phase 2 — Hardcoded Secrets & API Keys

### Automated Scan

```bash
# Trufflehog on decompiled output
trufflehog filesystem target_jadx/ --only-verified 2>/dev/null

# Gitleaks
gitleaks detect --source target_jadx/ --no-git -v

# Manual grep for common patterns
grep -rn --include="*.java" --include="*.kt" \
  -E '(api_key|apikey|secret|password|token|auth|bearer|private_key|aws_|AKIA|sk_live|pk_live)' \
  target_jadx/sources/ | grep -v '//.*test\|//.*TODO' | head -60
```

### High-Value Patterns

```bash
# AWS keys
grep -rn 'AKIA[0-9A-Z]{16}' target_jadx/

# Firebase
grep -rn 'AIza[0-9A-Za-z_-]{35}' target_jadx/
grep -rn 'firebaseio\.com\|firebase\.google\.com' target_jadx/

# Stripe
grep -rn 'sk_live_[0-9a-zA-Z]{24}' target_jadx/
grep -rn 'pk_live_[0-9a-zA-Z]{24}' target_jadx/

# JWT secrets
grep -rn 'HS256\|HS512\|JWT_SECRET\|jwtSecret' target_jadx/

# OAuth client secrets
grep -rn 'client_secret\s*=\s*["\x27][^"]+["\x27]' target_jadx/

# Private keys
grep -rn 'BEGIN.*PRIVATE KEY\|BEGIN RSA' target_jadx/

# Google Maps, Twilio, SendGrid, etc.
grep -rn 'AIza\|TWILIO\|SG\.\|sendgrid' target_jadx/ -i
```

### Firebase Misconfiguration

```bash
# Extract Firebase project URL
grep -rn 'firebaseio\.com\|firebase\.google\.com\|google-services' target_jadx/ target_apktool/res/

# Test unauthenticated read
curl -s "https://your-project-default-rtdb.firebaseio.com/.json?print=pretty" | head -30

# Test unauthenticated write (NEVER write real data — just check HTTP 200 vs 401)
curl -s -X PUT "https://your-project-default-rtdb.firebaseio.com/test.json" \
  -d '"bounty_test"' -w "\nHTTP: %{http_code}\n"
```

Firebase rules misconfiguration is a Critical finding.

---

## Phase 3 — Insecure Data Storage

### Shared Preferences

```bash
grep -rn 'getSharedPreferences\|SharedPreferences\|PreferenceManager' \
  target_jadx/sources/ | head -30

# Check MODE_WORLD_READABLE / MODE_WORLD_WRITEABLE
grep -rn 'MODE_WORLD' target_jadx/sources/
```

`MODE_WORLD_READABLE` = any app on device can read. Critical on older API levels.

### SQLite Databases

```bash
grep -rn 'SQLiteDatabase\|openOrCreateDatabase\|Room\b' target_jadx/sources/

# Check if DB is at a world-readable path
grep -rn 'getExternalFilesDir\|Environment.getExternal\|sdcard' target_jadx/sources/
```

**Dynamic follow-up:** pull DB after login, check if sensitive data is plaintext.

```bash
adb shell run-as com.target.app cp /data/data/com.target.app/databases/app.db /sdcard/
adb pull /sdcard/app.db .
sqlite3 app.db ".tables"
sqlite3 app.db "SELECT * FROM users LIMIT 5;"
```

### External Storage Leakage

```bash
grep -rn 'getExternalStorage\|EXTERNAL_STORAGE\|Environment\.getExternal\|/sdcard/' \
  target_jadx/sources/ | head -20

# Also check file paths in strings
grep -rn '"/sdcard\|/storage/emulated' target_jadx/
```

Sensitive data written to external storage = readable by any app with `READ_EXTERNAL_STORAGE`.

### Log Leakage

```bash
# Production builds should not log sensitive data
grep -rn 'Log\.d\|Log\.v\|Log\.i\|Log\.w\|Log\.e\|System\.out\.print' \
  target_jadx/sources/ | grep -i 'token\|pass\|secret\|auth\|key\|credit\|card' | head -20
```

### Clipboard Leakage

```bash
grep -rn 'ClipboardManager\|setPrimaryClip\|clipData' target_jadx/sources/
```

Password fields writing to clipboard = data leakage.

---

## Phase 4 — Insecure Network Communication

### SSL/TLS Misconfigurations

```bash
# TrustManager that accepts all certs (CRITICAL)
grep -rn -A15 'TrustManager\|X509TrustManager' target_jadx/sources/ | \
  grep -A10 'checkClientTrusted\|checkServerTrusted' | grep -E '\{\s*\}|\{\s*return'

# HostnameVerifier that accepts all (CRITICAL)
grep -rn 'ALLOW_ALL_HOSTNAME_VERIFIER\|verify.*return true\|HostnameVerifier' target_jadx/sources/

# SSLSocketFactory with no verification
grep -rn 'SSLContext\|TrustAllCerts\|NullTrustManager\|InsecureTrustManager' target_jadx/sources/
```

Finding an empty `checkServerTrusted` = accepts any cert = MitM = Critical.

**Canonical vulnerable pattern:**
```java
// VULNERABLE — report this
new X509TrustManager() {
    public void checkClientTrusted(...) {}
    public void checkServerTrusted(...) {}  // <-- empty = accepts anything
    public X509Certificate[] getAcceptedIssuers() { return null; }
}
```

### Certificate Pinning Bypass Research

```bash
# Identify pinning implementation (for dynamic bypass later)
grep -rn 'CertificatePinner\|TrustKit\|okhttp.*pin\|PublicKeyPinning\|sha256/' \
  target_jadx/sources/ | head -20

# OkHttp pinning
grep -rn 'CertificatePinner\.Builder\|add.*sha256' target_jadx/sources/

# Network Security Config pinning
find target_apktool/ -name "network_security_config.xml" -exec grep -l 'pin-set' {} \;
```

No pinning + custom TrustManager = network interception trivial.

### HTTP URLs (Cleartext)

```bash
grep -rn '"http://' target_jadx/sources/ | grep -v 'test\|debug\|localhost\|127\.0\.0\.1' | head -20
grep -rn "http://" target_apktool/res/ --include="*.xml" | head -20
```

---

## Phase 5 — Cryptography Flaws

### Weak Algorithms

```bash
# ECB mode (block cipher — no IV, leaks patterns)
grep -rn 'ECB\|AES/ECB\|DES\b\|DESede\|3DES\|RC4\|MD5\|SHA1\b\|SHA-1\b' target_jadx/sources/

# Static IV (kills semantic security)
grep -rn -B3 -A3 'IvParameterSpec\|iv.*=.*new byte\|getBytes.*iv' target_jadx/sources/ | \
  grep -B3 'static\|final\|hardcoded\|0x00'

# Small key sizes
grep -rn 'KeyPairGenerator\|KeyGenerator' target_jadx/sources/ -A5 | grep '512\|1024\b'
```

### Hardcoded Crypto Keys

```bash
grep -rn -E '(SecretKeySpec|PBEKeySpec|KeyStore)\s*\(' target_jadx/sources/ -A3 | \
  grep -E '"[A-Za-z0-9+/=]{8,}"'

# Static salt
grep -rn 'salt\s*=\s*["\x27]' target_jadx/sources/
grep -rn 'new PBEKeySpec.*[0-9]+\s*\)' target_jadx/sources/
```

### Random Number Generator

```bash
# java.util.Random is NOT cryptographically secure
grep -rn 'new Random()\|Math\.random()\|java\.util\.Random' target_jadx/sources/ | \
  grep -i 'token\|nonce\|session\|key\|secret\|otp'

# Correct: SecureRandom
grep -rn 'SecureRandom' target_jadx/sources/ | head -10
```

---

## Phase 6 — IPC / Deep Link Vulnerabilities

### Deep Link Parameter Injection

```bash
# Find deep link handlers
grep -rn 'getIntent\(\)\|getData\(\)\|getScheme\(\)\|Uri\.parse\|handleDeepLink' \
  target_jadx/sources/ | head -30

# Find registered schemes
grep -rn 'android:scheme\|android:host\|android:pathPrefix' target_apktool/AndroidManifest.xml
```

**Test: open deep link with injected params**
```bash
adb shell am start -a android.intent.action.VIEW \
  -d "target://payment?redirect=https://evil.com" com.target.app

# JavaScript deep link → WebView XSS
adb shell am start -a android.intent.action.VIEW \
  -d "target://open?url=javascript:alert(document.cookie)"
```

### WebView Vulnerabilities

```bash
# JavaScript enabled
grep -rn 'setJavaScriptEnabled(true)\|addJavascriptInterface\|evaluateJavascript' \
  target_jadx/sources/ -B5 -A5 | head -50

# File access
grep -rn 'setAllowFileAccess\|setAllowFileAccessFromFileURLs\|setAllowUniversalAccessFromFileURLs' \
  target_jadx/sources/

# Universal access + JS = arbitrary file read
```

**Vulnerable pattern:**
```java
webView.getSettings().setJavaScriptEnabled(true);
webView.getSettings().setAllowUniversalAccessFromFileURLs(true); // CRITICAL
webView.addJavascriptInterface(new JSBridge(), "Android");         // RCE risk
```

### Intent Redirection

```bash
# App receives intent, re-sends it (classic escalation)
grep -rn 'getIntent\(\).*startActivity\|getParcelableExtra.*Intent\|putExtra.*getIntent' \
  target_jadx/sources/ | head -20
```

---

## Phase 7 — Authentication & Authorization

### Broken Local Auth

```bash
# Biometric auth bypass patterns
grep -rn 'BiometricPrompt\|FingerprintManager\|KeyguardManager\|isDeviceSecure' \
  target_jadx/sources/ -A10 | grep -E 'onAuthenticationSucceeded|onAuthenticationFailed'

# PIN/pattern stored insecurely
grep -rn 'pin\|passcode\|pattern' target_jadx/sources/ -i | \
  grep -i 'sharedpref\|sqlite\|file\|plaintext' | head -20
```

Flag: auth result stored as boolean in SharedPreferences → trivially bypassed.

### JWT Handling

```bash
grep -rn 'jwt\|JsonWebToken\|jjwt\|jose4j' target_jadx/sources/ -i

# Check for "none" algorithm acceptance
grep -rn '\"none\"\|alg.*none\|parseWithoutValidation' target_jadx/sources/ -i

# Hardcoded signing secret
grep -rn 'signWith\|HMAC\|SecretKey' target_jadx/sources/ -A3 | grep '"'
```

### Token Storage

```bash
# Tokens should be in EncryptedSharedPreferences or Keystore, not plain prefs
grep -rn 'putString.*token\|putString.*auth\|putString.*session' target_jadx/sources/ | \
  grep -v 'Encrypted\|Keystore\|Secure' | head -20
```

---

## Phase 8 — Third-Party SDKs & Supply Chain

### Identify SDKs

```bash
# List all third-party packages
ls target_jadx/sources/ | grep -v 'com\.target\|android\|java\|kotlin' | head -30

# Common risky ones
grep -rn 'com\.facebook\|io\.branch\|com\.appsflyer\|com\.onesignal\|com\.mixpanel' \
  target_jadx/sources/ -l
```

### SDK API Keys Exposed

Each SDK init call often contains a hardcoded key:
```bash
grep -rn 'Branch\.initSession\|AppsFlyerLib\|Adjust\.onCreate\|MixpanelAPI\.getInstance' \
  target_jadx/sources/ -A3 | grep '"[A-Za-z0-9_-]{10,}"'
```

These keys aren't always in scope but demonstrate poor secret hygiene.

---

## Phase 9 — Native Library Analysis

```bash
# Find native libs
find target_apktool/lib/ -name "*.so"

# Extract strings from each
for lib in target_apktool/lib/**/*.so; do
  echo "=== $lib ==="
  strings "$lib" | grep -E '(https?://|api|key|secret|token|password|BEGIN)' | head -20
done

# Check for unsafe C functions
for lib in target_apktool/lib/**/*.so; do
  echo "=== $lib ==="
  strings "$lib" | grep -E '\b(strcpy|strcat|sprintf|gets|scanf|system|exec)\b'
done
```

---

## Phase 10 — Backup & Debug Artifacts

### Debug Builds in Production

```bash
# BuildConfig check
grep -rn 'BuildConfig\.DEBUG\|DEBUG.*=.*true\|BuildConfig\.BUILD_TYPE' target_jadx/sources/ | head -10

# Staging/dev endpoints left in
grep -rn 'staging\|dev\.\|test\.\|localhost\|10\.0\.\|192\.168\.' target_jadx/sources/ -i | \
  grep -E 'https?://' | head -20
```

### Backup Extraction (Dynamic)

```bash
# Only if allowBackup="true" in manifest
adb backup -f target_backup.ab -noapk com.target.app
dd if=target_backup.ab bs=24 skip=1 | zlib-flate -uncompress | tar xvf -
# Review extracted files for tokens, creds, cached PII
```

---

## Severity Quick Reference

| Finding | Typical Severity |
|---|---|
| `debuggable="true"` in prod + RCE via JDWP | Critical |
| SSL TrustManager accepts all certs | Critical |
| Firebase DB open read/write | Critical |
| Exported Activity bypasses auth | High |
| Hardcoded AWS/Stripe live key | High |
| `addJavascriptInterface` + untrusted URL | High |
| Intent redirection → privilege escalation | High |
| `allowBackup="true"` + sensitive data | Medium |
| Cleartext HTTP for sensitive endpoints | Medium |
| ECB mode encryption | Medium |
| Log leakage of tokens | Medium |
| Weak RNG for session tokens | Medium |
| `allowBackup="true"` no sensitive data | Low/Info |
| MD5/SHA-1 for non-security use | Info |

---

## Validation Gate (Before Reporting)

1. **Is it exploitable RIGHT NOW?** Not theoretical — can you demonstrate impact?
2. **Is the endpoint/code in scope?** Check program policy.
3. **Can an attacker reach it?** No physical device access without explicit scope.
4. **Is there a clear impact?** Data exposure, account takeover, RCE, etc.
5. **Are you sure it's not intentional?** E.g., debug builds in test environments OOS.
6. **Does it require chaining?** If yes, demonstrate the full chain.
7. **Can it be reproduced from a fresh install?** Document exact steps.

---

## Report PoC Template

```
## Steps to Reproduce

1. Download APK version X.Y.Z from [source]
2. Decompile: `apktool d target.apk -o target_apktool/`
3. Open `target_jadx/sources/com/target/app/ui/AdminActivity.java:42`
4. Observe: [vulnerable code snippet]
5. Trigger: `adb shell am start -n com.target.app/.ui.AdminActivity`
6. Result: Admin panel accessible without authentication

## Impact

An unauthenticated local attacker (or malicious app on same device) can...

## CVSS 3.1

AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N — Score: 8.4 (High)
```

---

## Tool Quick Reference

| Tool | Command |
|---|---|
| Decompile | `apktool d target.apk -o out/` |
| Java source | `jadx -d out_jadx/ target.apk` |
| Secret scan | `trufflehog filesystem out_jadx/ --only-verified` |
| Exported components | `grep 'exported="true"' AndroidManifest.xml` |
| Launch activity | `adb shell am start -n com.pkg/.ActivityName` |
| Query provider | `adb shell content query --uri content://com.pkg.provider/table` |
| Pull DB | `adb shell run-as com.pkg cp /data/data/com.pkg/databases/x.db /sdcard/` |
| Send broadcast | `adb shell am broadcast -a com.pkg.ACTION -n com.pkg/.Receiver` |
| Firebase test | `curl "https://project.firebaseio.com/.json"` |
