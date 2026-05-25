# Strings — Mobile Hacking Lab

**Tags:** `android` `deep-links` `native-libraries` `frida` `memory-scanning` `aes` `shared-preferences`

---

## Overview

Single APK challenge — *"find the flag, format MHL{...}"*. The app opens to a static screen with no interaction. The flag is never stored as plaintext — it is assembled at runtime inside a stripped native library and exists only briefly in heap memory.

---

## Recon

Decompiled with `jadx-gui`. Two activities matter:

- **`MainActivity`** — loads `libchallenge.so`, declares a JNI method `something()`, and calls `KLOW()` which writes today's date to SharedPreferences
- **`Activity2`** — the real target, hidden behind a multi-condition validation gate

---

## The Validation Gate

`Activity2.onCreate()` checks five things before calling `getflag()`:

```java
SharedPreferences sharedPrefs = getSharedPreferences("DAD4", 0);
String u_1 = sharedPrefs.getString("UUU0133", null);

// Gate 1: intent action must be VIEW
// Gate 2: SharedPrefs UUU0133 must equal today's date (dd/MM/yyyy)
// Gate 3: URI scheme must be "mhl"
// Gate 4: URI host must be "labs"
// Gate 5: URI last segment, base64-decoded, must equal AES plaintext

Uri uri = getIntent().getData();
if (uri != null && uri.getScheme().equals("mhl") && uri.getHost().equals("labs")) {
    String base64Value = uri.getLastPathSegment();
    byte[] decodedValue = Base64.decode(base64Value, 0);
    String ds = new String(decodedValue, Charsets.UTF_8);
    byte[] bytes = "your_secret_key_1234567890123456".getBytes(Charsets.UTF_8);
    String str = decrypt("AES/CBC/PKCS5Padding", "bqGrDKdQ8zo26HflRsGvVA==", new SecretKeySpec(bytes, "AES"));
    if (str.equals(ds)) {
        System.loadLibrary("flag");
        String s = getflag();
        Toast.makeText(getApplicationContext(), s, 1).show();
        return;
    }
}
finishAffinity();
finish();
System.exit(0);
```

If anything fails the app silently kills itself — no crash, no stack trace.

---

## Exploitation

### Step 1 — Decrypt the AES payload

All the crypto material is hardcoded in the source:

- Algorithm: `AES/CBC/PKCS5Padding`
- Ciphertext: `bqGrDKdQ8zo26HflRsGvVA==`
- Key: `your_secret_key_1234567890123456`
- IV: `Activity2Kt.fixedIV` (constant in code)

Decrypted with CyberChef → `mhl_secret_1337`

Base64-encode it → `bWhsX3NlY3JldF8xMzM3` — this is the URI's last path segment.

### Step 2 — Bypass the SharedPrefs gate

`KLOW()` in `MainActivity` normally writes today's date to SharedPrefs. Skip it entirely — SharedPreferences are just XML files on disk:

```bash
DATE=$(date +"%d/%m/%Y")
cat > /tmp/DAD4.xml << EOF
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="UUU0133">$DATE</string>
</map>
EOF

adb push /tmp/DAD4.xml /sdcard/DAD4.xml
adb shell run-as com.mobilehackinglab.challenge mkdir -p shared_prefs
adb shell run-as com.mobilehackinglab.challenge cp /sdcard/DAD4.xml shared_prefs/DAD4.xml
```

### Step 3 — Fire the deep link

```bash
adb shell am start -a android.intent.action.VIEW \
  -n com.mobilehackinglab.challenge/.Activity2 \
  -d "mhl://labs/bWhsX3NlY3JldF8xMzM3"
```

Toast shows **"Success"** — validation passed. But `getflag()` returns a placeholder string, not the flag.

### Step 4 — Static analysis of `libflag.so`

```bash
strings libflag.so | grep -i "MHL"        # empty
objdump -s -j .rodata libflag.so | less   # ~200 bytes of integer constants
nm -D libflag.so | grep -i flag           # JNI symbols only, everything else stripped
```

`.rodata` contains little-endian signed int32 constants — the flag is assembled from these at runtime, character by character. It never exists as plaintext in the binary.

### Step 5 — Runtime memory scan with MemPry

Once `getflag()` runs, the assembled flag exists briefly in heap memory. Catch it with Frida:

```bash
# Start Frida server
adb shell /data/local/tmp/frida-server &

# Attach MemPry before the app loads
frida -U -f com.mobilehackinglab.challenge -l mempry.js --no-pause
```

Fire the intent to load `libflag.so` and run `getflag()`, then in the Frida REPL:

```
[Frida ::]-> findFlag('MHL{')
```

MemPry scans all readable and heap memory regions, wrapping every access in try/catch to avoid access violations. First match is the flag.

---

## Why objection failed

Tried `objection`'s bulk memory scan first:

```
memory search "MHL{" --string
```

Result: `Error: access violation accessing 0x5efe400000` — hit an unmapped guard page and crashed instead of skipping it. MemPry handles this gracefully by catching exceptions per-region.

---

## Full Reproducible Steps

```bash
# Force-stop for a clean slate
adb shell am force-stop com.mobilehackinglab.challenge

# Pre-create SharedPrefs
DATE=$(date +"%d/%m/%Y")
cat > /tmp/DAD4.xml << EOF
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="UUU0133">$DATE</string>
</map>
EOF
adb push /tmp/DAD4.xml /sdcard/DAD4.xml
adb shell run-as com.mobilehackinglab.challenge mkdir -p shared_prefs
adb shell run-as com.mobilehackinglab.challenge cp /sdcard/DAD4.xml shared_prefs/DAD4.xml

# Attach Frida
frida -U -f com.mobilehackinglab.challenge -l mempry.js --no-pause &
sleep 2

# Trigger deep link
adb shell am start -a android.intent.action.VIEW \
  -n com.mobilehackinglab.challenge/.Activity2 \
  -d "mhl://labs/bWhsX3NlY3JldF8xMzM3"

# In Frida REPL:
# findFlag('MHL{')
```

---

## Key Takeaways

- **Read the manifest first.** The URI scheme is `mhl` — completely independent from the package name. Would have saved hours.
- **No stack trace = silent `finish()`.** Process death without `AndroidRuntime FATAL EXCEPTION` means the app killed itself. Look for the validation gate.
- **SharedPreferences are just XML.** Pre-create them with `run-as` instead of triggering whatever normally writes them.
- **`strings` fails on runtime-assembled flags.** When `.rodata` has integer constants instead of readable strings, switch to Frida immediately.
- **Use the most specific prefix possible.** `MHL{` beats `MHL` — the brace filters out coincidental matches.

---

## Tools

| Tool | Purpose |
|---|---|
| `jadx-gui` | Java decompilation |
| `aapt` | Manifest analysis |
| `objdump` / `strings` / `nm` | Static binary analysis |
| `adb` | Device control |
| `Frida` + `MemPry` | Runtime heap memory scanning |
| CyberChef | AES decryption |

---

## References

- [Frida — Memory.scan API](https://frida.re/docs/javascript-api/#memory)
- [Android am command reference](https://developer.android.com/tools/adb#am)
- [Android intent filters](https://developer.android.com/guide/components/intents-filters)

---

#android #ctf #mobile-hacking-lab #frida #intent-filters #shared-preferences #native-libraries #string-obfuscation #memory-scanning #aes #deep-links
