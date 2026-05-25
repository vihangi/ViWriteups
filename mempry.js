// ============================================================
// MemPry — Interactive memory exploration toolkit for Frida
// ------------------------------------------------------------
// Loads into Frida's REPL and gives you a clean command set
// for searching, reading, and dumping process memory live.
//
// Usage:
//   frida -U -f com.target.app -l mempry.js --no-pause
//
// Then at the [Frida ::] prompt:
//   help()              List every command
//   help('scan')        Detailed help for one command
//   findFlag('MHL{')    Quick CTF flag extraction
//   scanString('pwd')   Search for a literal string in memory
// ============================================================


// ============================================================
// HELPERS — internal, not exposed in help
// ============================================================

// Convert an ASCII string to Frida's space-separated hex format.
// "MHL{"  ->  "4D 48 4C 7B"
function _toPattern(s) {
    return s.split('').map(function (c) {
        return c.charCodeAt(0).toString(16)
                .padStart(2, '0').toUpperCase();
    }).join(' ');
}

function _cyan(s)   { return '\x1b[36m' + s + '\x1b[0m'; }
function _yellow(s) { return '\x1b[1;33m' + s + '\x1b[0m'; }
function _green(s)  { return '\x1b[1;32m' + s + '\x1b[0m'; }
function _dim(s)    { return '\x1b[2m' + s + '\x1b[0m'; }

function _header(title) {
    console.log('\n' + _yellow('=== ' + title + ' ==='));
}


// ============================================================
// HELP REGISTRY
// ------------------------------------------------------------
// Each command registers its summary, signature, options, and
// examples here. help() reads from this — single source of
// truth, no drift between code and docs.
// ============================================================

var HELP = {

    'scan': {
        summary: 'Scan all readable memory for a hex byte pattern',
        signature: 'scan(pattern, opts)',
        args: [
            ['pattern', 'string', 'Space-separated hex bytes, e.g. "4D 48 4C 7B"']
        ],
        opts: [
            ['max',       'number',  '10',   'Stop after N matches'],
            ['includeRW', 'boolean', 'true', 'Also scan rw- (heap); false = only constants']
        ],
        examples: [
            'scan("4D 48 4C 7B")',
            'scan("4D 48 4C 7B", { max: 1 })',
            'scan("66 6C 61 67 7B", { includeRW: false })'
        ]
    },

    'scanString': {
        summary: 'Same as scan(), but takes plain text instead of hex',
        signature: 'scanString(text, opts)',
        args: [
            ['text', 'string', 'Plain ASCII text to find']
        ],
        opts: [
            ['max',       'number',  '10',   'Stop after N matches'],
            ['includeRW', 'boolean', 'true', 'Also scan rw- (heap)']
        ],
        examples: [
            'scanString("password")',
            'scanString("MHL{", { max: 1 })',
            'scanString("BEGIN PRIVATE KEY")'
        ]
    },

    'scanModule': {
        summary: 'Scan ONE specific module — faster, avoids access violations',
        signature: 'scanModule(modName, pattern, opts)',
        args: [
            ['modName', 'string', 'Module file name, e.g. "libflag.so"'],
            ['pattern', 'string', 'Space-separated hex bytes']
        ],
        opts: [
            ['max', 'number', '10', 'Stop after N matches']
        ],
        examples: [
            'scanModule("libflag.so", "4D 48 4C 7B")',
            'scanModule("libssl.so", "42 45 47 49 4E", { max: 5 })'
        ]
    },

    'scanModuleString': {
        summary: 'Same as scanModule, but takes plain text',
        signature: 'scanModuleString(modName, text, opts)',
        args: [
            ['modName', 'string', 'Module file name'],
            ['text',    'string', 'Plain ASCII text']
        ],
        opts: [
            ['max', 'number', '10', 'Stop after N matches']
        ],
        examples: [
            'scanModuleString("libflag.so", "MHL{")',
            'scanModuleString("libnative.so", "secret_key_")'
        ]
    },

    'findFlag': {
        summary: 'CTF shortcut: scan + read C string at first match',
        signature: 'findFlag(prefix)',
        args: [
            ['prefix', 'string', 'Flag prefix, e.g. "MHL{", "CTF{", "flag{"']
        ],
        opts: [],
        examples: [
            'findFlag("MHL{")',
            'findFlag("CTF{")',
            'findFlag("flag{")'
        ]
    },

    'read': {
        summary: 'Read N bytes at an address as a UTF-8 string',
        signature: 'read(addr, len)',
        args: [
            ['addr', 'address', 'Memory address (hex like 0x... or decimal)'],
            ['len',  'number',  'Bytes to read (default 64)']
        ],
        opts: [],
        examples: [
            'read(0x7abcd02f80, 128)',
            'read("0x7abcd02f80", 64)'
        ]
    },

    'cstring': {
        summary: 'Read C string at address (stops at null terminator)',
        signature: 'cstring(addr)',
        args: [
            ['addr', 'address', 'Memory address']
        ],
        opts: [],
        examples: [
            'cstring(0x7abcd02f80)'
        ]
    },

    'hex': {
        summary: 'Hex dump N bytes at an address (hex + ASCII view)',
        signature: 'hex(addr, len)',
        args: [
            ['addr', 'address', 'Memory address'],
            ['len',  'number',  'Bytes to dump (default 64)']
        ],
        opts: [],
        examples: [
            'hex(0x7abcd02f80)',
            'hex(0x7abcd02f80, 256)'
        ]
    },

    'modules': {
        summary: 'List loaded modules, optionally filtered by regex',
        signature: 'modules(filter)',
        args: [
            ['filter', 'regex', 'Optional — show only matching modules']
        ],
        opts: [],
        examples: [
            'modules()',
            'modules(/lib/)',
            'modules(/flag|ssl/)'
        ]
    },

    'module': {
        summary: 'Show details for one specific module',
        signature: 'module(name)',
        args: [
            ['name', 'string', 'Module file name']
        ],
        opts: [],
        examples: [
            'module("libflag.so")',
            'module("libc.so")'
        ]
    },

    'regions': {
        summary: 'List memory regions filtered by permissions',
        signature: 'regions(perms)',
        args: [
            ['perms', 'string', 'Permission string: r/w/x/-, default "r--"']
        ],
        opts: [],
        examples: [
            'regions()         // read-only',
            'regions("rw-")    // heap',
            'regions("r-x")    // executable code',
            'regions("rwx")    // suspicious — JIT or exploit territory'
        ]
    },

    'dump': {
        summary: 'Save N bytes from address to a file on the device',
        signature: 'dump(addr, len, path)',
        args: [
            ['addr', 'address', 'Memory address to dump from'],
            ['len',  'number',  'Number of bytes'],
            ['path', 'string',  'Output path (default /sdcard/memdump.bin)']
        ],
        opts: [],
        examples: [
            'dump(0x7abcd02000, 4096)',
            'dump(0x7abcd02000, 4096, "/sdcard/region.bin")'
        ]
    },

    'classes': {
        summary: 'List loaded Java classes, optionally filtered',
        signature: 'classes(filter)',
        args: [
            ['filter', 'regex', 'Optional — show only matching class names']
        ],
        opts: [],
        examples: [
            'classes(/mobilehackinglab/)',
            'classes(/Activity/)',
            'classes(/Crypto/)'
        ]
    },

    'callMethod': {
        summary: 'Find a live Java instance and invoke a method on it',
        signature: 'callMethod(cls, method)',
        args: [
            ['cls',    'string', 'Fully-qualified class name'],
            ['method', 'string', 'Method name (no parens)']
        ],
        opts: [],
        examples: [
            'callMethod("com.mobilehackinglab.challenge.Activity2", "getflag")',
            'callMethod("com.example.app.Crypto", "getKey")'
        ]
    },

    'hookReturn': {
        summary: 'Print return value of a Java method whenever it runs',
        signature: 'hookReturn(cls, method)',
        args: [
            ['cls',    'string', 'Fully-qualified class name'],
            ['method', 'string', 'Method name']
        ],
        opts: [],
        examples: [
            'hookReturn("com.example.app.Activity2", "getflag")',
            'hookReturn("com.example.app.Auth", "checkPassword")'
        ]
    }
};


// ============================================================
// help() and help('command') — discoverable docs
// ============================================================
function help(cmd) {
    if (cmd === undefined) {
        // No argument: list every command grouped, with one-liner summaries
        _header('memrepl — interactive memory toolkit');
        console.log(_dim('Type help("command") for full options + examples'));
        console.log('');

        var groups = {
            'Scanning':   ['scan', 'scanString', 'scanModule', 'scanModuleString', 'findFlag'],
            'Reading':    ['read', 'cstring', 'hex'],
            'Memory map': ['modules', 'module', 'regions'],
            'Dumping':    ['dump'],
            'Java':       ['classes', 'callMethod', 'hookReturn']
        };

        Object.keys(groups).forEach(function (group) {
            console.log(_yellow(group));
            groups[group].forEach(function (name) {
                var entry = HELP[name];
                console.log('  ' + _cyan(name.padEnd(20)) + entry.summary);
            });
            console.log('');
        });

        console.log(_dim('Quick start:'));
        console.log('  help("scan")');
        console.log('  findFlag("MHL{")');
        console.log('  modules(/flag/)');
        return;
    }

    // With an argument: zoom in on one command
    var entry = HELP[cmd];
    if (entry === undefined) {
        console.log('[-] No such command: ' + cmd);
        console.log('[*] Available: ' + Object.keys(HELP).join(', '));
        return;
    }

    _header(cmd);
    console.log(entry.summary);
    console.log('');
    console.log(_yellow('Signature'));
    console.log('  ' + entry.signature);

    if (entry.args.length > 0) {
        console.log('');
        console.log(_yellow('Arguments'));
        entry.args.forEach(function (a) {
            console.log('  ' + _cyan(a[0].padEnd(12)) +
                        _dim('(' + a[1] + ')').padEnd(20) +
                        a[2]);
        });
    }

    if (entry.opts.length > 0) {
        console.log('');
        console.log(_yellow('Options (pass as { key: value })'));
        entry.opts.forEach(function (o) {
            console.log('  ' + _cyan(o[0].padEnd(12)) +
                        _dim('(' + o[1] + ')').padEnd(15) +
                        _dim('default: ' + o[2]).padEnd(22) +
                        o[3]);
        });
    }

    if (entry.examples.length > 0) {
        console.log('');
        console.log(_yellow('Examples'));
        entry.examples.forEach(function (e) {
            console.log('  ' + e);
        });
    }
}


// ============================================================
// COMMANDS
// ============================================================

function scan(pattern, opts) {
    opts = opts || {};
    var maxMatches = opts.max || 10;
    var includeRW = opts.includeRW !== false;

    _header('Scanning for: ' + pattern);

    var results = [];
    var matchCount = 0;

    var ranges = Process.enumerateRanges('r--');
    if (includeRW) {
        ranges = ranges.concat(Process.enumerateRanges('rw-'));
    }
    console.log('[*] Scanning ' + _cyan(ranges.length) + ' regions...');

    for (var i = 0; i < ranges.length && matchCount < maxMatches; i++) {
        try {
            var matches = Memory.scanSync(ranges[i].base, ranges[i].size, pattern);
            for (var j = 0; j < matches.length && matchCount < maxMatches; j++) {
                matchCount++;
                var preview = '';
                try {
                    preview = Memory.readCString(matches[j].address);
                    if (preview && preview.length > 80) {
                        preview = preview.substring(0, 80) + '...';
                    }
                } catch (e) { preview = '(unreadable)'; }

                console.log('[+] ' + _cyan('#' + matchCount) +
                            ' at ' + matches[j].address +
                            '  →  ' + JSON.stringify(preview));

                results.push({ address: matches[j].address, preview: preview });
            }
        } catch (e) { /* skip bad regions silently */ }
    }

    console.log('[*] ' + _cyan(matchCount) + ' matches' +
                (matchCount >= maxMatches ? _dim(' (capped — raise opts.max for more)') : ''));
    return results;
}

function scanString(text, opts) {
    return scan(_toPattern(text), opts);
}

function scanModule(modName, pattern, opts) {
    opts = opts || {};
    var maxMatches = opts.max || 10;

    var mod = Process.findModuleByName(modName);
    if (mod === null) {
        console.log('[-] Module not found: ' + modName);
        return [];
    }

    _header('Scanning ' + modName + ' for: ' + pattern);
    console.log('[*] ' + mod.base + ' (' + _cyan(mod.size) + ' bytes)');

    var results = [];
    try {
        var matches = Memory.scanSync(mod.base, mod.size, pattern);
        for (var i = 0; i < matches.length && i < maxMatches; i++) {
            var preview = '';
            try {
                preview = Memory.readCString(matches[i].address);
                if (preview && preview.length > 80) {
                    preview = preview.substring(0, 80) + '...';
                }
            } catch (e) { preview = '(unreadable)'; }
            console.log('[+] ' + _cyan('#' + (i + 1)) +
                        ' at ' + matches[i].address +
                        '  →  ' + JSON.stringify(preview));
            results.push({ address: matches[i].address, preview: preview });
        }
        console.log('[*] ' + _cyan(matches.length) + ' matches');
    } catch (e) {
        console.log('[!] Scan failed: ' + e);
    }
    return results;
}

function scanModuleString(modName, text, opts) {
    return scanModule(modName, _toPattern(text), opts);
}

function findFlag(prefix) {
    prefix = prefix || 'CTF{';
    _header('Hunting flag: ' + prefix);
    var results = scan(_toPattern(prefix), { max: 5 });
    if (results.length === 0) {
        console.log('[-] No matches. Library not loaded? Try later or different prefix.');
        return null;
    }
    console.log('\n' + _green('[+] Best candidate: ') + JSON.stringify(results[0].preview));
    return results[0].preview;
}

function read(addr, len) {
    len = len || 64;
    try {
        return Memory.readUtf8String(ptr(addr), len);
    } catch (e) {
        console.log('[!] Read failed: ' + e);
        return null;
    }
}

function cstring(addr) {
    try {
        return Memory.readCString(ptr(addr));
    } catch (e) {
        console.log('[!] Read failed: ' + e);
        return null;
    }
}

function hex(addr, len) {
    len = len || 64;
    try {
        console.log(hexdump(ptr(addr), { length: len, ansi: true }));
    } catch (e) {
        console.log('[!] Hexdump failed: ' + e);
    }
}

function modules(filter) {
    _header('Loaded modules');
    var mods = Process.enumerateModules();
    var shown = 0;
    mods.forEach(function (m) {
        if (filter && !filter.test(m.name)) return;
        console.log('  ' + m.base + '  ' +
                    String(m.size).padStart(10) + '  ' + m.name);
        shown++;
    });
    console.log('[*] ' + _cyan(shown) + ' / ' + mods.length + ' modules shown');
}

function module(name) {
    var m = Process.findModuleByName(name);
    if (m === null) { console.log('[-] Not found: ' + name); return null; }
    _header('Module: ' + m.name);
    console.log('  base:  ' + m.base);
    console.log('  size:  ' + m.size + ' (' + (m.size / 1024).toFixed(1) + ' KB)');
    console.log('  path:  ' + m.path);
    return m;
}

function regions(perms) {
    perms = perms || 'r--';
    var ranges = Process.enumerateRanges(perms);
    _header('Memory regions: ' + perms);
    console.log('[*] ' + _cyan(ranges.length) + ' regions');
    var totalSize = 0;
    ranges.forEach(function (r) { totalSize += r.size; });
    console.log('[*] Total size: ' + (totalSize / 1024 / 1024).toFixed(1) + ' MB');
}

function dump(addr, len, path) {
    path = path || '/sdcard/memdump.bin';
    try {
        var bytes = Memory.readByteArray(ptr(addr), len);
        var f = new File(path, 'wb');
        f.write(bytes);
        f.close();
        console.log('[+] Wrote ' + _cyan(len) + ' bytes to ' + path);
        console.log('    Pull with: adb pull ' + path);
    } catch (e) {
        console.log('[!] Dump failed: ' + e);
    }
}

function classes(filter) {
    Java.perform(function () {
        _header('Java classes');
        var count = 0;
        Java.enumerateLoadedClasses({
            onMatch: function (name) {
                if (filter && !filter.test(name)) return;
                console.log('  ' + name);
                count++;
            },
            onComplete: function () {
                console.log('[*] ' + _cyan(count) + ' classes shown');
            }
        });
    });
}

function callMethod(cls, method) {
    Java.perform(function () {
        _header('Calling ' + cls + '.' + method + '()');
        var found = false;
        Java.choose(cls, {
            onMatch: function (instance) {
                found = true;
                console.log('[+] Instance: ' + instance);
                try {
                    var result = instance[method]();
                    console.log('[+] Returned: ' + result);
                } catch (e) {
                    console.log('[!] Call failed: ' + e);
                }
            },
            onComplete: function () {
                if (!found) console.log('[-] No live instances of ' + cls);
            }
        });
    });
}

function hookReturn(cls, method) {
    Java.perform(function () {
        try {
            var Klass = Java.use(cls);
            Klass[method].overloads.forEach(function (overload) {
                overload.implementation = function () {
                    var ret = overload.apply(this, arguments);
                    console.log('[hook] ' + cls + '.' + method +
                                '() returned: ' + JSON.stringify(ret));
                    return ret;
                };
            });
            console.log('[+] Hook installed on ' + cls + '.' + method);
        } catch (e) {
            console.log('[!] Hook failed: ' + e);
        }
    });
}


// ============================================================
// BANNER
// ============================================================
console.log('\n' + _green('[MemPry] Loaded — type help() for commands, help("name") for one'));
