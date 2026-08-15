# SIPExec Payload — Named Pipe Impersonation

Payload DLL for `tmb_sipexec_exec` (remote-exec mode). Loaded inside `wmiprvse.exe` via FinalPolicy hijack.

## What It Does

1. `SoftpubAuthenticode` export returns `S_OK` immediately (everything appears signed during hijack window)
2. Background thread creates a named pipe, waits for operator connection
3. Impersonates connecting client → gets admin token
4. Executes commands as the authenticated user, not NETWORK SERVICE

## Build

```bash
x86_64-w64-mingw32-gcc -shared -O2 -s -fno-ident \
  -o sipexec_payload_impersonate.dll \
  sipexec_payload_impersonate.c \
  -lkernel32 -ladvapi32
```

Or from the repo root:

```bash
make payload
```

## Pre-built

`sipexec_payload_impersonate.dll` is included pre-built (x64). The aggressor/axscript reads this file when no `--dll` is specified.

## Pipe Name

Derived from FNV-1a hash of the lowercase DLL basename: `\\.\pipe\wkssvc_<hash>`. The BOF computes the same hash to connect.
