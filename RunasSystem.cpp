#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <shellapi.h>
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "shell32.lib")
using namespace std;

bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin;
}

void RelaunchAsAdmin() {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);

    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpVerb = L"runas";  // Request admin privileges
    sei.lpFile = exePath;
    sei.nShow = SW_SHOWNORMAL;

    if (!ShellExecuteExW(&sei)) {
        exit(EXIT_FAILURE); // Exit if user cancels UAC prompt
    }
    exit(EXIT_SUCCESS);  // Close current process
}

HANDLE getToken(DWORD pid) {
    string userProcess;
    HANDLE cToken = NULL;
    HANDLE ph = NULL;
    ph = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, true, pid);
    if (ph == NULL) {
        cToken = (HANDLE)NULL;
    }
    else {
        BOOL res = OpenProcessToken(ph, MAXIMUM_ALLOWED, &cToken);
        if (!res) {
            cToken = (HANDLE)NULL;
        }
        else {
        }
    }
    if (ph != NULL) {
        CloseHandle(ph);
    }
    return cToken;
}

BOOL createProcess(HANDLE token, LPCWSTR app) {
    // initialize variables
    HANDLE dToken = NULL;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    BOOL res = TRUE;
    ZeroMemory(&si, sizeof(STARTUPINFOW));
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    si.cb = sizeof(STARTUPINFOW);

    res = DuplicateTokenEx(token, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &dToken);
    res = CreateProcessWithTokenW(dToken, LOGON_WITH_PROFILE, app, NULL, 0, NULL, NULL, &si, &pi);
    return res;
}

std::string WStringToString(const std::wstring& wstr) {
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, NULL, 0, NULL, NULL);
    std::string result(sizeNeeded - 1, 0);  // Exclude null terminator
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &result[0], sizeNeeded, NULL, NULL);
    return result;
}

string GetProcessUserName(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) return "";
    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        CloseHandle(hProcess);
        return "";
    }
    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
    PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(dwSize);
    SID_NAME_USE SidType;
    wchar_t lpName[MAX_PATH];
    DWORD dwNameSize = MAX_PATH;
    wchar_t lpDomain[MAX_PATH];
    DWORD dwDomainSize = MAX_PATH;
    if (!LookupAccountSidW(NULL, pTokenUser->User.Sid, lpName, &dwNameSize, lpDomain, &dwDomainSize, &SidType)) {
        free(pTokenUser);
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return "";
    }
    wstring username(lpDomain);
    username += L"/";
    username += lpName;
    free(pTokenUser);
    CloseHandle(hToken);
    CloseHandle(hProcess);
    return WStringToString(username);
}


int main() {
    if (!IsRunningAsAdmin()) {
        RelaunchAsAdmin();
    }
    std::cout << "Running as Admin...." << std::endl;
    string username;
    HANDLE hProcSnap;
    PROCESSENTRY32 pe32;
    string app;
    string userProcess;
    int pid = 0;

    hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    pe32.dwSize = sizeof(PROCESSENTRY32);
    cout << "Enter the path of the application you want to run as SYSTEM: ";
    cin >> app;
    wstring wapp = wstring(app.begin(), app.end());
    LPCWSTR LPCapp = wapp.c_str();

    if (!Process32First(hProcSnap, &pe32)) {
        CloseHandle(hProcSnap);
        return 0;
    }

    while (Process32Next(hProcSnap, &pe32)) {
        pid = pe32.th32ProcessID;
        username = GetProcessUserName(pid);
        if (username == "" || username == "NT AUTHORITY/SYSTEM") {
            // get username of process
            bool success = false;
            HANDLE cToken = getToken(pid);
            if (cToken != NULL || cToken == 0) {
                success = createProcess(cToken, LPCapp);
                if (success) {
                    break;
                }
            }
        }
    }
    CloseHandle(hProcSnap);
    return 0;
}