#include "PrivilegeHelpers.h"

BOOL IsElevated() {
    BOOL fRet = FALSE;
    HANDLE hToken = NULL;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION Elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
            fRet = Elevation.TokenIsElevated;
        }
    }

    if (hToken) {
        CloseHandle(hToken);
    }

    return fRet;
}

BOOL IsSystem() {
    HANDLE hToken = NULL;
    PTOKEN_USER pTokenUser = NULL;
    PSID pSystemSid = NULL;
    BOOL bResult = FALSE;
    DWORD dwSize = 0;
    SID_IDENTIFIER_AUTHORITY siaNT = SECURITY_NT_AUTHORITY;

    // Open process token
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        printf("OpenProcessToken Error %u\n", GetLastError());
        goto Cleanup;
    }

    // Get required buffer size
    if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize)) {
        DWORD dwResult = GetLastError();
        if (dwResult != ERROR_INSUFFICIENT_BUFFER) {
            printf("GetTokenInformation Error %u\n", dwResult);
            goto Cleanup;
        }
    }

    // Allocate memory for token user information
    pTokenUser = (PTOKEN_USER)GlobalAlloc(GPTR, dwSize);
    if (pTokenUser == NULL) {
        printf("GlobalAlloc failed\n");
        goto Cleanup;
    }

    // Get token user information
    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
        printf("GetTokenInformation Error %u\n", GetLastError());
        goto Cleanup;
    }

    // Create SYSTEM SID
    if (!AllocateAndInitializeSid(&siaNT, 1, SECURITY_LOCAL_SYSTEM_RID,
        0, 0, 0, 0, 0, 0, 0, &pSystemSid)) {
        printf("AllocateAndInitializeSid failed (%u)\n", GetLastError());
        goto Cleanup;
    }

    // Compare SIDs
    bResult = EqualSid(pTokenUser->User.Sid, pSystemSid);

Cleanup:
    // Clean up resources
    if (hToken) {
        CloseHandle(hToken);
    }
    if (pTokenUser) {
        GlobalFree(pTokenUser);
    }
    if (pSystemSid) {
        FreeSid(pSystemSid);
    }

    return bResult;
}

// Function to get TrustedInstaller SID dynamically
PSID GetTrustedInstallerSID(BOOL* pFromMalloc) {
    PSID pTrustedInstallerSid = NULL;
    *pFromMalloc = FALSE;

    // Method 1: Try the well-known SID (works on most systems)
    LPCWSTR trustedInstallerSidString = L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
    if (ConvertStringSidToSidW(trustedInstallerSidString, &pTrustedInstallerSid)) {
        *pFromMalloc = FALSE; // Use LocalFree for this
        return pTrustedInstallerSid;
    }

    // Method 2: Only try process-based method if we're elevated
    if (IsElevated()) {
        printf("Elevated context detected, trying to get TrustedInstaller SID from process...\n");

        // Try to get it from the running process
        DWORD dwTrustedInstallerPID = FindTrustedInstallerPID();
        if (dwTrustedInstallerPID != 0) {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwTrustedInstallerPID);
            if (hProcess) {
                HANDLE hToken;
                if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
                    DWORD dwSize = 0;
                    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);

                    PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(dwSize);
                    if (pTokenUser) {
                        if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
                            // Copy the SID
                            DWORD sidLength = GetLengthSid(pTokenUser->User.Sid);
                            pTrustedInstallerSid = malloc(sidLength);
                            if (pTrustedInstallerSid) {
                                CopySid(sidLength, pTrustedInstallerSid, pTokenUser->User.Sid);
                                *pFromMalloc = TRUE; // Use free for this
                                printf("Successfully retrieved TrustedInstaller SID from process\n");
                            }
                        }
                        free(pTokenUser);
                    }
                    CloseHandle(hToken);
                }
                CloseHandle(hProcess);
            }
        }
    }
    else {
        printf("Non-elevated context, skipping process-based SID retrieval\n");
    }

    return pTrustedInstallerSid;
}

BOOL IsTrustedInstaller() {
    HANDLE hToken = NULL;
    PTOKEN_USER pTokenUser = NULL;
    PSID pTrustedInstallerSid = NULL;
    BOOL bResult = FALSE;
    BOOL bFromMalloc = FALSE;
    DWORD dwSize = 0;

    // Open current process/thread token
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken)) {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            printf("OpenToken Error %u\n", GetLastError());
            goto Cleanup;
        }
    }

    // Get required buffer size
    if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize)) {
        DWORD dwResult = GetLastError();
        if (dwResult != ERROR_INSUFFICIENT_BUFFER) {
            printf("GetTokenInformation Error %u\n", dwResult);
            goto Cleanup;
        }
    }

    // Allocate memory for token user information
    pTokenUser = (PTOKEN_USER)GlobalAlloc(GPTR, dwSize);
    if (pTokenUser == NULL) {
        printf("GlobalAlloc failed\n");
        goto Cleanup;
    }

    // Get token user information
    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
        printf("GetTokenInformation Error %u\n", GetLastError());
        goto Cleanup;
    }

    // Get TrustedInstaller SID dynamically
    pTrustedInstallerSid = GetTrustedInstallerSID(&bFromMalloc);
    if (pTrustedInstallerSid == NULL) {
        printf("Failed to get TrustedInstaller SID\n");
        goto Cleanup;
    }

    // Compare SIDs
    bResult = EqualSid(pTokenUser->User.Sid, pTrustedInstallerSid);

    if (bResult) {
        printf("Confirmed: Current token is TrustedInstaller!\n");
    }
    else {
        printf("Current token is NOT TrustedInstaller\n");

        // Debug: Print current SID
        LPWSTR currentSidString = NULL;
        if (ConvertSidToStringSidW(pTokenUser->User.Sid, &currentSidString)) {
            printf("Current SID: %S\n", currentSidString);
            LocalFree(currentSidString);
        }

        // Debug: Print TrustedInstaller SID
        LPWSTR tiSidString = NULL;
        if (ConvertSidToStringSidW(pTrustedInstallerSid, &tiSidString)) {
            printf("TrustedInstaller SID: %S\n", tiSidString);
            LocalFree(tiSidString);
        }
    }

Cleanup:
    // Clean up resources
    if (hToken) {
        CloseHandle(hToken);
    }
    if (pTokenUser) {
        GlobalFree(pTokenUser);
    }
    if (pTrustedInstallerSid) {
        if (bFromMalloc) {
            free(pTrustedInstallerSid);
        }
        else {
            LocalFree(pTrustedInstallerSid);
        }
    }

    return bResult;
}

DWORD FindTrustedInstallerPID() {
    HANDLE hSnapshot = NULL;
    PROCESSENTRY32 pe32;
    DWORD dwPID = 0;

    // Take snapshot of all processes
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Get first process
    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return 0;
    }

    // Look for TrustedInstaller process
    do {
        if (wcscmp(pe32.szExeFile, L"TrustedInstaller.exe") == 0) {
            dwPID = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return dwPID;
}

BOOL StartTrustedInstallerService() {
    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;
    BOOL result = FALSE;

    // Open service manager
    hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSCManager == NULL) {
        DWORD dwError = GetLastError();
        if (dwError == ERROR_ACCESS_DENIED) {
            printf("Access denied opening service manager. Need elevated privileges.\n");
        }
        else {
            printf("Failed to open service manager: %d\n", dwError);
        }
        return FALSE;
    }

    // Open TrustedInstaller service
    hService = OpenServiceA(hSCManager, "TrustedInstaller", SERVICE_ALL_ACCESS);
    if (hService == NULL) {
        DWORD dwError = GetLastError();
        if (dwError == ERROR_ACCESS_DENIED) {
            printf("Access denied opening TrustedInstaller service. Need elevated privileges.\n");
        }
        else {
            printf("Failed to open TrustedInstaller service: %d\n", dwError);
        }
        CloseServiceHandle(hSCManager);
        return FALSE;
    }

    // Start the service
    result = StartService(hService, 0, NULL);
    if (!result && GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) {
        printf("TrustedInstaller service is already running\n");
        result = TRUE;
    }
    else if (!result) {
        DWORD dwError = GetLastError();
        if (dwError == ERROR_ACCESS_DENIED) {
            printf("Access denied starting TrustedInstaller service. Need elevated privileges.\n");
        }
        else {
            printf("Failed to start TrustedInstaller service: %d\n", dwError);
        }
    }
    else {
        printf("TrustedInstaller service started successfully\n");
        // Wait a bit for the service to fully initialize
        Sleep(2000);
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);

    return result;
}

HANDLE GetTrustedInstallerToken() {
    HANDLE hToken = INVALID_HANDLE_VALUE;
    HANDLE hProcess = NULL;
    DWORD dwTrustedInstallerPID = 0;

    // Find TrustedInstaller process
    dwTrustedInstallerPID = FindTrustedInstallerPID();
    if (dwTrustedInstallerPID == 0) {
        printf("TrustedInstaller process not found. Service may not be running.\n");
        return INVALID_HANDLE_VALUE;
    }

    printf("Found TrustedInstaller PID: %d\n", dwTrustedInstallerPID);

    // Open TrustedInstaller process
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwTrustedInstallerPID);
    if (hProcess == NULL) {
        DWORD dwError = GetLastError();
        if (dwError == ERROR_ACCESS_DENIED) {
            printf("Access denied opening TrustedInstaller process. Need elevated privileges.\n");
        }
        else {
            printf("Failed to open TrustedInstaller process: %d\n", dwError);
        }
        return INVALID_HANDLE_VALUE;
    }

    // Get process token
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
        DWORD dwError = GetLastError();
        if (dwError == ERROR_ACCESS_DENIED) {
            printf("Access denied opening TrustedInstaller token. Need elevated privileges.\n");
        }
        else {
            printf("Failed to open TrustedInstaller token: %d\n", dwError);
        }
        CloseHandle(hProcess);
        return INVALID_HANDLE_VALUE;
    }

    CloseHandle(hProcess);

    // Duplicate token for impersonation
    HANDLE hDuplicatedToken = INVALID_HANDLE_VALUE;
    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &hDuplicatedToken)) {
        DWORD dwError = GetLastError();
        if (dwError == ERROR_ACCESS_DENIED) {
            printf("Access denied duplicating TrustedInstaller token. Need elevated privileges.\n");
        }
        else {
            printf("Failed to duplicate TrustedInstaller token: %d\n", dwError);
        }
        CloseHandle(hToken);
        return INVALID_HANDLE_VALUE;
    }

    CloseHandle(hToken);
    return hDuplicatedToken;
}

BOOL ImpersonateTrustedInstaller() {
    HANDLE hTrustedInstallerToken = GetTrustedInstallerToken();
    if (hTrustedInstallerToken == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    BOOL result = ImpersonateLoggedOnUser(hTrustedInstallerToken);
    CloseHandle(hTrustedInstallerToken);

    return result;
}

// Function to get current user session ID
DWORD GetCurrentUserSessionId() {
    DWORD sessionId = 0;
    HANDLE hToken = NULL;
    DWORD dwLength = 0;

    // Try thread token first (in case of impersonation)
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken)) {
        // Fall back to process token
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            printf("Failed to open token for session ID: %d\n", GetLastError());
            return 0;
        }
    }

    if (!GetTokenInformation(hToken, TokenSessionId, &sessionId, sizeof(DWORD), &dwLength)) {
        printf("Failed to get session ID: %d\n", GetLastError());
        sessionId = 0;
    }

    CloseHandle(hToken);
    return sessionId;
}

// Function to get user token from active session
HANDLE GetActiveUserSessionToken() {
    HANDLE hUserToken = NULL;
    DWORD sessionId = WTSGetActiveConsoleSessionId();

    if (sessionId == 0xFFFFFFFF) {
        printf("No active console session found\n");
        return NULL;
    }

    printf("Active console session ID: %d\n", sessionId);

    if (!WTSQueryUserToken(sessionId, &hUserToken)) {
        DWORD dwError = GetLastError();
        printf("WTSQueryUserToken failed for session %d: %d\n", sessionId, dwError);
        return NULL;
    }

    printf("Successfully obtained user token for session %d\n", sessionId);
    return hUserToken;
}

// Enhanced function to create process in user session
BOOL CreateProcessInUserSession(HANDLE hToken, char* cmdline, DWORD sessionId) {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    HANDLE hUserTokenDup = NULL;
    BOOL result = FALSE;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.lpDesktop = "winsta0\\default"; // Specify user desktop
    ZeroMemory(&pi, sizeof(pi));

    // Duplicate the token as primary token
    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hUserTokenDup)) {
        printf("Failed to duplicate token: %d\n", GetLastError());
        return FALSE;
    }

    // Set the session ID for the token
    if (!SetTokenInformation(hUserTokenDup, TokenSessionId, &sessionId, sizeof(DWORD))) {
        printf("Failed to set session ID %d: %d\n", sessionId, GetLastError());
        // Continue anyway, might still work
    }
    else {
        printf("Successfully set token session ID to %d\n", sessionId);
    }

    // Create process with the session-specific token
    result = CreateProcessAsUserA(
        hUserTokenDup,      // Token with correct session
        NULL,               // No module name
        cmdline,            // Command line
        NULL,               // Process handle not inheritable
        NULL,               // Thread handle not inheritable
        FALSE,              // Set handle inheritance to FALSE
        CREATE_NEW_CONSOLE, // Creation flags
        NULL,               // Use parent's environment block
        NULL,               // Use parent's starting directory
        &si,                // Pointer to STARTUPINFO structure
        &pi                 // Pointer to PROCESS_INFORMATION structure
    );

    if (result) {
        printf("Process created successfully in session %d\n", sessionId);
        printf("Process ID: %d\n", pi.dwProcessId);

        // Don't wait for interactive processes
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else {
        printf("Failed to create process in session %d: %d\n", sessionId, GetLastError());
    }

    CloseHandle(hUserTokenDup);
    return result;
}

BOOL CreateProcessAsTrustedInstallerWithToken(HANDLE hToken, char* cmdline) {
    DWORD currentSessionId = GetCurrentUserSessionId();

    printf("Current user session ID: %d\n", currentSessionId);

    if (currentSessionId == 0) {
        printf("Warning: Running in session 0, process may not have UI access\n");
    }

    // Try to create process in user session
    if (CreateProcessInUserSession(hToken, cmdline, currentSessionId)) {
        return TRUE;
    }

    // Fallback to standard CreateProcessAsUser
    printf("Falling back to standard CreateProcessAsUser...\n");

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.lpDesktop = "winsta0\\default";
    ZeroMemory(&pi, sizeof(pi));

    BOOL result = CreateProcessAsUserA(
        hToken,             // Token handle
        NULL,               // No module name
        cmdline,            // Command line
        NULL,               // Process handle not inheritable
        NULL,               // Thread handle not inheritable
        FALSE,              // Set handle inheritance to FALSE
        CREATE_NEW_CONSOLE, // Creation flags
        NULL,               // Use parent's environment block
        NULL,               // Use parent's starting directory
        &si,                // Pointer to STARTUPINFO structure
        &pi                 // Pointer to PROCESS_INFORMATION structure
    );

    if (result) {
        printf("Process created successfully with TrustedInstaller token\n");
        printf("Process ID: %d\n", pi.dwProcessId);

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else {
        printf("Failed to create process with TrustedInstaller token: %d\n", GetLastError());
    }

    return result;
}

// Enhanced function for TrustedInstaller with user session support
BOOL CreateProcessAsTrustedInstallerInUserSession(HANDLE hTIToken, char* cmdline) {
    DWORD currentSessionId = GetCurrentUserSessionId();
    HANDLE hUserToken = GetActiveUserSessionToken();

    printf("Attempting to create TrustedInstaller process in user session...\n");
    printf("Target session ID: %d\n", currentSessionId);

    // Method 1: Use TrustedInstaller token with session adjustment
    if (CreateProcessInUserSession(hTIToken, cmdline, currentSessionId)) {
        if (hUserToken) CloseHandle(hUserToken);
        return TRUE;
    }

    // Method 2: If we have a user session token, try to combine privileges
    if (hUserToken) {
        printf("Trying alternative method with user session token...\n");

        // Duplicate the user token
        HANDLE hUserTokenDup = NULL;
        if (DuplicateTokenEx(hUserToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hUserTokenDup)) {

            // Try to adjust privileges to match TrustedInstaller
            // This is a best-effort approach
            BOOL result = CreateProcessInUserSession(hUserTokenDup, cmdline, currentSessionId);
            CloseHandle(hUserTokenDup);
            CloseHandle(hUserToken);

            if (result) {
                printf("Successfully created process using user session method\n");
                return TRUE;
            }
        }
        CloseHandle(hUserToken);
    }

    // Method 3: Fallback to service with desktop interaction
    printf("Falling back to service with desktop interaction...\n");

    // Modify command to launch in user session via task scheduler
    char taskCmd[1024];
    _snprintf_s(taskCmd, sizeof(taskCmd) - 1,
        "schtasks /create /tn \"TITask_%d\" /tr \"%s\" /sc once /st 00:00 /ru SYSTEM /f && "
        "schtasks /run /tn \"TITask_%d\" && "
        "timeout /t 2 && "
        "schtasks /delete /tn \"TITask_%d\" /f",
        GetTickCount(), cmdline, GetTickCount(), GetTickCount());

    // Use the original RPC method with the task scheduler command
    return (system(taskCmd) == 0);
}

BOOL CreateProcessAsTrustedInstaller(char* cmdline) {
    // Don't use CreateProcessA as it inherits from parent process
    // Instead, we rely on the current thread impersonation
    printf("Executing command with current TrustedInstaller impersonation: %s\n", cmdline);

    // Use system() which will inherit the impersonation context
    int result = system(cmdline);

    if (result == 0) {
        printf("Command executed successfully with TrustedInstaller privileges\n");
        return TRUE;
    }
    else {
        printf("Command execution failed with exit code: %d\n", result);
        return FALSE;
    }
}