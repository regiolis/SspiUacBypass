#pragma once

#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include <sddl.h>
#include <wtsapi32.h>

#pragma comment(lib, "wtsapi32.lib")

// Basic privilege check functions
BOOL IsElevated();
BOOL IsSystem();
BOOL IsTrustedInstaller();

// TrustedInstaller specific functions
HANDLE GetTrustedInstallerToken();
DWORD FindTrustedInstallerPID();
BOOL StartTrustedInstallerService();
BOOL ImpersonateTrustedInstaller();
PSID GetTrustedInstallerSID(BOOL* pFromMalloc);

// Process creation functions
BOOL CreateProcessInSession(char* cmdline, DWORD sessionId);
BOOL CreateProcessWithTokenInSession(HANDLE hToken, char* cmdline, DWORD sessionId);

// Session management functions
DWORD GetCurrentUserSessionId();
HANDLE GetActiveUserSessionToken();