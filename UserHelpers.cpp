#include <Windows.h>
#include <sddl.h>
#include <stdio.h>
#include <lm.h>
#include <tchar.h>
#pragma comment(lib, "Netapi32.lib")
#define MAX_NAME 256

BOOL IsMemberOfAdminGroup() {
    HANDLE hToken = NULL;
    PTOKEN_USER ptu = NULL;
    PSID pAdminGroupSID = NULL;
    LPLOCALGROUP_MEMBERS_INFO_1 pMembersInfo = NULL;
    DWORD dwLength;
    BOOL bResult = FALSE;

    // Open process token
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        printf("Error opening process token (%d)\n", GetLastError());
        goto Cleanup;
    }

    // Get token information size
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwLength);

    // Allocate memory for token user information
    ptu = (PTOKEN_USER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwLength);
    if (ptu == NULL) {
        printf("Memory allocation failed\n");
        goto Cleanup;
    }

    // Get actual token information
    if (!GetTokenInformation(hToken, TokenUser, (LPVOID)ptu, dwLength, &dwLength)) {
        printf("GetTokenInformation failed (%d)\n", GetLastError());
        goto Cleanup;
    }

    PSID pCurrentUserSID = ptu->User.Sid;

    // Convert admin group SID string to SID
    LPCWSTR adminGroupSidString = L"S-1-5-32-544";
    if (!ConvertStringSidToSidW(adminGroupSidString, &pAdminGroupSID)) {
        printf("Convert SID Error %u\n", GetLastError());
        goto Cleanup;
    }

    // Look up admin group name
    wchar_t lpName[MAX_NAME];
    wchar_t lpDomain[MAX_NAME];
    DWORD dwNameSize = MAX_NAME;
    DWORD dwDomainSize = MAX_NAME;
    SID_NAME_USE SidType;
    LPCWSTR adminGroupName = NULL;

    if (!LookupAccountSidW(NULL, pAdminGroupSID, lpName, &dwNameSize, lpDomain, &dwDomainSize, &SidType)) {
        DWORD dwResult = GetLastError();
        if (dwResult == ERROR_NONE_MAPPED) {
            // Use wide string copy for wide character array
            wcscpy_s(lpName, MAX_NAME, L"NONE_MAPPED");
        }
        else {
            printf("LookupAccountSid Error %u\n", GetLastError());
            goto Cleanup;
        }
    }

    adminGroupName = lpName;

    // Get members of admin group
    DWORD dwLevel = 1;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    NET_API_STATUS nStatus;

    nStatus = NetLocalGroupGetMembers(NULL, adminGroupName, dwLevel,
        (LPBYTE*)&pMembersInfo, MAX_PREFERRED_LENGTH,
        &dwEntriesRead, &dwTotalEntries, NULL);

    if (nStatus != NERR_Success) {
        printf("NetLocalGroupGetMembers Error %u\n", nStatus);
        goto Cleanup;
    }

    // Check if current user is in admin group
    for (DWORD i = 0; i < dwEntriesRead; i++) {
        if (EqualSid(pMembersInfo[i].lgrmi1_sid, pCurrentUserSID)) {
            bResult = TRUE;
            break;
        }
    }

Cleanup:
    // Clean up resources
    if (hToken) {
        CloseHandle(hToken);
    }
    if (ptu) {
        HeapFree(GetProcessHeap(), 0, (LPVOID)ptu);
    }
    if (pAdminGroupSID) {
        LocalFree(pAdminGroupSID);
    }
    if (pMembersInfo) {
        NetApiBufferFree(pMembersInfo);
    }

    return bResult;
}

BOOL HasPassword() {
    // Get current username
    wchar_t username[UNLEN + 1];
    DWORD size = UNLEN + 1;

    if (!GetUserNameW(username, &size)) {
        return true; // Assume password exists if we can't check
    }

    // Try to authenticate with empty password
    HANDLE hToken;
    BOOL result = LogonUserW(
        username,                    // Username
        L".",                       // Domain (local machine)
        L"",                        // Empty password
        LOGON32_LOGON_INTERACTIVE,  // Logon type
        LOGON32_PROVIDER_DEFAULT,   // Logon provider
        &hToken                     // Token handle
    );

    if (result) {
        // Empty password worked - user has no password
        CloseHandle(hToken);
        return false;
    }

    // Check the error code
    DWORD error = GetLastError();

    // If error is wrong password, then user has a password
    if (error == ERROR_LOGON_FAILURE) {
        return true; // User has a password
    }

    // If account restrictions prevent empty password login,
    // it might mean the user has no password but policy prevents it
    if (error == ERROR_ACCOUNT_RESTRICTION) {
        return false; // User likely has no password, but policy blocks empty passwords
    }

    // For other errors, assume password exists
    return true;
}