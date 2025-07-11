#pragma once

// Original function for SYSTEM privileges
int InvokeCreateSvcRpcMain(char* pExecCmd);

// New enhanced function with options
int InvokeCreateSvcRpcMainWithOptions(char* pExecCmd, BOOL bInteractive, BOOL bTrustedInstaller);