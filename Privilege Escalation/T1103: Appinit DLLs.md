# T1103: AppInit DLLs
Dynamic-link libraries (DLLs) that are specified in the AppInit_DLLs value in the Registry keys ```HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows``` or ```HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows are loaded by user32.dll``` into every process that loads user32.dll. In practice this is nearly every program, since user32.dll is a very common library. [1] Similar to Process Injection, these values can be abused to obtain persistence and privilege escalation by causing a malicious DLL to be loaded and run in the context of separate processes on the computer.

The AppInit DLL functionality is disabled in Windows 8 and later versions when secure boot is enabled. 

## Detection 
```
Sysmon Event ID = 12, 13, or 14
registry_key_path = "*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Appinit_Dlls\\*" OR
                    "*\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Appinit_Dlls\\*"
```
