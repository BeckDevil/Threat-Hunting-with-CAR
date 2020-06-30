# T1131: Authentication Package

Windows Authentication Package DLLs are loaded by the Local Security Authority (LSA) process at system start. They provide support for multiple logon processes and multiple security protocols to the operating system.

Adversaries can use the autostart mechanism provided by LSA Authentication Packages for persistence by placing a reference to a binary in the Windows Registry location ```HKLM\SYSTEM\CurrentControlSet\Control\Lsa\``` with the key value of ```"Authentication Packages"=```. The binary will then be executed by the system when the authentication packages are loaded.

## Detection
```
Sysmon Event ID = 12, 13, or 14
registry_key_path = "\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\" AND 
NOT (process_path = "C:\\WINDOWS\\system32\\lsass.exe", "C:\\Windows\\system32\\svchost.exe", "C:\\Windows\\system32\\services.exe")
```
