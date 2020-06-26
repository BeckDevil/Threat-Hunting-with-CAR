# T1013: Port Monitors

A port monitor can be set through the API call to set a DLL to be loaded at startup. This DLL can be located in C:\Windows\System32 and will be loaded by the print spooler service, spoolsv.exe, on boot. The spoolsv.exe process also runs under SYSTEM level permissions. Alternatively, an arbitrary DLL can be loaded if permissions allow writing a fully-qualified pathname for that DLL to HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors.

The Registry key contains entries for the following:

* Local Port
* Standard TCP/IP Port
* USB Monitor
* WSD Port
Adversaries can use this technique to load malicious code at startup that will persist on system reboot and execute as SYSTEM.

## Detection
```
Sysmon Event ID = 12 or 13 or 14
registry_key_path = "*\\SYSTEM\CurrentControlSet\Control\Print\Monitors\\*"
```
