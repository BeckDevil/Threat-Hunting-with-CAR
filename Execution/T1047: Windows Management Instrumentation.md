# T1047: Windows Management Instrumentation

Windows Management Instrumentation (WMI) is a Windows administration feature that provides a uniform environment for local and remote access to Windows system components. It relies on the WMI service for local and remote access and the server message block (SMB) and Remote Procedure Call Service (RPCS) for remote access. RPCS operates over port 135.

An adversary can use WMI to interact with local and remote systems and use it as a means to perform many tactic functions, such as gathering information for Discovery and remote Execution of files as part of Lateral Movement.

## Detection
```
Event 1
Sysmon Event ID = 1
Windows Security Event ID = 4688
process_parent_path = "*\\wmiprvse.exe" OR 
process_name = "wmic.exe" OR 
process_command_line = "*wmic* "

Event 2
Sysmon Event ID = 3
process_name = "wmic.exe" OR
process_command_line = "*wmic* "

Event 3
Sysmon Event ID = 1
Windows Security Event ID = 4688
process_parent_path = "C:\\Windows\\System32\\svchost.exe" AND
process_path = "C:\\WINDOWS\\system32\\wbem\\scrcons.exe"
```
