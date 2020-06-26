# T1093: Process Hollowing
Process hollowing occurs when a process is created in a suspended state then its memory is unmapped and replaced with malicious code. Similar to Process Injection, execution of the malicious code is masked under a legitimate process and may evade defenses and detection analysis.

## Detection
```
Event 1
Sysmon Event ID = 1
Windows Security Event ID = 4688
(process_name = "smss.exe" AND process_parent_name!="smss.exe") OR
(process_name = "csrss.exe" AND (process_parent_name != "smss.exe" AND process_parent_name != "svchost.exe")) OR
(process_name = "wininit.exe" AND process_parent_name != "smss.exe") OR 
(process_name = "winlogon.exe" AND process_parent_name != "smss.exe") OR
(process_name = "lsass.exe" AND parent_process_name != "wininit.exe") OR 
(process_name = "LogonUI.exe" AND (process_parent_name != "winlogon.exe" AND process_parent_name!="wininit.exe")) OR 
(process_name = "services.exe" AND process_parent_name != "wininit.exe") OR 
(process_name = "spoolsv.exe" AND process_parent_name != "services.exe") OR
(process_name = "taskhost.exe" AND (process_parent_name != "services.exe" AND process_parent_name != "svchost.exe")) OR
(process_name = "taskhostw.exe" AND (process_parent_name != "services.exe" AND process_parent_name != "svchost.exe")) OR 
(process_name = "userinit.exe" AND (process_parent_name != "dwm.exe" AND process_parent_name != "winlogon.exe"))

Event 2
Sysmon Event ID = 1
Windows Security Event ID = 4688
process_command_line = "" OR process_command_line = $$process_path$$

Event 3
Sysmon Event ID = 1
Windows Security Event ID = 4688
process_parent_name =["winword.exe" or "excel.exe" or "outlook.exe") AND
process_command_line = "C:\\Program Files\\Microsoft Office\\*-enc*"

```
