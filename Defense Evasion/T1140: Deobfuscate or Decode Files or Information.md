# T1140: Deobfuscate or Decode Files or Information

Adversaries may use Obfuscated Files or Information to hide artifacts of an intrusion from analysis. They may require separate mechanisms to decode or deobfuscate that information depending on how they intend to use it. Methods for doing that include built-in functionality of malware, Scripting, PowerShell, or by using utilities present on the system.

## Detection
```
Event 1
Sysmon Event ID = 1
Windows Security Event ID = 4688
process_name = "certutil.exe" AND
process_command_line = "*decode*"
```
