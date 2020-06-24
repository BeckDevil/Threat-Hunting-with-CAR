# T1223 Compiled HTML File

Compiled HTML files (.chm) are commonly distributed as part of the Microsoft HTML Help system. CHM files are compressed compilations of various content such as HTML documents, images, and scripting/web related programming languages such VBA, JScript, Java, and ActiveX. CHM content is displayed using underlying components of the Internet Explorer browser loaded by the HTML Help executable program (hh.exe).

## Detection
```
Sysmon Event ID = 1
Windows Security Event ID = 4688
process_name = "hh.exe"
```
