# 1158: Hidden Files and Directories

To prevent normal users from accidentally changing special files on a system, most operating systems have the concept of a ‘hidden’ file. These files don’t show up when a user browses the file system with a GUI or when using normal commands on the command line. Users must explicitly ask to show the hidden files either via a series of Graphical User Interface (GUI) prompts or with command line switches (```dir /a``` for Windows and ```ls –a``` for Linux and macOS).

## Detection 
```
Event 1
Sysmon Event ID = 1
Windows Security Event ID = 4688
process_name = "attrib.exe" AND
process_command_line = ["*+h*", "*+s*"]

Event 2
Sysmon Event ID = 1
Windows Security Event ID = 4688
process_path = "*\\VolumeShadowCopy*\\*" OR "*\\VolumeShadowCopy*\\*"
```
