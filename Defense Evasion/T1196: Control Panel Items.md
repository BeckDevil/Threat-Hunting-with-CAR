# T1196 Control Panel Items 

Windows Control Panel items are utilities that allow users to view and adjust computer settings. Control Panel items are registered executable (.exe) or Control Panel (.cpl) files, the latter are actually renamed dynamic-link library (.dll) files that export a CPlApplet function. Control Panel items can be executed directly from the command line, programmatically via an application programming interface (API) call, or by simply double-clicking the file.

## Detection
```
Event 1
Sysmon Event ID = 1
Windows Security Event ID = 4688
process_command_line = "*control* \/name*" OR "rundll32* shell32.dll, Control_RunDLL"

Event 2
Sysmon Event ID = 12 OR 13 OR 14
registry_key_path = "*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ControlPanel\\NameSpace*" OR 
                    "*\\Software\\Microsoft\\Windows\\CurrentVersion\\Controls Folder\\*\\Shellex\\PropertySheetHandlers\\*" OR
                    "*\\Software\\Microsoft\\Windows\\CurrentVersion\\Control Panel\\*"
```
