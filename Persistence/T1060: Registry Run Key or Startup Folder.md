# T1060: Registry Run Key or Startup Folder

Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key. Adding an entry to the "run keys" in the Registry or startup folder will cause the program referenced to be executed when a user logs in. These programs will be executed under the context of the user and will have the account's associated permissions level.

Placing a program within a startup folder will also cause that program to execute when a user logs in. There is a startup folder location for individual user accounts as well as a system-wide startup folder that will be checked regardless of which user account logs in. The startup folder path for the current user is ```C:\Users[Username]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup```. The startup folder path for all users is ```C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp```.

The following run keys are created by default on Windows systems: 
```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run 
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce 
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run 
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce
```

The ```HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx``` is also available but is not created by default on Windows Vista and newer. Registry run key entries can reference programs directly or list them as a dependency. For example, it is possible to load a DLL at logon using a "Depend" key with RunOnceEx: 
```reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d "C:\temp\evil[.]dll"```

The following Registry keys can be used to set startup folder items for persistence: 
```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders 
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders 
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
```

The following Registry keys can control automatic startup of services during boot: 
```
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce 
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce 
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices 
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices
```

Using policy settings to specify startup programs creates corresponding values in either of two Registry keys: 
```
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
```
The Winlogon key controls actions that occur when a user logs on to a computer running Windows 7. Most of these actions are under the control of the operating system, but you can also add custom actions here. The ```HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit``` and ```HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell``` subkeys can automatically launch programs.

Programs listed in the load value of the registry key ```HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows``` run when any user logs on.

By default, the multistring BootExecute value of the registry key ```HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager``` is set to ```autocheck autochk *```. This value causes Windows, at startup, to check the file-system integrity of the hard disks if the system has been shut down abnormally. Adversaries can add other programs or processes to this registry value which will automatically launch at boot.

Adversaries can use these configuration locations to execute malware, such as remote access tools, to maintain persistence through system reboots. Adversaries may also use Masquerading to make the Registry entries look as if they are associated with legitimate programs.

## Detection
```
Event 1
Sysmon Event ID = 12, 13, or 14
registry_key_path = ["*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*", "*\\Software\\Microsoft\\Windows\\CurrentVersion\Explorer\\*Shell Folders"]

Event 2
Sysmon Event ID = 12, 13, or 14
registry_key_path = "HKU\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Startup" AND 
registry_key_details != "*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
```
