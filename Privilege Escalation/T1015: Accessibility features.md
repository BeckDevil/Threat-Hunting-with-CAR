# T1015: Accessibility Features
Windows contains accessibility features that may be launched with a key combination before a user has logged in (for example, when the user is on the Windows logon screen). An adversary can modify the way these programs are launched to get a command prompt or backdoor without logging in to the system.

Two common accessibility programs are C:\Windows\System32\sethc.exe, launched when the shift key is pressed five times and C:\Windows\System32\utilman.exe, launched when the Windows + U key combination is pressed. The sethc.exe program is often referred to as "sticky keys", and has been used by adversaries for unauthenticated access through a remote desktop login screen.

Depending on the version of Windows, an adversary may take advantage of these features in different ways because of code integrity enhancements. In newer versions of Windows, the replaced binary needs to be digitally signed for x64 systems, the binary must reside in %systemdir%\, and it must be protected by Windows File or Resource Protection (WFP/WRP). The debugger method was likely discovered as a potential workaround because it does not require the corresponding accessibility feature binary to be replaced. Examples for both methods:

For simple binary replacement on Windows XP and later as well as and Windows Server 2003/R2 and later, for example, the program (e.g., C:\Windows\System32\utilman.exe) may be replaced with "cmd.exe" (or another program that provides backdoor access). Subsequently, pressing the appropriate key combination at the login screen while sitting at the keyboard or when connected over Remote Desktop Protocol will cause the replaced file to be executed with SYSTEM privileges.

For the debugger method on Windows Vista and later as well as Windows Server 2008 and later, for example, a Registry key may be modified that configures "cmd.exe," or another program that provides backdoor access, as a "debugger" for the accessibility program (e.g., "utilman.exe"). After the Registry is modified, pressing the appropriate key combination at the login screen while at the keyboard or when connected with RDP will cause the "debugger" program to be executed with SYSTEM privileges.

Other accessibility features exist that may also be leveraged in a similar fashion:

* On-Screen Keyboard: C:\Windows\System32\osk.exe
* Magnifier: C:\Windows\System32\Magnify.exe
* Narrator: C:\Windows\System32\Narrator.exe
* Display Switcher: C:\Windows\System32\DisplaySwitch.exe
* App Switcher: C:\Windows\System32\AtBroker.exe

## Detection
```
Event 1
Sysmon Event ID = 1
process_parent_name = "winlogon.exe"
process_name = ["sethc.exe", "utilman.exe", "osk.exe", "magnify.exe", "displayswitch.exe", "narrator.exe", "atbroker.exe"]

Event 2
Sysmon Event ID = 12, 13, or 14
registry_keys = ["HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"]

```
