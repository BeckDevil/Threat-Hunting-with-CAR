# T1076 Remote DeskTop Protocols 

Remote desktop is a common feature in operating systems. It allows a user to log into an interactive session with a system desktop graphical user interface on a remote system. Microsoft refers to its implementation of the Remote Desktop Protocol (RDP) as Remote Desktop Services (RDS). There are other implementations and third-party tools that provide graphical access Remote Services similar to RDS.

Adversaries may connect to a remote system over RDP/RDS to expand access if the service is enabled and allows access to accounts with known credentials. Adversaries will likely use Credential Access techniques to acquire credentials to use with RDP. Adversaries may also use RDP in conjunction with the Accessibility Features technique for Persistence.

Adversaries may also perform RDP session hijacking which involves stealing a legitimate user's remote session. Typically, a user is notified when someone else is trying to steal their session and prompted with a question. With System permissions and using Terminal Services Console, c:\windows\system32\tscon.exe [session number to be stolen], an adversary can hijack a session without the need for credentials or prompts to the user. This can be done remotely or locally and with active or disconnected sessions. It can also lead to Remote System Discovery and Privilege Escalation by stealing a Domain Admin or higher privileged account session. All of this can be done by using native Windows commands, but it has also been added as a feature in RedSnarf.

## Detection

```
Event 1
Sysmon Event ID = 1
Windows Security Event ID = 4688
process_name = "tscon.exe" OR process_name="mstsc.exe"

Event 2
Sysmon Event ID = 3
process_path = "*\\tscon.exe" OR process_name="mstsc.exe" OR dst_port=3389 
initiated = true

Event 3
Sysmon Event_id = 12 OR 13 OR 14
process_path = "C:\\Windows\\system32\\LogonUI.exe" OR
registry_key_path = "*\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\*"
```
