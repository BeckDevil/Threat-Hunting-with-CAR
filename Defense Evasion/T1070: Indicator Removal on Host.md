# T1070: Indicator Removal on Host

Adversaries may delete or alter generated artifacts on a host system, including logs and potentially captured files such as quarantined malware. Locations and format of logs will vary, but typical organic system logs are captured as Windows events or Linux/macOS files such as Bash History and /var/log/* .

Actions that interfere with eventing and other notifications that can be used to detect intrusion activity may compromise the integrity of security solutions, causing events to go unreported. They may also make forensic analysis and incident response more difficult due to lack of sufficient data to determine what occurred.

## Clear Windows Event Logs

Windows event logs are a record of a computer's alerts and notifications. Microsoft defines an event as "any significant occurrence in the system or in a program that requires users to be notified or an entry added to a log." There are three system-defined sources of Events: System, Application, and Security.

Adversaries performing actions related to account management, account logon and directory service access, etc. may choose to clear the events in order to hide their activities.

The event logs can be cleared with the following utility commands:
```
wevtutil cl system
wevtutil cl application
wevtutil cl security
```
Logs may also be cleared through other mechanisms, such as PowerShell.

## Detection
```
Sysmon Event ID = 1
Windows Security Event ID = 4688
process_name = "wevtutil.exe" OR
process_command_line = "*wevtutil* cl*"
```
