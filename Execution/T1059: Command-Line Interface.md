# T1059: Command-Line Interface
Command-line interfaces provide a way of interacting with computer systems and is a common feature across many types of operating system platforms. One example command-line interface on Windows systems is cmd, which can be used to perform a number of tasks including execution of other software. Command-line interfaces can be interacted with locally or remotely via a remote desktop application, reverse shell session, etc. Commands that are executed run with the current permission level of the command-line interface process unless the command includes process invocation that changes permissions context for that execution (e.g. Scheduled Task).

Adversaries may use command-line interfaces to interact with systems and execute other software during the course of an operation.

## Detection
```
Sysmon Event ID = 1
Windows Security Event ID = 4688
process_name = "cmd.exe"
```
