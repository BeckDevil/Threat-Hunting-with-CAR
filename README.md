# Threat-Hunting-with-CAR
The set of rules based on MITRE Cyber Analytics Repository's  data model. It provides the threat hunting rules for MITRE ATT&amp;CK TTPs using the events in ecar data format. The corresponding map to Sysmon or Windows Log events are provided when relevant.

## Events recorded in eCAR

Objects | Actions
------------ | -------------
THREAD | {REMOTE_CREATE, TERMINATE, CREATE}
FILE | {MODIFY, RENAME, WRITE, DELETE, READ, CREATE} 
FLOW | {START, MESSAGE, OPEN}
PROCESS | {OPEN, TERMINATE, CREATE} 
REGISTRY | {EDIT, ADD, REMOVE}
TASK | {MODIFY, START, DELETE, CREATE}
MODULE | {LOAD} 
SHELL | {COMMAND}
USER_SESSION | {GRANT, INTERACTIVE, UNLOCK, REMOTE, RDP, LOGOUT, LOGIN}
HOST | {START} 
SERVICE | {CREATE}
