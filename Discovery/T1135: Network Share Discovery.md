# T1135: Network Share Discovery

Networks often contain shared network drives and folders that enable users to access file directories on various systems across a network.

In Windows, file sharing over a Windows network occurs over the SMB protocol. 
Net can be used to query a remote system for available shared drives using the net view \remotesystem command. It can also be used to query shared drives on the local system using net share.

Adversaries may look for folders and drives shared on remote systems as a means of identifying sources of information to gather as a precursor for Collection and to identify potential systems of interest for Lateral Movement.

On Mac, locally mounted shares can be viewed with the df -aH command.

## Sysmon
Sysmon Event1: create process Where process name contains "Net.exe" or command line includes "net view" or "net share commands"

## ecar
Event1- OPEN PROCESS Where process name contains "Net.exe" or command line includes "net view" or "net share commands"

Event2- MESSAGE FLOW Where process name contains "Net.exe" or command line includes "net view" or "net share commands"
