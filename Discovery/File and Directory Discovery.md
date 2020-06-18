# Introduction

Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system. Adversaries may use the information from File and Directory Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

## Windows
Example utilities used to obtain this information are dir and tree. Custom tools may also be used to gather file and directory information and interact with the Windows API.

## Mac and Linux
In Mac and Linux, this kind of discovery is accomplished with the ls, find, and locate commands.

## Sysmon
Event ID 1: Process creation

## ecar
```
{
  'action': 'START'
  'object': 'PROCESS'
  'command_line': 'dir*' OR 'tree*'
}
```
