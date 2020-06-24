# T1146 Clear Command History

macOS and Linux both keep track of the commands users type in their terminal so that users can easily remember what they've done. These logs can be accessed in a few different ways. While logged in, this command history is tracked in a file pointed to by the environment variable ```HISTFILE```. When a user logs off a system, this information is flushed to a file in the user's home directory called ```~/.bash_history```. The benefit of this is that it allows users to go back to commands they've used before in different sessions. Since everything typed on the command-line is saved, passwords passed in on the command line are also saved. Adversaries can abuse this by searching these files for cleartext passwords. Additionally, adversaries can use a variety of methods to prevent their own commands from appear in these logs such as ```unset HISTFILE```, ```export HISTFILESIZE=0```, ```history -c```, ```rm ~/.bash_history```.

# Detection
```
Sysmon Event ID = 1
Windows Security Event ID = 4688
process_command_line = "*rm (Get-PSReadlineOption).HistorySavePath*" OR,
                       "*del (Get-PSReadlineOption).HistorySavePath*" OR,
                       "*Set-PSReadlineOption –HistorySaveStyle SaveNothing*" OR,
                       "*Remove-Item (Get-PSReadlineOption).HistorySavePath*"
```
