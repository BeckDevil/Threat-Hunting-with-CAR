# T1075 Pass the Hash 
Pass the hash (PtH) is a method of authenticating as a user without having access to the user's cleartext password. This method bypasses standard authentication steps that require a cleartext password, moving directly into the portion of the authentication that uses the password hash. In this technique, valid password hashes for the account being used are captured using a Credential Access technique. Captured hashes are used with PtH to authenticate as that user. Once authenticated, PtH may be used to perform actions on local or remote systems.

Windows 7 and higher with KB2871997 require valid domain user credentials or RID 500 administrator hashes.

## Detection
```
Windows Security Event ID = 4624 AND 
((Security_ID="NULL SID" OR Security_ID="S-1-0-0") AND
(Logon_Type="3") AND
(Source_Network_Address != "*::1*") AND
(Logon_Process="*NtLmSsp") AND 
(Package_Name__NTLM_only_="*NTLM V2") AND
(Key_Length="0") AND 
(user != "*ANONYMOUS LOGON" OR Account_Name != "*ANONYMOUS LOGON"))
```
