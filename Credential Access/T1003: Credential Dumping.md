# T1003 Credential Dumping

Credential dumping is the process of obtaining account login and password information, normally in the form of a hash or a clear text password, from the operating system and software. Credentials can then be used to perform Lateral Movement and access restricted information. Several of the tools mentioned in this technique may be used by both adversaries and professional security testers. Additional custom tools likely exist as well.

## Windows
### SAM (Security Accounts Manager)
The SAM is a database file that contains local accounts for the host, typically those found with the ‘net user’ command. To enumerate the SAM database, system level access is required. A number of tools can be used to retrieve the SAM file through in-memory techniques:
```
pwdumpx.exe
gsecdump
Mimikatz
secretsdump.py
```

Alternatively, the SAM can be extracted from the Registry with Reg:
```
reg save HKLM\sam sam
reg save HKLM\system system
```
Creddump7 can then be used to process the SAM database locally to retrieve hashes. Notes:Rid 500 account is the local, in-built administrator.Rid 501 is the guest account. User accounts start with a RID of 1,000+.

### Cached Credentials
The DCC2 (Domain Cached Credentials version 2) hash, used by Windows Vista and newer caches credentials when the domain controller is unavailable. The number of default cached credentials varies, and this number can be altered per system. This hash does not allow pass-the-hash style attacks. A number of tools can be used to retrieve the SAM file through in-memory techniques.
```
pwdumpx.exe
gsecdump
Mimikatz
```
Alternatively, reg.exe can be used to extract from the Registry and Creddump7 used to gather the credentials.

### Local Security Authority (LSA) Secrets
With SYSTEM access to a host, the LSA secrets often allows trivial access from a local account to domain-based account credentials. The Registry is used to store the LSA secrets. When services are run under the context of local or domain users, their passwords are stored in the Registry. If auto-logon is enabled, this information will be stored in the Registry as well. A number of tools can be used to retrieve the SAM file through in-memory techniques.
```
pwdumpx.exe
gsecdump
Mimikatz
secretsdump.py
```
Alternatively, reg.exe can be used to extract from the Registry and Creddump7 used to gather the credentials.

Notes:The passwords extracted by his mechanism are UTF-16 encoded, which means that they are returned in plaintext.Windows 10 adds protections for LSA Secrets described in Mitigation.

### NTDS from Domain Controller
Active Directory stores information about members of the domain including devices and users to verify credentials and define access rights. The Active Directory domain database is stored in the NTDS.dit file. By default the NTDS file will be located in %SystemRoot%\NTDS\Ntds.dit of a domain controller.

The following tools and techniques can be used to enumerate the NTDS file and the contents of the entire Active Directory hashes.
```
Volume Shadow Copy
secretsdump.py
Using the in-built Windows tool, ntdsutil.exe
Invoke-NinjaCopy
```
### Group Policy Preference (GPP) Files
Group Policy Preferences (GPP) are tools that allowed administrators to create domain policies with embedded credentials. These policies, amongst other things, allow administrators to set local accounts.

These group policies are stored in SYSVOL on a domain controller, this means that any domain user can view the SYSVOL share and decrypt the password (the AES private key was leaked on-line.

The following tools and scripts can be used to gather and decrypt the password file from Group Policy Preference XML files:
```
Metasploit’s post exploitation module: "post/windows/gather/credentials/gpp"
Get-GPPPassword
gpprefdecrypt.py
```
Notes:On the SYSVOL share, the following can be used to enumerate potential XML files.dir /s * .xml

### Plaintext Credentials
After a user logs on to a system, a variety of credentials are generated and stored in the Local Security Authority Subsystem Service (LSASS) process in memory. These credentials can be harvested by a administrative user or SYSTEM.

SSPI (Security Support Provider Interface) functions as a common interface to several Security Support Providers (SSPs): A Security Support Provider is a dynamic-link library (DLL) that makes one or more security packages available to applications.

The following SSPs can be used to access credentials:
```
Msv: Interactive logons, batch logons, and service logons are done through the MSV authentication package.
Wdigest: The Digest Authentication protocol is designed for use with Hypertext Transfer Protocol (HTTP) and Simple Authentication Security Layer (SASL) exchanges.
Kerberos: Preferred for mutual client-server domain authentication in Windows 2000 and later.
CredSSP:  Provides SSO and Network Level Authentication for Remote Desktop Services.
```
The following tools can be used to enumerate credentials:
```
Windows Credential Editor
Mimikatz
```
As well as in-memory techniques, the LSASS process memory can be dumped from the target host and analyzed on a local system.

For example, on the target host use procdump:
```procdump -ma lsass.exe lsass_dump```
Locally, mimikatz can be run:
```
sekurlsa::Minidump lsassdump.dmp
sekurlsa::logonPasswords
```

### DCSync
DCSync is a variation on credential dumping which can be used to acquire sensitive information from a domain controller. Rather than executing recognizable malicious code, the action works by abusing the domain controller's application programming interface (API) to simulate the replication process from a remote domain controller. Any members of the Administrators, Domain Admins, Enterprise Admin groups or computer accounts on the domain controller are able to run DCSync to pull password data from Active Directory, which may include current and historical hashes of potentially useful accounts such as KRBTGT and Administrators. The hashes can then in turn be used to create a Golden Ticket for use in Pass the Ticket or change an account's password as noted in Account Manipulation. DCSync functionality has been included in the "lsadump" module in Mimikatz. Lsadump also includes NetSync, which performs DCSync over a legacy replication protocol.

## Linux
### Proc filesystem
The /proc filesystem on Linux contains a great deal of information regarding the state of the running operating system. Processes running with root privileges can use this facility to scrape live memory of other running programs. If any of these programs store passwords in clear text or password hashes in memory, these values can then be harvested for either usage or brute force attacks, respectively. This functionality has been implemented in the MimiPenguin, an open source tool inspired by Mimikatz. The tool dumps process memory, then harvests passwords and hashes by looking for text strings and regex patterns for how given applications such as Gnome Keyring, sshd, and Apache use memory to store such authentication artifacts.
