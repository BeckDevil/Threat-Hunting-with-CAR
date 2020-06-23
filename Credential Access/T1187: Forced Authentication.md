# T1187: Forced Authentication

The Server Message Block (SMB) protocol is commonly used in Windows networks for authentication and communication between systems for access to resources and file sharing. When a Windows system attempts to connect to an SMB resource it will automatically attempt to authenticate and send credential information for the current user to the remote system. This behavior is typical in enterprise environments so that users do not need to enter credentials to access network resources. Web Distributed Authoring and Versioning (WebDAV) is typically used by Windows systems as a backup protocol when SMB is blocked or fails. WebDAV is an extension of HTTP and will typically operate over TCP ports 80 and 443.

Adversaries may take advantage of this behavior to gain access to user account hashes through forced SMB authentication. An adversary can send an attachment to a user through spearphishing that contains a resource link to an external server controlled by the adversary (i.e. Template Injection), or place a specially crafted file on navigation path for privileged accounts (e.g. .SCF file placed on desktop) or on a publicly accessible share to be accessed by victim(s). When the user's system accesses the untrusted resource it will attempt authentication and send information including the user's hashed credentials over SMB to the adversary controlled server. With access to the credential hash, an adversary can perform off-line Brute Force cracking to gain access to plaintext credentials.

## Detection
```
Sysmon Event ID = 11 
file_path = "*.lnk" OR "*.scf"
```
