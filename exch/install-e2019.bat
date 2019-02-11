#--- run as administrator
runas /user:administrator powershell

# generate folder structure c:\ inst,temp, tmp, noscan
# set-location /Path c:\inst
# get-ChildItem -Name
# Get-Item -Path .\demo.ps1 | Selec-Object -Property Length

# vm-folder
Set-Variable -Name 'vmdir' -Value 'F:\vm'
# oldvm=
Set-Variable -Name 'oldvm' -Value 'osce14-01-w16'
# newvm= 
Set-Variable -Name 'newvm' -Value 'a1cent-01-w16'
# newvm= 
Set-Variable -Name 'newvm' -Value 'a1cent-01-w16'
# vmext =  @('vmx','vmxf','nvram')'vmdk'
$vmext =  @('vmx','vmxf')
#Write-Host $vmext[0],$vmext.length
# Path for Taskbar W2016
Taskbardir ='C:\Users\Administrator\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar'

Start Menu, "C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu"
Quick Launch, "C:\Users\Administrator\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch"
AppDAta, 

# Backup infos
$osusrdir = 'c:\users'
$bkpusrs =  @('dyone','manu','administrator')
$bkpdir = 'C:\tmp'

#Create Shortcuts in Task Menu
# shortcutfile looks like: <Shortcutname>, <Shortcutvalue>
$Shortcutfile='c:\temp\shortcutfile.txt'
$csv = import-csv $Shortcutfile 
$Shortcutpath='c:\temp'
$csv | Foreach-Object{
   $Shortcutname=$_.Shortcutname
   $Shortcutvalue=$_.Shortcutvalue
   New-Item -ItemType SymbolicLink -Path $Shortcutpath -Name $Shortcutname -Value $Shortcutvalue
   
   
# rename folder

$old= $vmdir,$oldvm -join '\'
$new= $vmdir,$newvm -join '\'
Rename-Item -Path $old -NewName $new
# rename files in folder
$new=$vmdir + '\' + $newvm +  '\*.*'
Get-ChildItem $dir | Rename-Item -NewName { $_.name -Replace $oldvm, $newvm }
for ($i=1; $i -lt $vmext.length; $i++){
   $new=$vmdir + '\' + $newvm + '\' + $newvm + '.' + $vmext[$i]
   (Get-Content $new) -replace $oldvm, $newvm | Set-Content $new
}

#Disable UAC - restart needed!
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value "0" 
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value "0" 
Restart-Computer

#CreateZipArchiveOffolder
# Check if backup folder exists
If (-Not (Test-path $bkpdir)) {New-Item -ItemType directory -Path $bkpdir}
#If(Test-path $bkpdir) {Remove-item $bkpdir}

for ($i=0; $i -lt $bkpusrs.length; $i++){
 
   $old = $osusrdir + '\' + $bkpusrs[$i]
   $new = $bkpdir + '\' + $bkpusrs[$i] + '.zip'
   # if zip exist, then delete item
   If(Test-path $new) {Remove-item $new}
   # generate zip file
   Add-Type -assembly 'system.io.compression.filesystem'
   If(Test-path $old) { [io.compression.zipfile]::CreatefromDirectory($old,$new)}   
   #If(Test-path $old) { [io.compression.zipfile]::CreatefromDirectory($old,$new)}   
      #Get-ChildItem $old -Recurse -Exclude $bkpexcl | Copy-Item -Destination {Join-Path $new $_.FullName.Substring($old.length)}
      #"\Program Files\7-Zip"\7z a -r -t7z %username%-backup.7z %userprofile%
}

}

Sysprep.exe -generalize  /reboot 

# Change information in 

runas /user:administrator cmd

powershell

# PowershellOperatiing system
$PSVersionTable.OS
# Powershellversion
$PSVersionTable.GitCommitId

$env:MyTestVariable = "My temporary test variable."

# Set Telemetry for Powershell Core 6.1
[Environment]::SetEnvironmentVariable("POWERSHELL_TELEMETRY_OPTOUT", "1", "Machine")
[Environment]::SetEnvironmentVariable("POWERSHELL_TELEMETRY_OPTOUT", "1", "User")
#LX:
sudo rm /opt/microsoft/powershell/6.0.0/DELETE_ME_TO_DISABLE_CONSOLEHOST_TELEMETRY
# MSFT: 
sudo pwsh
Remove-Item $PSHOME\DELETE_ME_TO_DISABLE_CONSOLEHOST_TELEMETRY

DELETE_ME_TO_DISABLE_CONSOLEHOST_TELEMETRY

# change time format
intl.cpl

# ipconfig - get the lans adapter

# rename the network adapter
rename-netadapter -name "Ethernet" Lan
rename-netadapter -name "Ethernet 2" Priv

# set Ip address 
get-netadapter -name Lan | new-netipaddress -ipaddress "192.168.1.36" -PrefixLength 22 -DefaultGateway 192.168.1.2
get-netadapter -name Priv | new-netipaddress -ipaddress "192.168.200.36" -PrefixLength 24 -DefaultGateway 192.168.200.2

#set dns 
Set-DnsClientServerAddress -InterfaceAlias "Lan" -ServerAddresses 172.21.3.36, 8.8.8.8
Set-DnsClientServerAddress -InterfaceAlias "Priv" -ServerAddresses 192.168.200.36, 8.8.8.8

# show dns server
get-DnsClientServerAddress -InterfaceAlias "Lan"
get-DnsClientServerAddress -InterfaceAlias "Priv"

#Check if IPv4 IP address is preferredc
#If the reply is IPv6 address, run following registry setting to just prefer ipv4 and reboot
New-ItemProperty “HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\” -Name “DisabledComponents” -Value 0x20 -PropertyType “DWord”
#If DisabledComponents exists, use the set cmdlet
Set-ItemProperty “HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\” -Name “DisabledComponents” -Value 0x20
#You need to reboot the computer in order for the changes to take effect
Restart-Computer

# set default keyboard language
# list of the available keyboard commands
Get-Command -Module International
Get-WinUserLanguageList
# list of acceptabel language codes: 
[system.globalization.cultureInfo]::GetCultures('InstalledWin32Cultures') | out-gridview

# Set-WinUserLanguageList -LanguageList de-DE
Set-WinUserLanguageList -LanguageList en-US, de-De -force

# Get current FQDN
[system.net.dns]::gethostbyname(($env:comuterName))

# is Computer member of a domain or workgroup, is Ture if part of a Domian, gives False if part of Workgroup
(Get-WmiObject -Class Win32_Computer.System).PartOfDomain
# is empty if part of a domain, otherwise gives workgroup name
(Get-WmiObject -Class Win32_Computer.System).Workgroup

# change hostname
#rename-computer -newname smex-01-w16
rename-computer -Computername $env:COMPUTERNAME -NewName 'smex-01-w16' -Restart



$env:COMPUTERNAME

#disable network card (priv)
disable-netadapter -name priv

# Enable Firewall rules:
enable-netfirewallrule -DisplayGroup "Remote Service Management"
enable-netfirewallrule -DisplayGroup "Remote Event Log Management"
enable-netfirewallrule -DisplayGroup "Remote Volume Management"

# disable firewall completely
netsh firewall set opmode disable
# Enable the Windows Firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True}
# Disable the Windows Firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False



# Enable Remote Desktop
(Get-WmiObject Win32_TerminalServiceSetting -Namespace root\cimv2\TerminalServices).SetAllowTsConnections(1,1) | Out-Null
(Get-WmiObject -Class "Win32_TSGeneralSetting" -Namespace root\cimv2\TerminalServices -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(0) | Out-Null
Get-NetFirewallRule -DisplayName "Remote Desktop*" | Set-NetFirewallRule -enabled true
# - or enable set remote desktop settings 
cscript C:\Windows\System32\SCregEdit.wsf /ar 0
# view remote desktop settings 
cscript C:\Windows\System32\SCregEdit.wsf /ar /v

# enable set remote desktop settings user authentication
cscript C:\Windows\System32\SCregEdit.wsf /cs 0
# remote access from older systems (i.e. xp) 
cscript C:\Windows\System32\SCregEdit.wsf /cs /v


# set automatic update to manual
# 1...manual, 3...enable DL only, 4...enalbe authomatic update
cscript C:\Windows\System32\SCregEdit.wsf /au 1


WinRM quickconfig
# 
# Disable IE Enhnaced Securtiy configuration
#
 cmd /c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
 New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 1 -Force
 Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 1 -Force
# 
#set trusted hosts
set-item wsman:\\localhost\client\trustedhosts -value "*" -force
# show trusted hosts
get-item wsman:\\localhost\client\trustedhosts
# show listeners
winrm enumerate winrm/config/listener


# start Disk Management
net start vds
# set disk managment to autostart
sc config vds start=auto

#disable server manager
Get-Item HKCU:\Software\Microsoft\ServerManager
Get-ItemProperty -Path HKCU:\Software\Microsoft\ServerManager -Name DoNotOpenServerManagerAtLogon | select DoNotOpenServerManagerAtLogon | Ft –AutoSize
New-ItemProperty -Path HKCU:\Software\Microsoft\ServerManager -Name DoNotOpenServerManagerAtLogon -PropertyType DWORD -Value “0x1” –Force



#
# Disable IE Enhnaced Securtiy configuration
#
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Value 0 -Force
Stop-Process -Name Explorer -Force
Write-Host "IE Enhanced Security Configuration (ESC) has been disabled." -ForegroundColor Green

#
# Enable IE Enhnaced Securtiy configuration
#
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Value 1 -Force
Stop-Process -Name Explorer -Force
Write-Host "IE Enhanced Security Configuration (ESC) has been disabled." -ForegroundColor Green

#
# Disable UserAccessControl configuration (via Server mgmt)
#
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 00000000 -Force
Write-Host "User Access Control (UAC) has been disabled." -ForegroundColor Green    

----
#
# Enable Quick Edit for cmd
#

# gpedit.msc
# Widows settings - Security Settings - Account Policy - Password Policy
# Pwd must meet complexity - disbble
# minimum pwd age - 0
# maximum pwd age - 0 (never expires)
# Widows settings - Security Settings - Local Policy - Security Options
# Domain Controller - Refuse machine account pwd changes - enabled
# Domain Member - Disable machine account pwd changes - enabled
# Interactive Logon - do not require CTL+ALT+DEL - enabled
# Shutdown - Allow system to be shut down without having to log on - enabled
# Administative Templates - System
# Display Shutdown Event Tracker - disabled
# HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Reliability\ShutdownReasonOndword)=0
ShutdownReasonUI(dword)=0
OR
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability
# 
gpupdate /force




# rename C drive from current name (default: Local Disk) to "System"
label C: System

# show Page File 
'
gwmi -query "select * from win32_PageFileSetting where name='c:\\pagefile.sys'" -EnableAllPrivileges


# Deaktivieren der Auslagerungsdateigröße für alle Laufwerke automatisch verwalten
$computersys = Get-WmiObject Win32_ComputerSystem -EnableAllPrivileges
$computersys.AutomaticManagedPagefile = $False
$computersys.Put()


# Löschen einer Pagefile
$pagefile = Get-WmiObject -Query "Select * From Win32_PageFileSetting Where Name='c:\pagefile.sys'"
$pagefile.Delete()


#see if administrator is active:
net user administrator| findstr /c:"active"
# activeate account if not active
net user administrator| /active:yes

# new admin user
net user admin1 testlab /fullname:"Admin1" /add
# add admin1 to the administrators group 
net localgroup Administrators /add admin1
net user admin1

net user manu testlab /fullname:"Manu" /add
# add admin1 to the administrators group 
net localgroup Administrators /add manu
net user manu


# Passwort admin anpassen
net user administrator *

#For Flash: Add roles, and then choose Add Roles, and add Remote Desktop Services and then RDSH, on the next page.


# change license key W2K16
slmgr.vbs -ipk NBH9Y-YG66G-68FJG-HGMG9-GJG34
# WIN2K12: C9HDK-8YNKG-DFV8C-WBC9F-9WY68
# Activate the server
slmgr.vbs -ato

#reboot computer
restart-computer

dism /online /enable-feature /featurename:NetFX3 /all /Source:d:\sources\sxs /LimitAccess


# 
# Install Active Directory services
# 
Import-Module ServerManager
Install-windowsfeature -name AD-Domain-Services –IncludeManagementTools

#
# Windows PowerShell script for AD DS Deployment
#
Import-Module ADDSDeployment
Install-ADDSForest `
-CreateDnsDelegation:$false `
-DatabasePath "C:\Windows\NTDS" `
-DomainMode "Win2012R2" `
-DomainName "tmmr-e16-01.tm" `
-DomainNetbiosName "TMMR-E16-01" `
-ForestMode "Win2012R2" `
-InstallDns:$true `
-LogPath "C:\Windows\NTDS" `
-NoRebootOnCompletion:$false `
-SysvolPath "C:\Windows\SYSVOL" `
-Force:$true


#
# Add AD Groups
#
NEW-ADGroup –name "Gr-Sales" –groupscope Global
NEW-ADGroup –name "Gr-Techie" –groupscope Global
NEW-ADGroup –name "Gr-All" –groupscope Global
NEW-ADGroup –name "Gr-SMEX-Admin" –groupscope Global

#
# Add AD Users inclusive password
#
$password = „trendmicro“ | ConvertTo-SecureString -AsPlainText -Force
New-ADUser -Name SMEX-adm -Surname SMEX-adm -AccountPassword $password -ChangePasswordAtLogon $False -Enabled $True
New-ADUser -Name chef -Surname chef -AccountPassword $password -ChangePasswordAtLogon $False -Enabled $True
New-ADUser -Name user01 -Surname User01 -Path "OU=Users,DC=TREMD,C=local" -AccountPassword $password -ChangePasswordAtLogon $False -Enabled $True
New-ADUser -Name user01 -Surname User01 -Path "OU=Testuser,DC=TREMD,,DC=local" -AccountPassword $password -ChangePasswordAtLogon $False -Enabled $True
New-ADUser -Name user02 -Surname User02 -Path "OU=Testuser,DC=TREMD,,DC=local" -AccountPassword $password -ChangePasswordAtLogon $False -Enabled $True
New-ADUser -Name user03 -Surname User03 -Path "OU=Testuser,DC=TREMD,,DC=local" -AccountPassword $password -ChangePasswordAtLogon $False -Enabled $True
New-ADUser -Name Alice -Surname Jones -Path "OU=User,DC=TREMD,DC=local" -AccountPassword $password -ChangePasswordAtLogon $False -Enabled $True
New-ADUser -Name Bob -Surname Smith -Path "OU=User,DC=TREMD,DC=local" -AccountPassword $password -ChangePasswordAtLogon $False -Enabled $True
New-ADUser -Name Tim -Surname Allen -Path "OU=User,DC=TREMD,DC=local" -AccountPassword $password -ChangePasswordAtLogon $False -Enabled $True
New-ADUser -Name Happy -Surname Day -Path "OU=User,DC=TREMD,DC=local" -AccountPassword $password -ChangePasswordAtLogon $False -Enabled $True
New-ADUser -Name John -Surname Smith -Path "OU=User,DC=TREMD,DC=local" -AccountPassword $password -ChangePasswordAtLogon $False -Enabled $True
New-ADUser -Name smex-service -Path "OU=User,DC=TREMD,DC=local" -AccountPassword $password -ChangePasswordAtLogon $False -Enabled $True
New-ADUser -Name tmcm-service -Path "OU=User,DC=TREMD,DC=local" -AccountPassword $password -ChangePasswordAtLogon $False -Enabled $True







#
# Add AD Users to AD Group 
#
Add-ADGroupMember -Identity Gr-All -Members User01,User02,User03,chef
Add-ADGroupMember -Identity Gr-Techie -Members User03,chef
Add-ADGroupMember -Identity Gr-Sales -Members User01,User02,chef


#
# List AD Users
#
Get-ADGroupMember "Gr-All"
Get-ADGroupMember "Gr-Techie"
Get-ADGroupMember "Gr-Sales"
Get-ADGroupMember "grsharew"
Get-ADGroupMember "grsharer"

dsac

smex-01-w16.tmmr-e16-01.tm administrator testlab


AP-AYHV-4SA6W-6YKL3-8VWEW-MT82Z-5BCYP

local sql server SQL Express 2012 inkl. Management tools
	DB Engine: NT AUTHORITY\SYSTEM on DC!
	sa  sql-srv-svc TrendMicr0 Passwortcomplexity!!!!!
	tmcm db: vpm (std)
	Instance: TMCM
sa TrendMicr0
	SQL Browser automatic
	Change the SQL Server connection to enable TCP and named pipes

Masteradmin trendmicro

# Windows defender - disable automatic sample submissionr
# win+1, update & security, disable: cloud based protection and automatic sample submission
#	add following exculustion: c:\admin, c:\noscan, c:\inst
Via Registry: (Winr / regedit - 
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\SubmitSampleConsent(dword) = 2
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\SpynetReporting(dword) = 0
#disable windows defender commpletely: 
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware(dwoard) = 1
#configureing telemetry
# Settings / Privacy / Feedback & diagnostics/ Win should ask for my feedback: never, diangstics: security
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection\AllowTelemetry(dword)=0

# copy the output of a command so it can be pasted in another application (via clipboard)
application.exe | clip

# Create a new Share 
New-SmbShare -Name Share -Path  C:\Sgare -FullAccess  'trend.local\grsharew'   -ReadAccess 'trend.local\grsharer'  -Verbose 

  -ReadAccess 'prox-pc\testuser'  -Verbose
# disable hibernate
powercfg -h off

list all installed programs:
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table –AutoSize

# mount exchange installation
# go on cdrom
.\setup /Preparead /IAcceptExchangeServerLicenseTerms /OrganizationName:Tmmr-e16-01
.\setup /Preparedomain /IAcceptExchangeServerLicenseTerms

# after installation - verify exchange server version 
Get-ExchangeServer| FT Name,Admin*

#Install license key:
Set-ExchangeServer -Identity smex-01-w16 -Productkey 7WJV6-H9RMH-F4267-3R2KG-F6PBY

# disable circualar logging
Get-MailboxDatabase
Set-MailboxDatabase "Mailbox Database 1007878065" -CircularLoggingEnabled $false
# restart Information store


# enable file and print services
netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes
# enable powerprofile
powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
# install the Visual C++ 2013 Redistributable Package from MS

# install Unified Communications Managed API (UCMA) runtime 4.0 (Exchange 2019 still requried for skype and lync integration)
# install the version included in the Exchange Server 2019 ISO in the UCMARedist folder.

# install win roles and features:
 you'd rather install the Windows prerequisites yourself from PowerShell instead of letting Setup do it, run the following cmdlet:
 Install-WindowsFeature Web-WebServer,Web-Common-Http,Web-Default-Doc,Web-Dir-Browsing,Web-Http-Errors,Web-Static-Content,Web-Http-Redirect,Web-Health,Web-Http-Logging,Web-Log-Libraries,Web-Request-Monitor,Web-Http-Tracing,Web-Performance,Web-Stat-Compression,Web-Dyn-Compression,Web-Security,Web-Filtering,Web-Basic-Auth,Web-Client-Auth,Web-Digest-Auth,Web-Windows-Auth,Web-App-Dev,Web-Net-Ext45,Web-Asp-Net45,Web-ISAPI-Ext,Web-ISAPI-Filter,Web-Mgmt-Tools,Web-Mgmt-Compat,Web-Metabase,Web-WMI,Web-Mgmt-Service,NET-Framework-45-ASPNET,NET-WCF-HTTP-Activation45,NET-WCF-MSMQ-Activation45,NET-WCF-Pipe-Activation45,NET-WCF-TCP-Activation45,Server-Media-Foundation,MSMQ-Services,MSMQ-Server,RSAT-Feature-Tools,RSAT-Clustering,RSAT-Clustering-PowerShell,RSAT-Clustering-CmdInterface,RPC-over-HTTP-Proxy,WAS-Process-Model,WAS-Config-APIs
# mount iso
Mount-DiskImage -ImagePath "C:\Temp\ExchangeServer2019-x64.iso"
# run setup
Setup.EXE /Mode:Install /InstallWindowsComponents /IAcceptExchangeServerLicenseTerms /Roles:MB
# 
# Run the LaunchEMS cmdlet from a CMD prompt to launch the Exchange Management Shell 
# in another window locally on the server.
