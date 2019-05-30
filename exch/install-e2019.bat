#--- run as administrator
runas /user:administrator powershell

# check filesystem
fsutil fsinfo ntfsinfo c:

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


# Enable Remote Desktop
# Launch the registry editing tool by typing REGEDIT in the run.
HKEY_LOCAL_MACHINE\SYSTEM\CurRentControlSet\Control\Terminal Server\fDenyTSConnections Name 0
# Enable RDP:
Reg add “HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server”  /v fDenyTSConnections /t REG_DWORD /d /f
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" –Value 
# disable RDP: 
Reg add “HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server”  /v fDenyTSConnections /t REG_DWORD /d 1 /f
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" –Value 1
Netsh advfirewall firewall set rule group=”remote desktop” new enable=yes
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
# Add User to 
Add-LocalGroupMember -Group "Remote Desktop Users" -Member "manu"
Add-LocalGroupMember -Group "Remote Desktop Users" -Member "administrator"
Add-LocalGroupMember -Group "Remote Desktop Users" -Member "admin1"

Invoke-Command -Computername <computer name> -ScriptBlock {Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" –Value 0 }
Invoke-Command -Computername <computer name> -ScriptBlock {Enable-NetFirewallRule -DisplayGroup "Remote Desktop"}

# 
# Install Active Directory services
# 
Import-Module ServerManager
Install-windowsfeature -name AD-Domain-Services –IncludeManagementTools

#
# Windows PowerShell script for AD DS Deployment
#
Import-Module ADDSDeployment

dism /online /Disable-Feature /FeatureName:WindowsMediaPlayer /norestart
dism /online /enable-feature /featurename:NetFX3 /all /Source:d:\sources\sxs /LimitAccess


# Windows PowerShell script for AD DS Deployment
#

Import-Module ADDSDeployment
Install-ADDSForest `
-CreateDnsDelegation:$false `
-DatabasePath "C:\Windows\NTDS" `
-DomainMode "Win2012R2" `
-DomainName "tmmr-a1c-w16-01.tm" `
-DomainNetbiosName "TMMR-a1c-W16-01" `
-ForestMode "Win2012R2" `
-InstallDns:$true `
-LogPath "C:\Windows\NTDS" `
-NoRebootOnCompletion:$false `
-SysvolPath "C:\Windows\SYSVOL" `
-Force:$true


----
#
# Enable Quick Edit for cmd
#

# gpmc.msc
# Widows settings - Security Settings - Account Policy - Password Policy
# Pwd must meet complexity - disbble
# minimum pwd age - 0
# maximum pwd age - 0 (never expires)
# Windows settings - Security Settings - Local Policy - Security Options
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

Set-ADDefaultDomainPasswordPolic
Set-ADDefaultDomainPasswordPolicy -Identity TMMR-a1c-W16-01.tm -MaxPasswordAge 0 -MinPasswordLength 0 -PassThru

# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange=1
# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\RefusePasswordChange=1

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "DisablePasswordChange" –Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RefusePasswordChange" –Value 1

Set-GPRegistryValue -Name "Default Domain Policy" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SeCEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/Netlogon/Parameters" -ValueName "DisablePasswordChange" -Type DWORD -value 1
Set-GPRegistryValue -Name "Default Domain Policy" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SeCEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/Netlogon/Parameters" -ValueName "RefusePasswordChange" -Type DWORD -value 1

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\DisableCAD=1
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policy\System\shutdownwithoutlogon=1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DisableCAD -Value 1
Set-ItemProperty -Path "HKLM:\Microsoft\Windows\CurrentVersion\Policy\System" -Name shutdownwithoutlogon -Value 1

reg add "HKLM\SOFTWARE\policies\microsoft\Windows NT\Reliability" /v ShutdownReasonUI  /t REG_DWORD /d 0 /f
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" -Name ShutdownReasonOn -Value 0
#
# Get Flashplayer version 
# https://get.adobe.com/flashplayer/
i.e. Version "32.0.0.142"
# Get local Version of Flash Player
# NPAPI (Mozilla)
Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Adobe Flash Player NPAPI" | Select DisplayVersion
# Unintall STring: C:\WINDOWS\SysWOW64\Macromed\Flash\FlashUtil32_32_0_0_142_Plugin.exe -maintain plugin
# PPAPI (Chrome)
HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Adobe Flash Player PPAPI\DisplayVersion
Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Adobe Flash Player PPAPI" | Select DisplayVersion
# Uninstall String: C:\WINDOWS\SysWOW64\Macromed\Flash\FlashUtil32_32_0_0_142_pepper.exe -maintain pepperplugin
# install flash silently 
#- install
# msi: start /wait msiexec /i "%~dp0%xxxxxx.msi%" /qn
# start /wait msiexec /i "%~dp0%xxxxxx.msi%" /qn
# create config file  in 
# C:\windows\system32\macromed\flash\mms.cfgin 
#C:\windows\syswow64\macromed\flash\mms.cfgin 
# with the content
#AutoUpdateDisable=1
#SilentAutoUpdateEnable=0
----


$RegUninstallPath=@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
$UninstallSearchFilter = {($_.GetValue('Publisher') -like '*Mozilla*')} -and {($_.GetValue('DisplayName') -like '*')} -and {($_.GetValue('DisplayVersion') -like '*')}
foreach ($Path in $RegUninstallPath) {if (Test-Path $Path) {Get-ChildItem $Path | Where $UninstallSearchFilter }} 



# 7zip
# Get version installed x64: Registry:
Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" | Select DisplayVersion
# Get Version isntalled x32: 
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\7-Zip" | Select DisplayVersion

# Comodo Dragon
# Get version installed x64: Registry:
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" | Select DisplayVersion
# Get Version isntalled x32: 
Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Comodo Dragon" | Select DisplayVersion

# Java
# Installer
# Drive abreviation is needed!
New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null 
Get-ItemProperty -Path "HKCR:\Installer\Products\4EA42A62D9304AC4784BF2238120100F" | Select ProductName
# Java uninstall string: 32 Bit 
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{26A24AE4-039D-4CA4-87B4-2F32180172F0}" | Select DisplayVersion
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{26A24AE4-039D-4CA4-87B4-2F32180201F0}" | Select Displ
#
Java uninstall string: 64 Bit 
Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{26A24AE4-039D-4CA4-87B4-2F32180172F0}" | Select DisplayVersion
Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{26A24AE4-039D-4CA4-87B4-2F32180201F0}" | Select DisplayVersion
#
Mozilla Firefox

$RegUninstallPath=@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
$UninstallSearchFilter = {($_.GetValue('DisplayName') -like '*Firefox*') -and ($_.GetValue('Publisher') -like '*Mozilla*')}
foreach ($Path in $RegUninstallPath) {if (Test-Path $Path) {Get-ChildItem $Path | Where $UninstallSearchFilter }} 

#
# Acrobat Reader uninstall string: 32 Bit 
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{AC76BA86-7AD7-1033-7B44-AC0F074E4100}" | Select DisplayVersion
# Acrobat Reader uninstall string: 64 Bit 
Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{AC76BA86-7AD7-1033-7B44-AC0F074E4100}" | Select DisplayVersion

# Add AD Groups
#
NEW-ADGroup –name "Gr-Sales" –groupscope Global
NEW-ADGroup –name "Gr-Techie" –groupscope Global
NEW-ADGroup –name "Gr-All" –groupscope Global
NEW-ADGroup –name "Gr-SMEX-Admin" –groupscope Global
NEW-ADGroup –name "GR-SQL-ADM" –groupscope Global
NEW-ADGroup –name "GR-EX-ADM" –groupscope Global
NEW-ADGroup –name "GR-All-Srvc" –groupscope Global


#
# Add AD Users inclusive password
#
$password = "testlab" | ConvertTo-SecureString -AsPlainText -Force; or
# input new password
$password = Read-Host -Prompt "Password" -AsSecureString
# import new AD user via script
Import-Csv -Path c:\scripts\newusers.csv |
foreach {
New-ADUser -Name $_.Name -SamAccountName $_.samaccountname `
-AccountPassword $secpass -Enabled:$true `
-Path 'OU=UserGroups,DC=Manticore,DC=org' 
}
# move AD User to another OU
Get-ADUser -Filter * -SearchBase 'OU=UserGroups,DC=Manticore,DC=org'  | 
Move-ADObject -TargetPath 'OU=UserAccounts,DC=Manticore,DC=org'
# set additional attribute:
$source = Get-ADUser -Identity bobsmith -Properties OfficePhone, otherHomePhone
Set-ADUser -Identity EmilySmith -Replace @{telephoneNumber = $($source.OfficePhone); otherHomePhone = $($source.otherHomePhone)}
Get-AD User -Identtiy bobsmith -properties 
Get-ADUser -Identity emilysmith -Properties * | select *phone*
# remove a user
Remove-ADUser -Identity emilysmith -whatif
# find locked AD user
Search-ADAccount -LockedOut
# To find users with expired passwords: 
Search-ADAccount -PasswordExpired
# To find expired accounts: 
Search-ADAccount -AccountExpired
# get accounts wiht last login date < 30 days
$testdate = (Get-Date).AddDays(-90)
Get-ADUser -Filter * -Properties LastLogonDate | where {$_.LastLogonDate -And  $_.LastLogonDate -le $testdate}
This code look

New-ADUser -Name user01 -Surname User01 -AccountPassword $password -ChangePasswordAtLogon $False -Enabled:$True
New-ADUser -Name user02 -Surname User02 -AccountPassword $password -ChangePasswordAtLogon $False -Enabled:$True
New-ADUser -Name user03 -Surname User03 -AccountPassword $password -ChangePasswordAtLogon $False -Enabled:$True
New-ADUser -Name user04 -Surname User04 -AccountPassword $password -ChangePasswordAtLogon $False -Enabled:$True
New-ADUser -Name user05 -Surname User05 -AccountPassword $password -ChangePasswordAtLogon $False -Enabled:$True
New-ADUser -Name chef -Surname chef -AccountPassword $password -ChangePasswordAtLogon $False -Enabled:$True
New-ADUser -Name Alice -Surname Jones -AccountPassword $password -ChangePasswordAtLogon $False -Enabled:$True
New-ADUser -Name Bob -Surname Smith -AccountPassword $password -ChangePasswordAtLogon $False -Enabled:$True
New-ADUser -Name Tim -Surname Allen -AccountPassword $password -ChangePasswordAtLogon $False -Enabled:$True
New-ADUser -Name Happy -Surname Day -AccountPassword $password -ChangePasswordAtLogon $False -Enabled:$True
New-ADUser -Name John -Surname Smith -AccountPassword $password -ChangePasswordAtLogon $False -Enabled:$True
New-ADUser -Name SQL-adm -Surname SQL-adm -AccountPassword $password -ChangePasswordAtLogon $False -Enabled:$True
New-ADUser -Name SQLSrvAcc -Surname SQLSrvAcc -AccountPassword $password -ChangePasswordAtLogon $False -Enabled:$True
New-ADUser -Name Ex-adm   -Surname Ex-adm   -AccountPassword $password -ChangePasswordAtLogon $False -Enabled:$True
New-ADUser -Name ExSrvAcc -Surname ExSrvAcc -AccountPassword $password -ChangePasswordAtLogon $False -Enabled:$True
New-ADUser -Name ADSrvAcc -Surname ADSrvAcc -AccountPassword $password -ChangePasswordAtLogon $False -Enabled:$True
New-ADUser -Name SMEX-adm -Surname SMEX-adm -AccountPassword $password -ChangePasswordAtLogon $False -Enabled:$True
New-ADUser -Name smex-service -AccountPassword $password -ChangePasswordAtLogon $False -Enabled:$True
New-ADUser -Name a1c-service -AccountPassword $password -ChangePasswordAtLogon $False -Enabled:$True
New-ADUser -Name charles -Surname tailer -SamAccountName charlestailer -AccountPassword $password -Enabled:$true -Path 'OU=UserGroups,DC=Manticore,DC=org' -PassThru
#
# Add AD Groups
#
NEW-ADGroup –name "Gr-Sales" –groupscope Global
NEW-ADGroup –name "Gr-Techie" –groupscope Global
NEW-ADGroup –name "Gr-All" –groupscope Global
NEW-ADGroup –name "Gr-SMEX-Admin" –groupscope Global
NEW-ADGroup –name "GR-SQL-ADM" –groupscope Global
NEW-ADGroup –name"GR-All-Srvc" –groupscope Global
NEW-ADGroup –name "GR-EX-ADM" –groupscope Global
NEW-ADGroup –name"Gr-SMEX-Admin"  –groupscope Global
#
# Add AD Users to AD Group 
#
Add-ADGroupMember -Identity Gr-All -Members User01,User02,User03,User04,User05,chef,alice,bob,tim,happy,john
Add-ADGroupMember -Identity Gr-Techie -Members User03,User4,tim,chef
Add-ADGroupMember -Identity Gr-Sales -Members User01,User02,bob,chef
Add-ADGroupMember -Identity GR-SQL-ADM -Members SQL-adm
Add-ADGroupMember -Identity GR-All-Srvc -Members SQLSrvAcc,ADSrvAcc,ADSrvAcc,smex-service,a1c-service
Add-ADGroupMember -Identity GR-admin -Members SMEX-adm,Ex-adm,SQL-adm 
Add-ADGroupMember -Identity GR-EX-ADM -Members SQLSrvAcc,ADSrvAcc
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

Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name SubmitSampleConsent -Value 2
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name SpynetReporting -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name AllowTelemetry -Value 0

# copy the output of a command so it can be pasted in another application (via clipboard)
application.exe | clip

# Install CA

# To install the inf file before  the Certification Service is enrolled
# The OID should be changed to your own organizations OID, as the one listed is the Microsoft OID.  
# See this MSDN article here:  (http://msdn.microsoft.com/library/windows/desktop/ms677621.aspx)
---
# c:\windows\CAPolicy.inf
[Version]
Signature=”$Windows NT$”
[PolicyStatementExtension]
Policies=InternalPolicy
[InternalPolicy]
OID= 1.2.3.4.1455.67.89.5
URL=http://pki.bedrock.domain/pki/cps.html
[Certsrv_Server]
RenewalKeyLength=2048
RenewalValidityPeriod=Years
RenewalValidityPeriodUnits=20
CRLPeriod=Years
CRLPeriodUnits=20
CRLDeltaPeriod=Days
CRLDeltaPeriodUnits=0
LoadDefaultTemplates=0
---
# Install AD CS Role
Add-WindowsFeature Adcs-Cert-Authority -IncludeManagementTools
# After the role is finished installing, you must configure it.  
# Enter the following in PowerShell, changing the options as needed to fit your environment.  
# The options are described below:
Install-AdcsCrtificatoinAuthority -CAType EnterpriseRootCa -CryptoProviderName "
# Configure Tool
Install-AdcsCertificationAuthority -CAType StandaloneRootCA -CACommonName "TMMR A1C Root Certificate Authority" -KeyLength 4096 -HashAlgorithm SHA256 -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" -ValidityPeriod Years -ValidityPeriodUnits 20 -Force
# Tools for Mangement Server
Add-WindowsFeature RSAT-ADCS,RSAT-ADCS-mgmt
---
$crllist = Get-CACrlDistributionPoint; foreach ($crl in $crllist) {Remove-CACrlDistributionPoint $crl.uri -Force};
Add-CACRLDistributionPoint -Uri C:\Windows\System32\CertSrv\CertEnroll\BEDROCK-ROOT%8%9.crl -PublishToServer -PublishDeltaToServer -Force
Add-CACRLDistributionPoint -Uri http://pki.bedrock.domain/pki/BEDROCK-ROOT%8%9.crl -AddToCertificateCDP -AddToFreshestCrl -Force
Get-CAAuthorityInformationAccess | where {$_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*'} | Remove-CAAuthorityInformationAccess -Force
Add-CAAuthorityInformationAccess -AddToCertificateAia http://pki.bedrock.domain/pki/BEDROCK-ROOT%3%4.crt -Force
certutil.exe –setreg CA\CRLPeriodUnits 20
certutil.exe –setreg CA\CRLPeriod “Years”
certutil.exe –setreg CA\CRLOverlapPeriodUnits 3
certutil.exe –setreg CA\CRLOverlapPeriod “Weeks”
certutil.exe –setreg CA\ValidityPeriodUnits 10
certutil.exe –setreg CA\ValidityPeriod “Years”
certutil.exe -setreg CA\AuditFilter 127
Restart-Service certsvc




http://www.azure365pro.com/install-and-configure-certificate-authority-in-windows-server-2016/
Open Server Manager – Manage – Add Roles and Features
Choose : Active Directory Certificate Services
Choose : •Certification Authority•Certification Authority Web Enrollment
Choose Install and Close

Step 3:
To Configure Active Directory Certificate Services – Choose the Exclamation Mark on the Flag
Configure Active Directory Certificate Services on the Destination Server
Choose •Certificate Authority •Certification Authority Web Enrollment
Choose Enterprise CA
•Enterprise CAs Must be domain members and are typically online to issue certificates or certificate policies
Step 4:
 Choose Root CA
Root CAs are the first and may be the only CAs Configured in a PKI Hierarchy.

Step 5:
 Create a new Private key
Step 6:
•Use SHA256
•RSA#Microsoft Software Key Storage Provider
•Key Length – 2048


certification authority
Certification authority web enrollment

Enterprise CA
Root CA
New private Key
RSA 2048
SHA256

Common name: tmmr-cm-w16-01-TMCM7-01-W16-CA
Distinguished name: DC=tmmr-cm-w16-01,DC=tm
PRev. of distinguished name: CN=tmmr-cm-w16-01-TMCM7-01-W16-CA,DC=tmmr-cm-w16-01,DC=tm

30 years

db location: C:\Windows\system32\CertLog
Cert db log location: C:\Windows\system32\CertLog

#----
http://www.pdhewaju.com.np/2017/03/02/configuring-secure-ldap-connection-server-2016/
http://pdhewaju.com.np/2016/04/08/installation-and-configuration-of-active-directory-certificate-services/

LDAP...Lightweight Directory Access Protocol
per default LDAP is insecure
To make LDAP secure SSL can be used
prerequisite: install a properly formatted certificate from MS CA or non MS CA

LDAP Port: TCP/UDP 389
LDAPS Port: TCP/UDP 636

how to check: open ldp

Install Certificate Authority on the Domain Controller

Open the Local CA
Right click on Certificate template / Manage / Action / View Object Identifiers
Now scroll down and verify if you do have Server Authentication with object Identifier 
	1.3.6.1.5.5.7.3.1, this is the thing which allows us to configure secure ldap.
Open MMC / Add or Remove Snap-in / computer certificates / Add certificate for th local computer and click OK
Expand "Personal" / Certificates / All Tasks / Request New Certificate... / 
Certificate Enrollmnent / Next / Certificate Enrollment Policy Next / Select Domian Controller / Click Enroll
Click Finish for completion
Certificate issued for the domain controll is listed 





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

#---
# generate certificate for Exchange Server
- Browse to your Certificate services web console, via https://server.local/certsrv
- Select a new request, and choose the advanced option on the next screen.
- Submit a certificate request by using a base 64 encoded CMC or PKS #10 file.
- Open the certificate request that you generated from my previous blog post. 
This just needs to be opened in your favourite text editor.
- Copy the contents of the file and paste it into the request field on the web console. 
Select the server type as a web server, and leave all other attributes blank.
- Save the resulting certificate to an accessible location, and close the web console.
# import the certificate into Exchange - Through EMS - Use the Import-Exchange-Certificate-Path
 Import-Exchange-Certificate-Path c:\temp\cert_answer.cer | Enable Exchangecertificate-Services “SMTP, IMAP, POP, IIS”
# check and make sure that the new certificate is in use. i.e with  test-outlookwebservices
 c:\windows\system32>test-outlookwebservices | FL
# You should now see the details of the certificate. 
# Easiest things to spot that it is the new certificate include the validity dates, or any SAN’s you may have included.
# Browse to the OWA service and view the certificate that is presented to ensure that it is in fact the new and current one.
#---


# Exchange default databse foulder (*.edb)
C:\Program Files\Microsoft\Exchange Server\V15\Mailbox\Mailbox Database <Nummer>.

# create new mailbox databaases
New-MailboxDatabase -Name "new-db-name" -EdbFilePath D:\DatabaseFiles\MailboxDatabase01.edb -LogFolderPath D:\DatabaseFiles\LogFolder

# restart exchange database service
# Net stop msexchangeis; Net start msexchangeis

# moaunt new database
mount-Database  -Identity  "new-db-name"

# Anzeige der aktuell vorhandenen Datenbanken
Get-MailboxDatabase |fl Name,EdbFilePath,LogFolderPath

# umbenennen der Datenbanken
Set-MailboxDatabase "Mailbox Database 32566324217" -Name "DB01"

# databank verschieben
Move-DatabasePath -Identity <Datenbank> -EdbFilePath <Neuer Pfad zur EDB-Datei>
# datenbank verschieben nit aenderung des Speicherung der Transaction logs
Move-DatabasePath DB01 -EdbFilePath D:\DB01\DB01.edb -LogFolderPath E:\DB01

# Set Max values for mailboxes
#

# Generate DAG Groups
#

#  Maibloxen anzeigen 
Get-MailboxDatabase. 
# Anzeige Maiboxen inklusive Mountstatus
Get-MailboxDatabase | Select Name, Mounted 
# Satus der Datenbank 
Get-MailboxDatabase -Status
# informationen zur sicherung 
Get-MailboxDatabase -Status | Select Name, Mounted, LastFullBackup,LastIncrementalBackup,BackupinProgress 
# status der Replikation
Get-MailboxDatabaseCopyStatus
# REpliationsstatus aller datenbank vom server
Get-MailboxDatabase | Get-MailboxDatabaseCopyStatus

# Exchange maintenance - offline Defragmenierung (database shrink)
Eseutil.exe /d
# ???
eseutil /mh " Mailbox Database.edb" 
# DAtenbank auf konsistenz pruefen
eseutil /k " Mailbox Database.edb" 
# datenbank integritaet ueberpruefen
Eseutil /g "Mailbox Database <ID>.edb"

# ab Exchange 2013 Reparaturmoeglichkeit (frueher isinteg
New-MailboxRepairRequest -Database "Mailbox Database" -CorruptionType SearchFolder,AggregateCounts,ProvisionedFolder,FolderView 

# datenbank dismounten (z.B. fuer offline defrag)
Dismount-Database -Identity <Name der Datenbank>
# Status sder Datenbank nach dem defragemtieren - ist  der unterschied sehr gross, dann defrag
Get-MailboxDatabase -Status |ft Name,DatabaseSize,AvailableNewMailboxSpace 
# 

# Enable accout for Mailbox export/import for user:
New-ManagementRoleAssignment -Role "Mailbox Import Export" -User "<Benutzername>" 
# Enable group for Mailbox export/import:
New-ManagementRoleAssignment -Role "Mailbox Import Export" -SecurityGroup "<Gruppe>"
# restart the Exchange Management Shell after changing the rights
# After the restart following cmdlets are available
# Get Help for new command for Export also possible for import
Help New-Mailbox-ExportRequest 
Help New-MailboxExportRequest  -Detailed
Help New-MailboxExportRequest -Examples 

# New-MailboxImportRequest: Mit  diesem  Cmdlet  importieren  Sie  Daten  einer  .pst-Datei in Exchange-Datenbanken. 
#    Der Befehl überprüft den Import auf Duplikate und über-geht diese beim Import.
# Get-MailboxImportRequest Mit diesem Cmdlet erhalten Sie Informationen über aktu-elle Importvorgänge und deren Status.
# Get-MailboxImportRequestStatistics Mit diesem Befehl lassen sich weiterführende Informationen anzeigen, 
#    die über die Möglichkeiten von Get-MailboxImportRequest hin-ausgehen. 
# Remove-MailboxImportRequest Dieses Cmdlet löscht Importvorgänge, die noch in der Warteschlange stehen. 
#   Auch bereits durchgeführte Importvorgänge lassen sich mit dem Befehl aus der Anzeige entfernen.
# ResumE-MailboxImportRequest Mit diesem Cmdlet starten Sie einen fehlgeschlage-nen Import erneut. 
#   Auch mit Suspend-MailboxImportRequest pausierte Importvorgänge lassen sich mit dem Cmdlet erneut starten.
# Set-MailboxImportRequest Mit  diesem  Cmdlet  passen  Sie  Optionen  eines  bereits erstellten Importvorgangs nachträglich an.
# Suspend-MailboxImportRequest Mit  diesem  Befehl  halten  Sie  einen  oder  mehrere Importvorgänge an.
# New-MailboxExportRequest Mit  diesem  Befehl  exportieren  Sie  Postfächer  in  .pst-Dateien.
# Get-MailboxExportRequest Dieses Cmdlet zeigt Informationen zu den anstehendenExportvorgängen an.
# Get-MailboxExportRequestStatistics Mit diesem Cmdlet zeigen Sie erweiterte Infor-mationen an, die Get-MailboxExportRequest 
#    nicht anzeigt. 
# RemovE-MailboxExportRequest Löscht anstehende Exportvorgänge oder entfernt die Anzeige bereits durchgeführter Vorgänge.
# ResumE-MailboxExportRequestMit diesem Cmdlet starten Sie einen fehlgeschlage-nen Export erneut. Auch mit Suspend-MailboxExportRequest
#    pausierte Exportvorgänge lassen sich mit dem Cmdlet wieder starten.
# Set-MailboxExportRequestMit  diesem  Cmdlet  passen  Sie  Optionen  eines  bereits erstellten Exports-Vorgangs nachträglich an.
# Suspend-MailboxExportRequestMit  diesem  Befehl  halten  Sie  einen  oder  mehrere Exportvorgänge an.Die Cmdlets zum Importieren und 
#    Exportieren bieten mit der Option -ContentFilter weitrei-chende Möglichkeiten zur Filterung an. 

# Anzeige der Postfaecher einer DAtenbank
Get-Mailbox -Database <Name der Datenbank> 
# Ausgabe aller Mailboxen einer Organisation
# Get-Mailbox


# Export mailbox from database to pst mit oder ohne -Confirm:$false - Export-Mailbox is old - 2010
# note: per default the needed rights are missing for Organisationsadministrator oder Domainadministrators (do not see the cmdlets) 
# Export-Mailbox is not available in Exchange 2016 - Export-Mailbox is old - 2010
Get-Mailbox -Database <Name des Exchange-Servers>\<Postfachdatenbank> | Export-Mailbox -PSTFolderPath <Pfad> 

# Import pst to database mit oder ohne -Confirm:$false 
# Import-Mailbox is not available in Exchange 2016 - Import-Mailbox is old 2013
Get-Mailbox -Database <Name des Exchange-Servers>\<Postfachdatenbank> | Import-Mailbox -PSTFolderPath <Pfad> 

# Import post to database for Exchange 2016 - needs UNC path, with -verbose more inforamtion
New-MailboxImportRequest -Mailbox <Name des Postfachs> -FilePath <UNC-Pfad und Name der .pst-Datei>
New-MailboxImportRequest -Mailbox joost -FilePath \\s1\temp\outlook1.ps
# Importstatus
Get-MailboxImportRequest <Name des Importvorgangs> |fl
# in case or errors
# 1. Check Role assignment persmissions 
Get-ManagementRoleAssignment -RoleAssignee <Gruppe oder Benutzer>
# 2. see if the mailbox is available
Get-Mailbox -Identity <Name>
# 3. enough rights to the Mabilbox
Get-Mailbox -Identity <Name> | Get-MailboxPermission 
# bei erfolgreichem importstatus loeschen des Reports
$ Import von speziellen foldern moeglich< exclude von Ordnern mit  -ExcludeDumpster, Zielorder im Postfach mit TargetRootFolder
# mit -IsArchive, import ins Archiv
# New-MailboxImportRequest -Mailbox <Name> -FilePath <UNC-Pfad und Name der .pst-Datei> -IncludeFolders <Name des Ordners aus der .pst-Datei>


## Konnektivitaet von Exchange testen
# Voraussetzunt: TEstuser ist angelegt: 
C:\Program Files\Micro-soft\Exchange Server\V15\Scripts\New-TestCasConnectivityUser.ps1 
# Script auf Maiboxserver ausfuehren:
Get-MailboxServer | .\New-TestCasConnectivityUser.ps1
# Anzeige aller ClientAccess serve: 
Get-ClientAccessServer
# ActiveSync testen:
Test-ActiveSyncConnectivity-CliemtAccessServer <Servername>
# Andere Test commandlets:
 Test-OwaConnectivity , Test-EcpConnectivity, Test-WebServicesConnectivity, Test-PopConnectivity, Test-ImapConnectivit

Test-OutlookConnectivity -Protocol httpTest-OutlookConnectivity -Protocol tcp
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
