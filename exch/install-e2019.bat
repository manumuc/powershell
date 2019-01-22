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
