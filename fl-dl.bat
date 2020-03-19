!/bin/bash
#Flashplayer
logfile=download_log

$Version='32.0.0.344"
$baseUrl = "https://fpdownload.macromedia.com/get/flashplayer/pdc/$Version/"
$dir = 'f:\'
$files = 'install_flash_player_ax.exe',
         'install_flash_player.exe',
          'install_flash_player_ppapi.exe',         


Set-Location $dir
foreach ($file in $files)
{
   Write-Host "Downloading $file"
   $dlUrl = "$($baseUrl)$file"
   $dlPath = "$($dir)$file"
   Invoke-WebRequest $dlUrl -OutFile $dlPath
   
   Flash Player 32.0.0.330 (ppapi).exe
   Flash Player 32.0.0.330 (npapi).exe
   
   $Version='32.0.0.344'
   $baseUrl = "https://fpdownload.macromedia.com/get/flashplayer/pdc/$Version"
   $dir = 'f:'
   Invoke-WebRequest "$($baseUrl)/install_flash_player_ax.exe" -OutFile "$($dir)\Flash Player $Version (ie).exe"
   Invoke-WebRequest "$($baseUrl)/install_flash_player.exe" -OutFile "$($dir)\Flash Player $Version (nnapi).exe"
   Invoke-WebRequest "$($baseUrl)/install_flash_player_ppapi.exe" -OutFile "$($dir)\Flash Player $Version (ppapi).exe"
   
   $dlUrl = "$($baseUrl)/install_flash_player_ax.exe"
   $dlPath = "$($dir)\Flash Player $Version (ie).exe"
   Invoke-WebRequest $dlUrl -OutFile $dlPath
   $dlUrl = "$($baseUrl)/install_flash_player.exe"
   $dlPath = "$($dir)\Flash Player $Version (nnapi).exe"
   Invoke-WebRequest $dlUrl -OutFile $dlPath
   $dlUrl = "$($baseUrl)/install_flash_player_ppapi.exe"
   $dlPath = "$($dir)\Flash Player $Version (ppapi).exe"
   Invoke-WebRequest $dlUrl -OutFile $dlPath
   #
#
$baseUrl + '/install_flash_player_ax.exe'
https://fpdownload.macromedia.com/get/flashplayer/pdc/32.0.0.101'/'
https://fpdownload.macromedia.com/get/flashplayer/pdc/32.0.0.101' '
 

ActiveX https://fpdownload.adobe.com/get/flashplayer/distyfp/current/win/
NPAPI https://fpdownload.adobe.com/get/flashplayer/distyfp/current/win/install_flash_player_27_plugin.msi 
PPAPI https://fpdownload.adobe.com/get/flashplayer/distyfp/current/win/install_flash_player_27_ppapi.msi 

fplayer_mainlink='https://fpdownload.macromedia.com/pub/flashplayer/get/'
fplayer_version=`curl --silent 'http://get.adobe.com/flashplayer/about/' | grep -o '[0-9]\{2\}\.[0-9]\.[0-9]\.[0-9]\{3\}' | sort -u -V | tail -1`
fplayer_main=`echo $fplayer_version | cut -c1-2`
f_activex='install_flash_player_'$fplayer_main'_active_x.msi'
f_plugin='install_flash_player_'$fplayer_main'_plugin.msi'
f_ppapi='install_flash_player_'$fplayer_main'_ppapi.msi'

echo Download Flashplayer ActiveX $fplayer_version >>$logfile
echo --------------------- >>$logfile
wget -nv -a $logfile -nc -P flashplayer_$fplayer_version $fplayer_mainlink$fplayer_version/$f_activex

echo Download Flashplayer Plugin $fplayer_version >>$logfile
echo --------------------- >>$logfile
wget -nv -a $logfile -nc -P flashplayer_$fplayer_version $fplayer_mainlink$fplayer_version/$f_plugin

echo Download Flashplayer NPAPI $fplayer_version >>$logfile
echo --------------------- >>$logfile
wget -nv -a $logfile -nc -P flashplayer_$fplayer_version $fplayer_mainlink$fplayer_version/$f_ppapi
