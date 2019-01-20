
$url = " http://2016.eicar.org/download/eicar" 
$path = "C:\temp\eicar" 
$usrAgent = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2;)"
# $pwd = ...


# eicar.com
# $eicarext =".com"
# eicar.txt
# $eicarext =".com.txt"
# eicar.zip
# $eicarext ="_com.zip"
# eicar2.zip
# $eicarext ="com2.zip"

# param([string]$url+ $eicarext, [string]$path+§eicarext) 
      
    if(!(Split-Path -parent $path) -or !(Test-Path -pathType Container (Split-Path -parent $path))) { 
      $path = Join-Path $pwd (Split-Path -leaf $path) 
    } 
     
    # Write to console: 
    $client = new-object System.Net.WebClient 
	$client.Headers.Add("user-agent", $usrAgent)
    # eicar.com
    $eicarext = ".com"
    # Write to console: 
    "Downloading [$url$eicarext]`nSaving at [$path$eicarext]" 
	$client.Headers.Add("user-agent", $usrAgent)
    $client.DownloadFile($url+$eicarext, $path+$eicarext)
    # eicar.txt
    $eicarext = "_com.txt"
    # Write to console: 
    "Downloading [$url$eicarext]`nSaving at [$path$eicarext]" 
	$client.Headers.Add("user-agent", $usrAgent)
    $client.DownloadFile($url+$eicarext, $path+$eicarext)
	# eicar.zip
    $eicarext = "_com.zip"
    # Write to console: 
    "Downloading [$url$eicarext]`nSaving at [$path$eicarext]" 
	$client.Headers.Add("user-agent", $usrAgent)
    $client.DownloadFile($url+$eicarext, $path+$eicarext)
    # eicar2.zip
    $eicarext = "_com2.zip"
    # Write to console: 
    "Downloading [$url$eicarext]`nSaving at [$path$eicarext]" 
	$client.Headers.Add("user-agent", $usrAgent)
    $client.DownloadFile($url+$eicarext, $path+$eicarext)
    
    #$client.DownloadFile($url$eicarext, $path$eicarext) 
    #$client.DownloadData($url$eicarext, $path$eicarext)
    # or 
    # (new-object System.Net.WebClient).DownloadFile($url, $path)
          
    # $path++$eicarext
