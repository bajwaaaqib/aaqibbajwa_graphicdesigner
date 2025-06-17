function Get-WiFiPasswords {
    $profiles = netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object {
        ($_ -split ":")[1].Trim()
    }
  
      Write-Host "PASSWORDS OF AVAIALBLE CONNECTIONS" -ForegroundColor Green
    foreach ($profile in $profiles) {
        Write-Host "`n===== $profile =====" -ForegroundColor Cyan
        netsh wlan show profile name="$profile" key=clear | Select-String "Key Content"
    }
pause
}

Get-WiFiPasswords
