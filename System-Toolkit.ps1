# ===========================
# System Toolkit by Aaqib Bajwa
# ===========================

# Ensure Clear-RecycleBin is available
Import-Module Storage -ErrorAction SilentlyContinue

# 1. Activate Windows
function Activate-Windows {
    Write-Host "`n[+] Activating Windows..." -ForegroundColor Yellow
    try {
        slmgr.vbs /ato
    } catch {
        Write-Host "Activation failed: $_" -ForegroundColor Red
    }
    Pause
}

# 2. Check Windows Updates
function Check-WindowsUpdates {
    Write-Host "`n[+] Checking for Windows Updates..." -ForegroundColor Yellow
    Install-PackageProvider -Name NuGet -Force -ErrorAction SilentlyContinue
    Install-Module PSWindowsUpdate -Force -ErrorAction SilentlyContinue
    Import-Module PSWindowsUpdate
    Get-WindowsUpdate
    Pause
}

# 3. Run System Maintenance
function Run-Maintenance {
    Write-Host "`n[+] Running Disk Cleanup..." -ForegroundColor Yellow
    Start-Process cleanmgr.exe -ArgumentList "/sagerun:1" -Wait
    Pause
}

# 4. Show Installed Drivers
function Show-Drivers {
    Write-Host "`n[+] Installed Drivers:" -ForegroundColor Yellow
    Get-WmiObject Win32_PnPSignedDriver |
        Select DeviceName, DriverVersion, Manufacturer |
        Format-Table -AutoSize

    $update = Read-Host "`nOpen Device Manager to check driver updates? (y/n)"
    if ($update -eq 'y') {
        Start-Process devmgmt.msc
    }
    Pause
}

# 5. Show Drive-wise Memory Info
function Show-Drives {
    Write-Host "`n[+] Drive-wise Memory Info:" -ForegroundColor Yellow
    Get-PSDrive -PSProvider FileSystem |
        Select Name,
               @{Name="Used(GB)";Expression={[math]::Round($_.Used/1GB,2)}},
               @{Name="Free(GB)";Expression={[math]::Round($_.Free/1GB,2)}},
               @{Name="Total(GB)";Expression={[math]::Round(($_.Used + $_.Free)/1GB,2)}} |
        Format-Table -AutoSize
    Pause
}

# 6. Activate Office via KMS
function Activate-Office {
    Write-Host "`n[+] Activating Microsoft Office using KMS..." -ForegroundColor Yellow

    $paths = @(
        "C:\Program Files\Microsoft Office\Office16",
        "C:\Program Files (x86)\Microsoft Office\Office16",
        "C:\Program Files\Microsoft Office\Office15",
        "C:\Program Files (x86)\Microsoft Office\Office15"
    )
    $officePath = $paths | Where-Object { Test-Path $_ } | Select-Object -First 1

    if (-not $officePath) {
        Write-Host "Office installation not found. Please verify path." -ForegroundColor Red
        Pause
        return
    }

    Push-Location $officePath
    cscript ospp.vbs /sethst:kms8.msguides.com
    cscript ospp.vbs /act
    Pop-Location

    Pause
}

# 7. Show MAC and IP Address
function Show-NetworkDetails {
    Write-Host "`n[+] Network Adapter Info:" -ForegroundColor Yellow
    Get-NetAdapter | Select Name, MacAddress, Status | Format-Table -AutoSize

    Write-Host "`n[+] IPv4 Address:" -ForegroundColor Yellow
    Get-NetIPAddress | Where-Object AddressFamily -eq 'IPv4' |
        Select InterfaceAlias, IPAddress |
        Format-Table -AutoSize
    Pause
}

# 8. Hardware Health Check
function Check-HardwareStatus {
    Write-Host "`n[+] Checking Hardware Health..." -ForegroundColor Yellow

    $cpu = Get-WmiObject Win32_Processor
    Write-Host "`nCPU: $($cpu.Name)" -ForegroundColor White
    Write-Host "Status: $($cpu.Status)" -ForegroundColor Green

    $ram = Get-WmiObject Win32_PhysicalMemory
    foreach ($r in $ram) {
        Write-Host "RAM: $([math]::Round($r.Capacity/1GB)) GB, $($r.Manufacturer), $($r.Speed) MHz"
    }

    $battery = Get-WmiObject Win32_Battery -ErrorAction SilentlyContinue
    if ($battery) {
        Write-Host "`nBattery Status: $($battery.BatteryStatus), Charge: $($battery.EstimatedChargeRemaining)%"
    }

    $drives = Get-WmiObject Win32_DiskDrive
    foreach ($d in $drives) {
        Write-Host "`nDisk: $($d.Model), Size: $([math]::Round($d.Size/1GB)) GB, Status: $($d.Status)"
    }

    $smart = Get-WmiObject MSStorageDriver_FailurePredictStatus -Namespace root\wmi -ErrorAction SilentlyContinue
    if ($smart) {
        foreach ($s in $smart) {
            if ($s.PredictFailure) {
                Write-Host " SMART Failure Predicted!" -ForegroundColor Red
            } else {
                Write-Host "SMART Status OK" -ForegroundColor Green
            }
        }
    } else {
        Write-Host "SMART not available on this system." -ForegroundColor Yellow
    }

    Pause
}

# 9. Clear Temp/Junk Files
function Clear-JunkFiles {
    Write-Host "`n[+] Clearing Temp and Junk Files..." -ForegroundColor Yellow
    Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
    Clear-RecycleBin -Force -ErrorAction SilentlyContinue
    Write-Host "Cleanup Completed!" -ForegroundColor Green
    Pause
}

# 10. Run SFC and DISM
function Run-SystemRepair {
    Write-Host "`n[+] Running SFC..." -ForegroundColor Yellow
    sfc /scannow
    Write-Host "`n[+] Running DISM..." -ForegroundColor Yellow
    DISM /Online /Cleanup-Image /RestoreHealth
    Write-Host "System Repair Completed!" -ForegroundColor Green
    Pause
}


# 11. Show Installed Applications
function Show-InstalledApps {
    $apps = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
        Select DisplayName, DisplayVersion, Publisher, InstallDate
    $apps | Format-Table -AutoSize
    $apps | Out-File "$env:USERPROFILE\Desktop\InstalledApps.txt"
    Write-Host "`nInstalled apps list saved to Desktop." -ForegroundColor Green
    Pause
}

# 12. Show System Info
function Get-SystemInfo {
    Write-Host "`n[+] Gathering System Information..." -ForegroundColor Cyan

    $sys  = Get-CimInstance -ClassName Win32_ComputerSystem
    $os   = Get-CimInstance -ClassName Win32_OperatingSystem
    $cpu  = Get-CimInstance -ClassName Win32_Processor
    $bios = Get-CimInstance -ClassName Win32_BIOS
    $mb   = Get-CimInstance -ClassName Win32_BaseBoard

    $totalRAMGB = [math]::Round($sys.TotalPhysicalMemory / 1GB, 2)

    Write-Host "`nSystem Information" -ForegroundColor Yellow
    Write-Host "----------------------------------" -ForegroundColor Gray
    Write-Host "Computer Name     : $($sys.Name)"
    Write-Host "Manufacturer      : $($sys.Manufacturer)"
    Write-Host "Model             : $($sys.Model)"
    Write-Host "User Name         : $($sys.UserName)"
    Write-Host "OS Name           : $($os.Caption)"
    Write-Host "OS Version        : $($os.Version)"
    Write-Host "System Type       : $($sys.SystemType)"
    Write-Host ("Total RAM (GB)    : {0:N2}" -f $totalRAMGB)
    Write-Host "Processor         : $($cpu.Name)"
    Write-Host "BIOS Version      : $($bios.SMBIOSBIOSVersion)"
    Write-Host "Motherboard       : $($mb.Manufacturer) $($mb.Product)"

    # Robust date conversion
    if ($os.InstallDate -and $os.InstallDate -match '^\d{14}(\.\d+)?$') {
        $installDate = [System.Management.ManagementDateTimeConverter]::ToDateTime($os.InstallDate)
        Write-Host "Install Date      : $installDate"
    } else {
        Write-Host "Install Date      : Not Available or Invalid Format" -ForegroundColor DarkYellow
    }

    if ($os.LastBootUpTime -and $os.LastBootUpTime -match '^\d{14}(\.\d+)?$') {
        $bootTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime)
        Write-Host "Last Boot Time    : $bootTime"
    } else {
        Write-Host "Last Boot Time    : Not Available or Invalid Format" -ForegroundColor DarkYellow
    }

    Write-Host "----------------------------------"
    Pause
}

# 13. Network Speed Test
function Test-NetworkSpeed {
    Write-Host "`n[+] Opening Network Speed Test in Browser..." -ForegroundColor Cyan
    Start-Process "https://fast.com"
    Pause
}

# 14. Battery Health Report (for laptops)
function Generate-BatteryReport {
    Write-Host "`n[+] Generating Battery Health Report..." -ForegroundColor Cyan
    $outputPath = "$env:USERPROFILE\Desktop\battery_report.html"
    powercfg /batteryreport /output $outputPath | Out-Null
    if (Test-Path $outputPath) {
        Write-Host "Battery Report saved to: $outputPath" -ForegroundColor Green
        Start-Process $outputPath
    } else {
        Write-Host "Failed to generate battery report." -ForegroundColor Red
    }
    Pause
}

# 15. System Uptime
function Show-SystemUptime {
    Write-Host "`n[+] Calculating System Uptime..." -ForegroundColor Cyan
    $uptime = (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    Write-Host "System Uptime: $($uptime.Days) days, $($uptime.Hours) hours, $($uptime.Minutes) minutes" -ForegroundColor Yellow
    Pause
}

# 16. List and Manage Running Services
function Manage-Services {
    Write-Host "`n[+] Listing Running Services..." -ForegroundColor Cyan
    Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Status, Name, DisplayName | Format-Table -AutoSize
    Write-Host "
Use 'Get-Service <name> | Stop-Service' or 'Start-Service' commands to manage services manually." -ForegroundColor Gray
    Pause
}

# 17. Manage Startup Programs
function Show-StartupPrograms {
    Write-Host "`n[+] Listing Startup Programs..." -ForegroundColor Cyan
    $startupItems = Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location
    if ($startupItems) {
        $startupItems | Format-Table -AutoSize
    } else {
        Write-Host "No startup programs found." -ForegroundColor Red
    }
    Pause
}

# 18. Run Virus Scan
function Run-VirusScan {
    Write-Host "`n[+] Running Quick Virus Scan with Windows Defender (Fallback Method)..." -ForegroundColor Cyan

    $defenderPath = "$env:ProgramData\Microsoft\Windows Defender\Platform"
    $exe = Get-ChildItem -Path $defenderPath -Recurse -Filter MpCmdRun.exe -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1

    if (-not $exe) {
        Write-Host "[-] MpCmdRun.exe not found." -ForegroundColor Red
        return
    }

    # Run the scan with a progress bar
    $progressActivity = "Windows Defender Quick Scan"
    $progressStatus = "Starting scan..."

    # Start the scan asynchronously so we can show progress
    $process = Start-Process -FilePath $exe.FullName -ArgumentList "-Scan -ScanType 1" -PassThru -NoNewWindow -Wait

    # Because MpCmdRun.exe doesn't output progress directly, simulate progress bar during the scan
    $progressPercent = 0
    while (-not $process.HasExited) {
        Write-Progress -Activity $progressActivity -Status $progressStatus -PercentComplete $progressPercent
        Start-Sleep -Seconds 1
        $progressPercent = ($progressPercent + 10) % 100
    }

    # Clear progress bar after scan finishes
    Write-Progress -Activity $progressActivity -Completed

    Write-Host "[+] Quick Virus Scan completed." -ForegroundColor Green
    Pause
}

# 19. Network Status Check
function Get-NetworkStatus {
    Write-Host "`n[+] Checking Network Status..." -ForegroundColor Cyan

    $progressActivity = "Network Status Check"
    $progressStatus = "Pinging default gateway..."
    $progressPercent = 0

    # Simulate progress during ping test
    for ($i = 0; $i -le 100; $i += 20) {
        Write-Progress -Activity $progressActivity -Status $progressStatus -PercentComplete $i
        Start-Sleep -Milliseconds 400
    }

    # Get network adapters that are up
    $netAdapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }

    # Ping google DNS to check internet connectivity
    $pingResult = Test-Connection -ComputerName 8.8.8.8 -Count 2 -Quiet

    Write-Progress -Activity $progressActivity -Completed

    if ($netAdapters.Count -eq 0) {
        Write-Host "[-] No network adapters are currently connected." -ForegroundColor Red
    }
    else {
        Write-Host "[+] Network adapters currently up:" -ForegroundColor Green
        $netAdapters | ForEach-Object {
            Write-Host "    Name: $($_.Name) | Status: $($_.Status) | MAC: $($_.MacAddress)"
        }

        if ($pingResult) {
            Write-Host "[+] Internet connectivity: Online (8.8.8.8 reachable)" -ForegroundColor Green
        }
        else {
            Write-Host "[-] Internet connectivity: Offline (unable to reach 8.8.8.8)" -ForegroundColor Yellow
        }
    }

    Pause
}

# 20. Windows Defender Real-Time Protection Status
function Get-DefenderRealtimeStatus {
    Write-Host "`n[+] Checking Windows Defender Real-Time Protection Status..." -ForegroundColor Cyan

    $realtimeStatus = Get-MpPreference | Select-Object -ExpandProperty DisableRealtimeMonitoring

    if ($realtimeStatus -eq $false) {
        Write-Host "[+] Real-Time Protection: ENABLED " -ForegroundColor Green
    }
    elseif ($realtimeStatus -eq $true) {
        Write-Host "[-] Real-Time Protection: DISABLED " -ForegroundColor Red
    }
    else {
        Write-Host "[!] Unable to determine Defender status." -ForegroundColor Yellow
    }

    Pause
}

# 21.  Launch Snipping Tool
function Start-SnippingTool {
    Write-Host "`n[+] Launching Snipping Tool..." -ForegroundColor Cyan

    $snipPath = "$env:SystemRoot\System32\SnippingTool.exe"
    $snipSketchPath = "$env:SystemRoot\SystemApps\Microsoft.ScreenSketch_8wekyb3d8bbwe\ScreenSketch.exe"

    if (Test-Path $snipSketchPath) {
        Start-Process $snipSketchPath
    }
    elseif (Test-Path $snipPath) {
        Start-Process $snipPath
    }
    else {
        Write-Host "[-] Snipping Tool is not available on this system." -ForegroundColor Red
    }

    Pause
}

# 22.  Open Task Manager
function Open-TaskManager {
    Write-Host "`n[+] Opening Task Manager..." -ForegroundColor Cyan

    Start-Process taskmgr.exe

    Pause
}

# 23. Main Menu
function Clear-Screen {
    Clear-Host
}

# 24. Event Log Viewer
function View-EventLogs {
    Write-Host "`n[+] Windows Event Log Viewer" -ForegroundColor Cyan
    Write-Host "x. System Logs" -ForegroundColor Green
    Write-Host "y. Application Logs" -ForegroundColor Green
    Write-Host "z. Security Logs" -ForegroundColor Green
    $choice = Read-Host "`nSelect log type" 

    switch ($choice) {
        x {
            Write-Host "`n[+] Fetching System Logs..." -ForegroundColor Yellow
            Get-WinEvent -LogName System -MaxEvents 20 | Format-Table TimeCreated, Id, LevelDisplayName, Message -Wrap -AutoSize
        }
        y {
            Write-Host "`n[+] Fetching Application Logs..." -ForegroundColor Yellow
            Get-WinEvent -LogName Application -MaxEvents 20 | Format-Table TimeCreated, Id, LevelDisplayName, Message -Wrap -AutoSize
        }
        z {
            Write-Host "`n[+] Fetching Security Logs..." -ForegroundColor Yellow
            Get-WinEvent -LogName Security -MaxEvents 20 | Format-Table TimeCreated, Id, LevelDisplayName, Message -Wrap -AutoSize
        }
        Default {
            Write-Host "[-] Invalid choice. Please Enter x,y,z" -ForegroundColor Red
        }
    }

    Pause
}


# 25. Exit handled in the loop

# Display Menu
function Show-Menu {
    Clear-Host
    Write-Host "`n========= SYSTEM TOOLKIT MENU BY AAQIB BAJWA =========" -ForegroundColor Cyan
    Write-Host "1.  Activate Windows" -ForegroundColor Green
    Write-Host "2.  Check for Windows Updates" -ForegroundColor Green
    Write-Host "3.  Run System Maintenance" -ForegroundColor Green
    Write-Host "4.  Show Installed Drivers" -ForegroundColor Green
    Write-Host "5.  Show System Drive Info" -ForegroundColor Green
    Write-Host "6.  Activate Microsoft Office" -ForegroundColor Green
    Write-Host "7.  Show MAC and IP Address" -ForegroundColor Green
    Write-Host "8.  Check Hardware Health" -ForegroundColor Green
    Write-Host "9.  Clear Temp/Junk Files" -ForegroundColor Green
    Write-Host "10. Run SFC and DISM Repair" -ForegroundColor Green
    Write-Host "11. Show Installed Applications" -ForegroundColor Green
	Write-Host "12. Show System Info" -ForegroundColor Green
	Write-Host "13. Network Speed Test" -ForegroundColor Green
	Write-Host "14. Battery Health Report-for laptops" -ForegroundColor Green
	Write-Host "15. System Uptime" -ForegroundColor Green
	Write-Host "16. List and Manage Running Services" -ForegroundColor Green
	Write-Host "17. Manage Startup Programs" -ForegroundColor Green
	Write-Host "18. Run Virus Scan" -ForegroundColor Green
	Write-Host "19. Network Status Check" -ForegroundColor Green
	Write-Host "20. Windows Defender Real-Time Protection Status" -ForegroundColor Green
	Write-Host "21. Launch Snipping Tool" -ForegroundColor Green
	Write-Host "22. Open Task Manager" -ForegroundColor Green
	Write-Host "23. Event Log Viewer" -ForegroundColor Green
	Write-Host "24. Main Menu" -ForegroundColor Yellow
    Write-Host "25. Exit" -ForegroundColor Red
    Write-Host "=====================================================" -ForegroundColor Cyan
}

# Main Loop
do {
    Show-Menu
    $choice = Read-Host "`nEnter your choice (1-25)"

    switch ($choice) {
        '1'  { Activate-Windows }
        '2'  { Check-WindowsUpdates }
        '3'  { Run-Maintenance }
        '4'  { Show-Drivers }
        '5'  { Show-Drives }
        '6'  { Activate-Office }
        '7'  { Show-NetworkDetails }
        '8'  { Check-HardwareStatus }
        '9'  { Clear-JunkFiles }
        '10' { Run-SystemRepair }
        '11' { Show-InstalledApps }
		'12' { Get-SystemInfo }
		'13' { Test-NetworkSpeed }
		'14' { Generate-BatteryReport }
		'15' { Show-SystemUptime }
		'16' { Manage-Services }
		'17' { Show-StartupPrograms }
		'18' { Run-VirusScan }
		'19' { Get-NetworkStatus }
		'20' { Get-DefenderRealtimeStatus }
		'21' { Start-SnippingTool }
		'22' { Open-TaskManager }
		'23' { View-EventLogs }
		'24' { Clear-Screen }
        '25' { Write-Host "`nExiting... Thank you!" -ForegroundColor Red; Exit }
        default {
            Write-Host "`nInvalid choice. Please select 1-25." -ForegroundColor Red
            Pause
        }
    }
} while ($true)
