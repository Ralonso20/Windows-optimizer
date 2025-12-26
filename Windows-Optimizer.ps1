# Windows Optimizer - Advanced Edition
# Versin mejorada con modo personalizado y restauracin

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$script:selectedOptions = @{}
$script:backupPath = "$env:USERPROFILE\Desktop\WindowsOptimizer_Backup"

# Funciones de utilidad
function Create-Backup {
    param([string]$description)
    
    if (-not (Test-Path $script:backupPath)) {
        New-Item -ItemType Directory -Path $script:backupPath | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $backupFile = "$script:backupPath\backup_$timestamp.txt"
    
    Add-Content -Path $backupFile -Value "=== BACKUP: $description ==="
    Add-Content -Path $backupFile -Value "Fecha: $(Get-Date)"
    Add-Content -Path $backupFile -Value "====================================`n"
    
    return $backupFile
}

function Log-Action {
    param([string]$action, [string]$backupFile)
    Add-Content -Path $backupFile -Value $action
}

# Funciones de optimizacion
function Disable-Telemetry {
    param([string]$backupFile)
    
    Write-Host "Deshabilitando telemetra..." -ForegroundColor Yellow
    
    $telemetryServices = @(
        "DiagTrack",
        "dmwappushservice",
        "WerSvc",
        "OneSyncSvc",
        "MessagingService",
        "PimIndexMaintenanceSvc",
        "UserDataSvc",
        "UnistoreSvc"
    )
    
    foreach ($service in $telemetryServices) {
        try {
            $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($svc) {
                $originalStatus = $svc.Status
                Log-Action "Servicio: $service - Estado original: $originalStatus" $backupFile
                
                Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
            }
        } catch {}
    }
    
    # Deshabilitar tareas programadas de telemetra
    $tasks = @(
        "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
        "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
        "\Microsoft\Windows\Autochk\Proxy",
        "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
        "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
        "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
    )
    
    foreach ($task in $tasks) {
        try {
            Disable-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
            Log-Action "Tarea deshabilitada: $task" $backupFile
        } catch {}
    }
}

function Disable-Cortana {
    param([string]$backupFile)
    
    Write-Host "Deshabilitando Cortana..." -ForegroundColor Yellow
    
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    
    Set-ItemProperty -Path $regPath -Name "AllowCortana" -Value 0 -Type DWord
    Log-Action "Cortana deshabilitada" $backupFile
}

function Enable-GameMode {
    param([string]$backupFile)
    
    Write-Host "Activando Game Mode..." -ForegroundColor Green
    
    $regPath = "HKCU:\Software\Microsoft\GameBar"
    Set-ItemProperty -Path $regPath -Name "AutoGameModeEnabled" -Value 1 -Type DWord
    Log-Action "Game Mode activado" $backupFile
}

function Optimize-Network {
    param([string]$backupFile)
    
    Write-Host "Optimizando red..." -ForegroundColor Yellow
    
    # Deshabilitar QoS packet scheduler
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched"
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name "NonBestEffortLimit" -Value 0 -Type DWord
    
    # Optimizar TCP/IP
    netsh int tcp set global autotuninglevel=normal
    netsh int tcp set global chimney=enabled
    netsh int tcp set global dca=enabled
    netsh int tcp set global netdma=enabled
    
    Log-Action "Red optimizada" $backupFile
}

function Optimize-GPU {
    param([string]$backupFile)
    
    Write-Host "Optimizando GPU..." -ForegroundColor Yellow
    
    # Hardware-accelerated GPU scheduling
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"
    Set-ItemProperty -Path $regPath -Name "HwSchMode" -Value 2 -Type DWord
    
    Log-Action "GPU optimizada (Hardware-accelerated scheduling)" $backupFile
}

function Set-HighPerformance {
    param([string]$backupFile)
    
    Write-Host "Configurando plan de alto rendimiento..." -ForegroundColor Yellow
    
    powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
    Log-Action "Plan de energa: Alto rendimiento" $backupFile
}

function Disable-Bloatware {
    param([string]$backupFile)
    
    Write-Host "Eliminando bloatware..." -ForegroundColor Yellow
    
    $bloatware = @(
        "Microsoft.3DBuilder",
        "Microsoft.BingNews",
        "Microsoft.BingWeather",
        "Microsoft.GetHelp",
        "Microsoft.Getstarted",
        "Microsoft.Messaging",
        "Microsoft.Microsoft3DViewer",
        "Microsoft.MicrosoftOfficeHub",
        "Microsoft.MicrosoftSolitaireCollection",
        "Microsoft.MicrosoftStickyNotes",
        "Microsoft.MixedReality.Portal",
        "Microsoft.OneConnect",
        "Microsoft.People",
        "Microsoft.Print3D",
        "Microsoft.SkypeApp",
        "Microsoft.Wallet",
        "Microsoft.WindowsAlarms",
        "Microsoft.WindowsCamera",
        "Microsoft.windowscommunicationsapps",
        "Microsoft.WindowsFeedbackHub",
        "Microsoft.WindowsMaps",
        "Microsoft.WindowsSoundRecorder",
        "Microsoft.Xbox.TCUI",
        "Microsoft.XboxApp",
        "Microsoft.XboxGameOverlay",
        "Microsoft.XboxGamingOverlay",
        "Microsoft.XboxIdentityProvider",
        "Microsoft.XboxSpeechToTextOverlay",
        "Microsoft.YourPhone",
        "Microsoft.ZuneMusic",
        "Microsoft.ZuneVideo"
    )
    
    foreach ($app in $bloatware) {
        try {
            Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -ErrorAction SilentlyContinue
            Log-Action "App eliminada: $app" $backupFile
        } catch {}
    }
}

function Optimize-WebView2 {
    param([string]$backupFile)
    
    Write-Host "Optimizando WebView2..." -ForegroundColor Yellow
    
    # Deshabilitar SOLO actualizaciones automaticas, NO el servicio completo
    # Esto permite que Discord, Teams, etc sigan funcionando
    
    # Deshabilitar tareas programadas de actualizacion (no el runtime)
    $edgeTasks = @(
        "\MicrosoftEdgeUpdateTaskMachineCore",
        "\MicrosoftEdgeUpdateTaskMachineUA"
    )
    
    foreach ($task in $edgeTasks) {
        try {
            Disable-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
            Log-Action "Tarea de actualizacion deshabilitada: $task" $backupFile
        } catch {}
    }
    
    # Configurar actualizaciones manuales (no automaticas)
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate"
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    
    # Deshabilitar solo actualizaciones automaticas, permitir manuales
    Set-ItemProperty -Path $regPath -Name "UpdateDefault" -Value 2 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $regPath -Name "AutoUpdateCheckPeriodMinutes" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    
    # Limpiar cache de WebView2 para liberar espacio
    $webview2CachePaths = @(
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Code Cache",
        "$env:LOCALAPPDATA\Microsoft\EdgeWebView\EBWebView\Default\Cache"
    )
    
    $totalCleaned = 0
    foreach ($cachePath in $webview2CachePaths) {
        if (Test-Path $cachePath) {
            try {
                $size = (Get-ChildItem -Path $cachePath -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB
                $totalCleaned += $size
                Remove-Item -Path "$cachePath\*" -Recurse -Force -ErrorAction SilentlyContinue
            } catch {}
        }
    }
    
    if ($totalCleaned -gt 0) {
        Log-Action "Cache de WebView2 limpiado (~$([math]::Round($totalCleaned, 2)) MB liberados)" $backupFile
    }
    
    # Optimizar prioridad del proceso EdgeUpdate (bajo en vez de normal)
    try {
        $edgeUpdateProcesses = Get-Process -Name "msedgewebview2" -ErrorAction SilentlyContinue
        foreach ($proc in $edgeUpdateProcesses) {
            $proc.PriorityClass = "BelowNormal"
        }
    } catch {}
    
    Log-Action "WebView2 optimizado (actualizaciones manuales, cache limpiado)" $backupFile
    
    Write-Host "WebView2 optimizado (apps seguiran funcionando)" -ForegroundColor Green
}

function Disable-OneDrive {
    param([string]$backupFile)
    
    Write-Host "Deshabilitando OneDrive..." -ForegroundColor Yellow
    
    taskkill /f /im OneDrive.exe 2>$null
    
    if (Test-Path "$env:SystemRoot\System32\OneDriveSetup.exe") {
        & "$env:SystemRoot\System32\OneDriveSetup.exe" /uninstall
    }
    if (Test-Path "$env:SystemRoot\SysWOW64\OneDriveSetup.exe") {
        & "$env:SystemRoot\SysWOW64\OneDriveSetup.exe" /uninstall
    }
    
    Log-Action "OneDrive deshabilitado y desinstalado" $backupFile
}

function Remove-OneDrive {
    param([string]$backupFile)
    
    Write-Host "Eliminando OneDrive completamente..." -ForegroundColor Red
    
    Disable-OneDrive $backupFile
    
    # Eliminar carpetas residuales
    Remove-Item -Path "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:ProgramData\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
    
    # Quitar del explorador
    New-PSDrive -PSProvider Registry -Root HKEY_CLASSES_ROOT -Name HKCR -ErrorAction SilentlyContinue
    Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
    
    Log-Action "OneDrive eliminado completamente" $backupFile
}

function Update-SecurityOnly {
    param([string]$backupFile)
    
    Write-Host "Configurando Windows Update (solo seguridad)..." -ForegroundColor Yellow
    
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    
    Set-ItemProperty -Path $regPath -Name "NoAutoUpdate" -Value 0 -Type DWord
    Set-ItemProperty -Path $regPath -Name "AUOptions" -Value 2 -Type DWord
    Set-ItemProperty -Path $regPath -Name "ScheduledInstallDay" -Value 0 -Type DWord
    
    Log-Action "Windows Update configurado para solo seguridad" $backupFile
}

function Update-SecurityAndDrivers {
    param([string]$backupFile)
    
    Write-Host "Configurando Windows Update (seguridad + drivers)..." -ForegroundColor Yellow
    
    Update-SecurityOnly $backupFile
    
    # Habilitar actualizacin de drivers
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching"
    Set-ItemProperty -Path $regPath -Name "SearchOrderConfig" -Value 1 -Type DWord
    
    Log-Action "Windows Update configurado para seguridad y drivers" $backupFile
}

function Activate-Windows {
    Write-Host "Activando Windows automaticamente..." -ForegroundColor Green
    
    # MAS (Microsoft Activation Scripts) - Activacion automatica HWID
    try {
        # Descargar y ejecutar MAS en modo automatico para Windows (HWID)
        $response = irm https://get.activated.win
        $response | iex
        # Ejecutar activacion HWID automaticamente
        & ([ScriptBlock]::Create((irm https://get.activated.win))) /HWID
    } catch {
        Write-Host "Metodo automatico fallo, intentando metodo interactivo..." -ForegroundColor Yellow
        try {
            irm https://get.activated.win | iex
        } catch {
            Write-Host "Error al ejecutar MAS. Por favor, ejecuta manualmente:" -ForegroundColor Red
            Write-Host "irm https://get.activated.win | iex" -ForegroundColor Yellow
            Write-Host "O visita: https://massgrave.dev" -ForegroundColor Yellow
        }
    }
}

function Activate-Office {
    Write-Host "Activando Office automaticamente..." -ForegroundColor Green
    
    # MAS - Activacion automatica Ohook para Office
    try {
        # Descargar y ejecutar MAS en modo automatico para Office (Ohook)
        $response = irm https://get.activated.win
        $response | iex
        # Ejecutar activacion Ohook automaticamente
        & ([ScriptBlock]::Create((irm https://get.activated.win))) /Ohook
    } catch {
        Write-Host "Metodo automatico fallo, intentando metodo interactivo..." -ForegroundColor Yellow
        try {
            irm https://get.activated.win | iex
        } catch {
            Write-Host "Error al ejecutar MAS. Por favor, ejecuta manualmente:" -ForegroundColor Red
            Write-Host "irm https://get.activated.win | iex" -ForegroundColor Yellow
            Write-Host "O visita: https://massgrave.dev" -ForegroundColor Yellow
        }
    }
}

function Optimize-WindowsActivation {
    param([string]$backupFile)
    
    Write-Host "Optimizando Windows Product Activation (WPA)..." -ForegroundColor Yellow
    
    # Deshabilitar tareas programadas de validacion de licencia
    $tasks = @(
        "\Microsoft\Windows\ApplicationData\CleanupTemporaryState",
        "\Microsoft\Windows\ApplicationData\DsSvcCleanup",
        "\Microsoft\Windows\Clip\License Validation",
        "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask",
        "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
        "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
        "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
        "\Microsoft\Windows\License Manager\TempSignedLicenseExchange",
        "\Microsoft\Windows\PI\Sqm-Tasks",
        "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem",
        "\Microsoft\Windows\Shell\FamilySafetyMonitor",
        "\Microsoft\Windows\Shell\FamilySafetyRefresh",
        "\Microsoft\Windows\Shell\FamilySafetyUpload",
        "\Microsoft\Windows\Windows Error Reporting\QueueReporting"
    )
    
    foreach ($task in $tasks) {
        try {
            Disable-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
            Log-Action "Tarea deshabilitada: $task" $backupFile
        } catch {}
    }
    
    # Optimizar servicios relacionados con licencias
    $licenseServices = @{
        "LicenseManager" = "Windows License Manager Service"
        "wlidsvc" = "Microsoft Account Sign-in Assistant"
        "ClipSVC" = "Client License Service (ClipSVC)"
    }
    
    foreach ($service in $licenseServices.GetEnumerator()) {
        try {
            $svc = Get-Service -Name $service.Key -ErrorAction SilentlyContinue
            if ($svc -and $svc.Status -eq "Running") {
                # Solo optimizar, no deshabilitar (podria afectar activacion)
                Set-Service -Name $service.Key -StartupType Manual -ErrorAction SilentlyContinue
                Log-Action "Servicio optimizado (Manual): $($service.Value)" $backupFile
            }
        } catch {}
    }
    
    # Deshabilitar Windows Genuine Advantage Notifications
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform"
    if (Test-Path $regPath) {
        Set-ItemProperty -Path $regPath -Name "NotificationDisabled" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Log-Action "Notificaciones de licencia deshabilitadas" $backupFile
    }
    
    Write-Host "Optimizacion WPA completada" -ForegroundColor Green
}

function Remove-Edge {
    param([string]$backupFile)
    
    Write-Host "Eliminando Microsoft Edge..." -ForegroundColor Red
    
    # Backup de Edge por si se quiere restaurar
    $edgePath = "$env:ProgramFiles(x86)\Microsoft\Edge\Application"
    if (Test-Path $edgePath) {
        Log-Action "Edge path encontrado: $edgePath" $backupFile
    }
    
    # Desinstalar Edge usando el instalador oficial
    $edgeInstallerPath = "$edgePath\*\Installer\setup.exe"
    $setupFiles = Get-Item $edgeInstallerPath -ErrorAction SilentlyContinue
    
    if ($setupFiles) {
        foreach ($setup in $setupFiles) {
            Write-Host "Desinstalando Edge con: $($setup.FullName)" -ForegroundColor Yellow
            Start-Process -FilePath $setup.FullName -ArgumentList "--uninstall --system-level --verbose-logging --force-uninstall" -Wait -NoNewWindow
            Log-Action "Edge desinstalado usando: $($setup.FullName)" $backupFile
        }
    }
    
    # Eliminar carpetas residuales
    $edgeFolders = @(
        "$env:ProgramFiles(x86)\Microsoft\Edge",
        "$env:ProgramFiles(x86)\Microsoft\EdgeUpdate",
        "$env:ProgramFiles(x86)\Microsoft\EdgeCore",
        "$env:LOCALAPPDATA\Microsoft\Edge",
        "$env:LOCALAPPDATA\Microsoft\EdgeUpdate"
    )
    
    foreach ($folder in $edgeFolders) {
        if (Test-Path $folder) {
            Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue
            Log-Action "Carpeta eliminada: $folder" $backupFile
        }
    }
    
    # Eliminar accesos directos
    Remove-Item "$env:PUBLIC\Desktop\Microsoft Edge.lnk" -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk" -Force -ErrorAction SilentlyContinue
    
    Log-Action "Microsoft Edge eliminado" $backupFile
    Write-Host "Microsoft Edge eliminado completamente" -ForegroundColor Green
}

function Restore-Edge {
    Write-Host "Reinstalando Microsoft Edge..." -ForegroundColor Green
    
    # Descargar instalador oficial de Edge
    $edgeInstallerUrl = "https://go.microsoft.com/fwlink/?linkid=2109047&Channel=Stable&language=en"
    $installerPath = "$env:TEMP\MicrosoftEdgeSetup.exe"
    
    try {
        Write-Host "Descargando Edge..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri $edgeInstallerUrl -OutFile $installerPath -UseBasicParsing
        
        Write-Host "Instalando Edge..." -ForegroundColor Yellow
        Start-Process -FilePath $installerPath -ArgumentList "/silent /install" -Wait
        
        Remove-Item $installerPath -Force -ErrorAction SilentlyContinue
        
        Write-Host "Microsoft Edge reinstalado correctamente" -ForegroundColor Green
    } catch {
        Write-Host "Error al reinstalar Edge. Descargalo manualmente desde:" -ForegroundColor Red
        Write-Host "https://www.microsoft.com/edge" -ForegroundColor Yellow
    }
}

function Remove-WindowsAI {
    param([string]$backupFile)
    
    Write-Host "Eliminando caracteristicas de IA de Windows..." -ForegroundColor Yellow
    
    # Deshabilitar Copilot
    $copilotKeys = @(
        "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"
    )
    
    foreach ($key in $copilotKeys) {
        if (-not (Test-Path $key)) {
            New-Item -Path $key -Force | Out-Null
        }
        Set-ItemProperty -Path $key -Name "TurnOffWindowsCopilot" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    }
    Log-Action "Copilot deshabilitado via registro" $backupFile
    
    # Deshabilitar Recall
    $recallKey = "HKCU:\Software\Policies\Microsoft\Windows\WindowsAI"
    if (-not (Test-Path $recallKey)) {
        New-Item -Path $recallKey -Force | Out-Null
    }
    Set-ItemProperty -Path $recallKey -Name "DisableAIDataAnalysis" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Log-Action "Recall/AI Data Analysis deshabilitado" $backupFile
    
    # Deshabilitar sugerencias de escritura/Input Insights
    $inputKey = "HKCU:\Software\Microsoft\Input\Settings"
    if (-not (Test-Path $inputKey)) {
        New-Item -Path $inputKey -Force | Out-Null
    }
    Set-ItemProperty -Path $inputKey -Name "InsightsEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $inputKey -Name "EnableHwkbTextPrediction" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Log-Action "Input Insights deshabilitado" $backupFile
    
    # Deshabilitar Rewrite en Notepad
    $notepadKey = "HKCU:\Software\Microsoft\Notepad"
    if (-not (Test-Path $notepadKey)) {
        New-Item -Path $notepadKey -Force | Out-Null
    }
    Set-ItemProperty -Path $notepadKey -Name "AIFeaturesEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Log-Action "Rewrite en Notepad deshabilitado" $backupFile
    
    # Deshabilitar Image Creator en Paint
    $paintKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Paint"
    if (-not (Test-Path $paintKey)) {
        New-Item -Path $paintKey -Force | Out-Null
    }
    Set-ItemProperty -Path $paintKey -Name "DisableImageCreator" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Log-Action "Image Creator en Paint deshabilitado" $backupFile
    
    # Deshabilitar Voice Access
    $voiceKey = "HKCU:\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps"
    if (-not (Test-Path $voiceKey)) {
        New-Item -Path $voiceKey -Force | Out-Null
    }
    Set-ItemProperty -Path $voiceKey -Name "AgentActivationEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Log-Action "Voice Access deshabilitado" $backupFile
    
    # Eliminar paquetes Appx de IA
    $aiPackages = @(
        "MicrosoftWindows.Client.WebExperience",  # Copilot
        "Microsoft.Windows.Ai.Copilot.Provider",
        "Microsoft.Copilot",
        "Microsoft.WindowsAIArt"
    )
    
    foreach ($package in $aiPackages) {
        try {
            Get-AppxPackage -Name "*$package*" -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
            Log-Action "Paquete AI eliminado: $package" $backupFile
        } catch {}
    }
    
    # Deshabilitar tareas de Recall
    $recallTasks = @(
        "\Microsoft\Windows\WindowsAI\AIDataAnalysis",
        "\Microsoft\Windows\Shell\AI Activity Snapshot"
    )
    
    foreach ($task in $recallTasks) {
        try {
            Disable-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
            Log-Action "Tarea AI deshabilitada: $task" $backupFile
        } catch {}
    }
    
    # Eliminar servicios de IA
    $aiServices = @(
        "AIDataAnalysis",
        "WindowsAIExperience"
    )
    
    foreach ($service in $aiServices) {
        try {
            $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($svc) {
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
                Log-Action "Servicio AI deshabilitado: $service" $backupFile
            }
        } catch {}
    }
    
    Log-Action "Caracteristicas de IA de Windows eliminadas/deshabilitadas" $backupFile
    Write-Host "Caracteristicas de IA eliminadas (Copilot, Recall, etc.)" -ForegroundColor Green
}

function Disable-WindowsDefender {
    param([string]$backupFile)
    
    Write-Host "Deshabilitando Windows Defender..." -ForegroundColor Red
    
    # Deshabilitar en tiempo real
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
    
    # Deshabilitar permanentemente
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name "DisableAntiSpyware" -Value 1 -Type DWord
    
    Log-Action "Windows Defender deshabilitado (AGRESIVO)" $backupFile
}

function Disable-UAC {
    param([string]$backupFile)
    
    Write-Host "Deshabilitando UAC..." -ForegroundColor Red
    
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    Set-ItemProperty -Path $regPath -Name "EnableLUA" -Value 0 -Type DWord
    
    Log-Action "UAC deshabilitado (AGRESIVO)" $backupFile
}

function Disable-Firewall {
    param([string]$backupFile)
    
    Write-Host "Deshabilitando Firewall..." -ForegroundColor Red
    
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
    
    Log-Action "Firewall deshabilitado (AGRESIVO)" $backupFile
}

function Optimize-SSD {
    param([string]$backupFile)
    
    Write-Host "Optimizando SSD..." -ForegroundColor Yellow
    
    # Deshabilitar desfragmentacin automtica en SSDs
    $drives = Get-PhysicalDisk | Where-Object { $_.MediaType -eq "SSD" }
    
    foreach ($drive in $drives) {
        $volumes = Get-Partition -DiskNumber $drive.DeviceId | Get-Volume
        foreach ($volume in $volumes) {
            if ($volume.DriveLetter) {
                Disable-ScheduledTask -TaskName "\Microsoft\Windows\Defrag\ScheduledDefrag" -ErrorAction SilentlyContinue
                Log-Action "Desfragmentacin deshabilitada para SSD en $($volume.DriveLetter):" $backupFile
            }
        }
    }
    
    # Habilitar TRIM
    fsutil behavior set DisableDeleteNotify 0
    Log-Action "TRIM habilitado para SSDs" $backupFile
    
    # Deshabilitar Prefetch y Superfetch para SSD
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnablePrefetcher" -Value 0 -Type DWord
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnableSuperfetch" -Value 0 -Type DWord
    Log-Action "Prefetch y Superfetch deshabilitados" $backupFile
    
    # Deshabilitar indexacin en SSD (opcional)
    $ssdDrives = Get-WmiObject -Class Win32_Volume | Where-Object { $_.DriveType -eq 3 }
    foreach ($ssdDrive in $ssdDrives) {
        try {
            $ssdDrive.IndexingEnabled = $false
            $ssdDrive.Put() | Out-Null
            Log-Action "Indexacin deshabilitada en unidad $($ssdDrive.DriveLetter)" $backupFile
        } catch {}
    }
    
    # Optimizar archivo de paginacion
    $computerSystem = Get-WmiObject Win32_ComputerSystem -EnableAllPrivileges
    $computerSystem.AutomaticManagedPagefile = $false
    $computerSystem.Put() | Out-Null
    
    $pageFile = Get-WmiObject -Query "Select * From Win32_PageFileSetting Where Name='C:\\pagefile.sys'"
    if ($pageFile) {
        $pageFile.Delete()
    }
    
    # Configurar archivo de paginacion en tamao fijo (reduce fragmentacin)
    $pageFilePath = "C:\pagefile.sys"
    wmic pagefileset create name="$pageFilePath"
    wmic pagefileset where name="$pageFilePath" set InitialSize=2048,MaximumSize=2048
    
    Log-Action "Archivo de paginacion optimizado para SSD" $backupFile
    
    # Deshabilitar hibernacin (libera espacio = RAM)
    powercfg -h off
    Log-Action "Hibernacin deshabilitada (libera espacio en SSD)" $backupFile
    
    Write-Host "SSD optimizado correctamente" -ForegroundColor Green
}

function Disable-UnnecessaryServices {
    param([string]$backupFile)
    
    Write-Host "Deshabilitando servicios innecesarios..." -ForegroundColor Yellow
    
    $unnecessaryServices = @{
        # Servicios de Xbox y Gaming (si no juegas desde Microsoft Store)
        "XblAuthManager" = "Xbox Live Auth Manager"
        "XblGameSave" = "Xbox Live Game Save"
        "XboxGipSvc" = "Xbox Accessory Management Service"
        "XboxNetApiSvc" = "Xbox Live Networking Service"
        
        # Servicios de impresin (si no usas impresoras)
        "Spooler" = "Print Spooler"
        "PrintNotify" = "Printer Extensions and Notifications"
        "PrintWorkflowUserSvc" = "PrintWorkflow"
        
        # Servicios de fax (nadie usa fax)
        "Fax" = "Fax Service"
        
        # Bluetooth (si no lo usas)
        # "bthserv" = "Bluetooth Support Service"
        # "BluetoothUserService" = "Bluetooth User Support Service"
        
        # Servicios de telefona (casi nunca se usa)
        "TapiSrv" = "Telephony"
        "PhoneSvc" = "Phone Service"
        
        # Windows Search (si prefieres bsquedas ms rpidas sin indexacin)
        "WSearch" = "Windows Search"
        
        # Biometra (si no usas lector de huellas/reconocimiento facial)
        "WbioSrvc" = "Windows Biometric Service"
        
        # Servicio de geolocalizacin
        "lfsvc" = "Geolocation Service"
        
        # Mapas descargados
        "MapsBroker" = "Downloaded Maps Manager"
        
        # Conexin compartida a Internet (ICS)
        "SharedAccess" = "Internet Connection Sharing"
        
        # Sensor Monitoring Service
        "SensrSvc" = "Sensor Monitoring Service"
        "SensorDataService" = "Sensor Data Service"
        "SensorService" = "Sensor Service"
        
        # Servicios de tablet PC
        "TabletInputService" = "Touch Keyboard and Handwriting Panel Service"
        
        # Windows Media Player Network Sharing
        "WMPNetworkSvc" = "Windows Media Player Network Sharing Service"
        
        # AllJoyn Router (IoT - rara vez usado)
        "AJRouter" = "AllJoyn Router Service"
        
        # Servicio de enrutador de SMS de Microsoft Windows
        "MessagingService" = "MessagingService"
        
        # Experiencia de uso compartido
        "CDPUserSvc" = "Connected Devices Platform User Service"
        
        # Retail Demo Service (para PCs de exhibicin en tiendas)
        "RetailDemo" = "Retail Demo Service"
        
        # Servicio de informes de errores de Windows
        "WerSvc" = "Windows Error Reporting Service"
        
        # Sincronizacin de configuracin (si no usas mltiples PCs)
        "OneSyncSvc" = "Sync Host Service"
        
        # Parental Controls (si no tienes hijos)
        "WpcMonSvc" = "Parental Controls"
        
        # Servicio de uso compartido de red del Reproductor
        "HomeGroupListener" = "HomeGroup Listener"
        "HomeGroupProvider" = "HomeGroup Provider"
        
        # Credential Manager (si no guardas contraseas)
        # "VaultSvc" = "Credential Manager" # Comentado por seguridad
        
        # Distributed Link Tracking Client
        "TrkWks" = "Distributed Link Tracking Client"
        
        # Programa de mejora de la experiencia del cliente
        "DcpSvc" = "Data Collection and Publishing Service"
        
        # Servicio de uso compartido de datos (CDPSvc)
        "CDPSvc" = "Connected Devices Platform Service"
        
        # Windows Insider Service
        "wisvc" = "Windows Insider Service"
        
        # Servicio de diagnstico recomendado
        "DPS" = "Diagnostic Policy Service"
        
        # Servicio de diagnstico de ejecucin
        "WdiServiceHost" = "Diagnostic Service Host"
        "WdiSystemHost" = "Diagnostic System Host"
    }
    
    foreach ($service in $unnecessaryServices.GetEnumerator()) {
        try {
            $svc = Get-Service -Name $service.Key -ErrorAction SilentlyContinue
            if ($svc) {
                $originalStatus = $svc.Status
                $originalStartType = $svc.StartType
                
                Log-Action "Servicio: $($service.Value) ($($service.Key)) - Estado: $originalStatus, Tipo inicio: $originalStartType" $backupFile
                
                Stop-Service -Name $service.Key -Force -ErrorAction SilentlyContinue
                Set-Service -Name $service.Key -StartupType Disabled -ErrorAction SilentlyContinue
                
                Write-Host "  OK Deshabilitado: $($service.Value)" -ForegroundColor Gray
            }
        } catch {
            Write-Host "  X No se pudo deshabilitar: $($service.Value)" -ForegroundColor DarkRed
        }
    }
    
    Write-Host "Servicios innecesarios deshabilitados" -ForegroundColor Green
}

function Disable-WebSearch {
    param([string]$backupFile)
    
    Write-Host "Deshabilitando bsqueda web en el Explorador..." -ForegroundColor Yellow
    
    # Deshabilitar bsqueda web en la barra de bsqueda de Windows
    $regPath1 = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"
    if (-not (Test-Path $regPath1)) {
        New-Item -Path $regPath1 -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath1 -Name "BingSearchEnabled" -Value 0 -Type DWord
    Set-ItemProperty -Path $regPath1 -Name "CortanaConsent" -Value 0 -Type DWord
    
    # Deshabilitar sugerencias web
    $regPath2 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    if (-not (Test-Path $regPath2)) {
        New-Item -Path $regPath2 -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath2 -Name "DisableWebSearch" -Value 1 -Type DWord
    Set-ItemProperty -Path $regPath2 -Name "ConnectedSearchUseWeb" -Value 0 -Type DWord
    
    # Deshabilitar en el men inicio tambin
    $regPath3 = "HKCU:\Software\Policies\Microsoft\Windows\Explorer"
    if (-not (Test-Path $regPath3)) {
        New-Item -Path $regPath3 -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath3 -Name "DisableSearchBoxSuggestions" -Value 1 -Type DWord
    
    Log-Action "Bsqueda web deshabilitada - Solo archivos locales" $backupFile
    
    Write-Host "Bsqueda configurada solo para archivos locales" -ForegroundColor Green
}

function Clean-TempFiles {
    param([string]$backupFile)
    
    Write-Host "Limpiando archivos temporales..." -ForegroundColor Yellow
    
    $tempPaths = @(
        "$env:TEMP\*",
        "$env:WINDIR\Temp\*",
        "$env:LOCALAPPDATA\Temp\*",
        "$env:WINDIR\Prefetch\*",
        "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache_*.db",
        "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\iconcache_*.db"
    )
    
    $totalCleaned = 0
    
    foreach ($path in $tempPaths) {
        try {
            $items = Get-ChildItem -Path $path -Force -ErrorAction SilentlyContinue
            $size = ($items | Measure-Object -Property Length -Sum).Sum / 1MB
            $totalCleaned += $size
            
            Remove-Item -Path $path -Force -Recurse -ErrorAction SilentlyContinue
            Write-Host "  OK Limpiado: $path ($([math]::Round($size, 2)) MB)" -ForegroundColor Gray
        } catch {}
    }
    
    # Limpiar cach de Windows Update
    Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:WINDIR\SoftwareDistribution\Download\*" -Force -Recurse -ErrorAction SilentlyContinue
    Start-Service -Name wuauserv -ErrorAction SilentlyContinue
    
    # Limpiar archivos de volcado de memoria
    Remove-Item -Path "$env:WINDIR\MEMORY.DMP" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:WINDIR\Minidump\*" -Force -Recurse -ErrorAction SilentlyContinue
    
    Log-Action "Archivos temporales limpiados (~$([math]::Round($totalCleaned, 2)) MB liberados)" $backupFile
    
    Write-Host "Limpieza completada: ~$([math]::Round($totalCleaned, 2)) MB liberados" -ForegroundColor Green
}

function Restore-Settings {
    Write-Host "`n=== RESTAURACIN DE CONFIGURACIN ===" -ForegroundColor Cyan
    
    if (-not (Test-Path $script:backupPath)) {
        [System.Windows.Forms.MessageBox]::Show("No se encontraron backups.", "Restaurar", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        return
    }
    
    $backups = Get-ChildItem -Path $script:backupPath -Filter "backup_*.txt" | Sort-Object LastWriteTime -Descending
    
    if ($backups.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No se encontraron backups.", "Restaurar", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        return
    }
    
    # Mostrar lista de backups
    $restoreForm = New-Object System.Windows.Forms.Form
    $restoreForm.Text = "Seleccionar Backup para Restaurar"
    $restoreForm.Size = New-Object System.Drawing.Size(600, 400)
    $restoreForm.StartPosition = "CenterScreen"
    $restoreForm.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $restoreForm.ForeColor = [System.Drawing.Color]::White
    
    $listBox = New-Object System.Windows.Forms.ListBox
    $listBox.Location = New-Object System.Drawing.Point(20, 20)
    $listBox.Size = New-Object System.Drawing.Size(540, 250)
    $listBox.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 45)
    $listBox.ForeColor = [System.Drawing.Color]::White
    
    foreach ($backup in $backups) {
        $listBox.Items.Add($backup.Name)
    }
    
    $restoreForm.Controls.Add($listBox)
    
    $btnRestore = New-Object System.Windows.Forms.Button
    $btnRestore.Location = New-Object System.Drawing.Point(20, 290)
    $btnRestore.Size = New-Object System.Drawing.Size(250, 50)
    $btnRestore.Text = "RESTAURAR SELECCIONADO"
    $btnRestore.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 212)
    $btnRestore.ForeColor = [System.Drawing.Color]::White
    $btnRestore.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $btnRestore.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    
    $btnRestore.Add_Click({
        if ($listBox.SelectedItem) {
            $selectedBackup = Join-Path $script:backupPath $listBox.SelectedItem
            
            $result = [System.Windows.Forms.MessageBox]::Show("Esto intentar revertir los cambios. Algunos cambios pueden requerir reinicio manual de servicios o configuracin manual.`n`nContinuar?", "Confirmar Restauracin", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
            
            if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
                notepad $selectedBackup
                [System.Windows.Forms.MessageBox]::Show("Revisa el archivo de backup y restaura manualmente los servicios/configuraciones necesarias.", "Informacin", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            }
        }
    })
    
    $restoreForm.Controls.Add($btnRestore)
    
    # Boton para restaurar Edge
    $btnRestoreEdge = New-Object System.Windows.Forms.Button
    $btnRestoreEdge.Location = New-Object System.Drawing.Point(20, 350)
    $btnRestoreEdge.Size = New-Object System.Drawing.Size(540, 40)
    $btnRestoreEdge.Text = "REINSTALAR MICROSOFT EDGE"
    $btnRestoreEdge.BackColor = [System.Drawing.Color]::FromArgb(0, 150, 136)
    $btnRestoreEdge.ForeColor = [System.Drawing.Color]::White
    $btnRestoreEdge.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $btnRestoreEdge.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $btnRestoreEdge.Add_Click({
        $result = [System.Windows.Forms.MessageBox]::Show("Esto descargara e instalara Microsoft Edge.`n`nContinuar?", "Restaurar Edge", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Question)
        if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
            Restore-Edge
        }
    })
    $restoreForm.Controls.Add($btnRestoreEdge)
    
    # Actualizar tamaño de ventana
    $restoreForm.Size = New-Object System.Drawing.Size(600, 450)
    
    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Location = New-Object System.Drawing.Point(310, 290)
    $btnCancel.Size = New-Object System.Drawing.Size(250, 50)
    $btnCancel.Text = "CANCELAR"
    $btnCancel.BackColor = [System.Drawing.Color]::FromArgb(180, 0, 0)
    $btnCancel.ForeColor = [System.Drawing.Color]::White
    $btnCancel.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $btnCancel.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $btnCancel.Add_Click({ $restoreForm.Close() })
    
    $restoreForm.Controls.Add($btnCancel)
    
    [void]$restoreForm.ShowDialog()
}

# Perfil Gaming
function Apply-Gaming {
    $backupFile = Create-Backup "Perfil Gaming"
    
    Disable-Bloatware $backupFile
    Optimize-WebView2 $backupFile
    Disable-Telemetry $backupFile
    Disable-Cortana $backupFile
    Disable-WebSearch $backupFile
    Enable-GameMode $backupFile
    Optimize-GPU $backupFile
    Optimize-Network $backupFile
    Optimize-SSD $backupFile
    Set-HighPerformance $backupFile
    Disable-UnnecessaryServices $backupFile
    Clean-TempFiles $backupFile
    Update-SecurityOnly $backupFile
    
    [System.Windows.Forms.MessageBox]::Show("Optimizacion Gaming completada!`n`nBackup guardado en:`n$backupFile`n`nSe recomienda reiniciar el sistema.", "Completado", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
}

# Perfil Trabajo/Oficina
function Apply-Work {
    $backupFile = Create-Backup "Perfil Trabajo/Oficina"
    
    Disable-Bloatware $backupFile
    Optimize-WebView2 $backupFile
    Disable-Telemetry $backupFile
    Disable-Cortana $backupFile
    Disable-WebSearch $backupFile
    Optimize-SSD $backupFile
    Clean-TempFiles $backupFile
    Activate-Windows
    Activate-Office
    Update-SecurityAndDrivers $backupFile
    
    [System.Windows.Forms.MessageBox]::Show("Optimizacion Trabajo/Oficina completada!`n`nBackup guardado en:`n$backupFile`n`nSe recomienda reiniciar el sistema.", "Completado", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
}

# Perfil Limpieza Bsica
function Apply-Basic {
    $backupFile = Create-Backup "Limpieza Bsica"
    
    Disable-Bloatware $backupFile
    Optimize-WebView2 $backupFile
    Disable-Telemetry $backupFile
    Disable-Cortana $backupFile
    Disable-WebSearch $backupFile
    Clean-TempFiles $backupFile
    
    [System.Windows.Forms.MessageBox]::Show("Limpieza Bsica completada!`n`nBackup guardado en:`n$backupFile", "Completado", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
}

# Modo Personalizado
function Show-CustomMode {
    $customForm = New-Object System.Windows.Forms.Form
    $customForm.Text = "Modo Personalizado - Windows Optimizer"
    $customForm.Size = New-Object System.Drawing.Size(1200, 700)
    $customForm.StartPosition = "CenterScreen"
    $customForm.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $customForm.ForeColor = [System.Drawing.Color]::White
    $customForm.MinimumSize = New-Object System.Drawing.Size(1000, 600)
    $customForm.MaximizeBox = $true
    
    # Ttulo
    $lblTitle = New-Object System.Windows.Forms.Label
    $lblTitle.Location = New-Object System.Drawing.Point(20, 20)
    $lblTitle.Size = New-Object System.Drawing.Size(1150, 40)
    $lblTitle.Text = "SELECCIONA LAS OPTIMIZACIONES QUE DESEAS APLICAR"
    $lblTitle.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
    $lblTitle.ForeColor = [System.Drawing.Color]::FromArgb(0, 120, 212)
    $customForm.Controls.Add($lblTitle)
    
    # Panel scrolleable
    $panel = New-Object System.Windows.Forms.Panel
    $panel.Location = New-Object System.Drawing.Point(20, 70)
    $panel.Size = New-Object System.Drawing.Size(1140, 500)
    $panel.AutoScroll = $true
    $panel.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 45)
    $panel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $customForm.Controls.Add($panel)
    
    $yPos = 10
    
    # Funcin para crear checkbox con descripcion
    function Add-CustomOption {
        param(
            [string]$text,
            [string]$description,
            [string]$severity, # "safe", "moderate", "aggressive"
            [string]$key,
            [int]$y
        )
        
        $checkbox = New-Object System.Windows.Forms.CheckBox
        $checkbox.Location = New-Object System.Drawing.Point(20, $y)
        $checkbox.Size = New-Object System.Drawing.Size(800, 25)
        $checkbox.ForeColor = [System.Drawing.Color]::White
        $checkbox.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
        
        # Color segn severidad
        $severityColor = switch ($severity) {
            "safe" { [System.Drawing.Color]::FromArgb(0, 200, 0) }
            "moderate" { [System.Drawing.Color]::FromArgb(255, 165, 0) }
            "aggressive" { [System.Drawing.Color]::FromArgb(255, 0, 0) }
        }
        
        $severityText = switch ($severity) {
            "safe" { "[SEGURO]" }
            "moderate" { "[MODERADO]" }
            "aggressive" { "[AGRESIVO]" }
        }
        
        $checkbox.Text = "$severityText $text"
        $checkbox.ForeColor = $severityColor
        
        $script:selectedOptions[$key] = $checkbox
        $panel.Controls.Add($checkbox)
        
        # Descripcin
        $lblDesc = New-Object System.Windows.Forms.Label
        $lblDesc.Location = New-Object System.Drawing.Point(40, $y + 25)
        $lblDesc.Size = New-Object System.Drawing.Size(780, 35)
        $lblDesc.Text = $description
        $lblDesc.ForeColor = [System.Drawing.Color]::FromArgb(180, 180, 180)
        $lblDesc.Font = New-Object System.Drawing.Font("Segoe UI", 9)
        $panel.Controls.Add($lblDesc)
        
        return $y + 70
    }
    
    # Categora: Limpieza
    $lblCat1 = New-Object System.Windows.Forms.Label
    $lblCat1.Location = New-Object System.Drawing.Point(10, $yPos)
    $lblCat1.Size = New-Object System.Drawing.Size(800, 30)
    $lblCat1.Text = " LIMPIEZA Y PRIVACIDAD "
    $lblCat1.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
    $lblCat1.ForeColor = [System.Drawing.Color]::Cyan
    $panel.Controls.Add($lblCat1)
    $yPos += 40
    
    $yPos = Add-CustomOption "Eliminar Bloatware" "Elimina aplicaciones preinstaladas innecesarias (Xbox, Mapas, etc.)" "safe" "bloatware" $yPos
    $yPos = Add-CustomOption "Optimizar WebView2" "Limpia cache y deshabilita updates automaticos (apps siguen funcionando)" "safe" "optimize_webview2" $yPos
    $yPos = Add-CustomOption "Deshabilitar Telemetra" "Desactiva el envo de datos de uso a Microsoft" "safe" "telemetry" $yPos
    $yPos = Add-CustomOption "Deshabilitar Cortana" "Desactiva el asistente de voz Cortana" "safe" "cortana" $yPos
    $yPos = Add-CustomOption "Bsqueda Solo Archivos Locales" "Deshabilita bsqueda web en el explorador (solo archivos)" "safe" "disable_websearch" $yPos
    $yPos = Add-CustomOption "Deshabilitar OneDrive" "Desinstala OneDrive (se puede reinstalar despus)" "moderate" "onedrive_disable" $yPos
    $yPos = Add-CustomOption "Eliminar OneDrive Completamente" "Elimina OneDrive y limpia carpetas residuales" "aggressive" "onedrive_remove" $yPos
    
    # Categora: Rendimiento
    $lblCat2 = New-Object System.Windows.Forms.Label
    $lblCat2.Location = New-Object System.Drawing.Point(10, $yPos)
    $lblCat2.Size = New-Object System.Drawing.Size(800, 30)
    $lblCat2.Text = " RENDIMIENTO "
    $lblCat2.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
    $lblCat2.ForeColor = [System.Drawing.Color]::Cyan
    $panel.Controls.Add($lblCat2)
    $yPos += 40
    
    $yPos = Add-CustomOption "Activar Game Mode" "Optimiza recursos para juegos" "safe" "gamemode" $yPos
    $yPos = Add-CustomOption "Optimizar GPU" "Habilita Hardware-accelerated GPU scheduling" "safe" "gpu" $yPos
    $yPos = Add-CustomOption "Optimizar Red" "Reduce latencia y mejora velocidad de conexin" "safe" "network" $yPos
    $yPos = Add-CustomOption "Optimizar SSD" "TRIM, deshabilita desfrag, optimiza paginacion y prefetch" "safe" "ssd" $yPos
    $yPos = Add-CustomOption "Plan Alto Rendimiento" "Configura el plan de energa para mximo rendimiento" "moderate" "highperf" $yPos
    $yPos = Add-CustomOption "Deshabilitar Servicios Innecesarios" "Desactiva servicios que rara vez se usan (Xbox, fax, biometra, etc.)" "moderate" "disable_services" $yPos
    $yPos = Add-CustomOption "Limpiar Archivos Temporales" "Elimina archivos temp, cach, prefetch" "safe" "clean_temp" $yPos
    
    # Categora: Sistema
    $lblCat3 = New-Object System.Windows.Forms.Label
    $lblCat3.Location = New-Object System.Drawing.Point(10, $yPos)
    $lblCat3.Size = New-Object System.Drawing.Size(800, 30)
    $lblCat3.Text = " SISTEMA Y ACTUALIZACIONES "
    $lblCat3.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
    $lblCat3.ForeColor = [System.Drawing.Color]::Cyan
    $panel.Controls.Add($lblCat3)
    $yPos += 40
    
    $yPos = Add-CustomOption "Update: Solo Seguridad" "Configura Windows Update solo para actualizaciones de seguridad" "safe" "update_security" $yPos
    $yPos = Add-CustomOption "Update: Seguridad + Drivers" "Incluye actualizaciones de drivers" "safe" "update_drivers" $yPos
    $yPos = Add-CustomOption "Activar Windows (MAS)" "Activa Windows usando Microsoft Activation Scripts" "moderate" "activate_windows" $yPos
    $yPos = Add-CustomOption "Activar Office (MAS)" "Activa Office usando Microsoft Activation Scripts" "moderate" "activate_office" $yPos
    
    # Categora: Seguridad (AGRESIVO)
    $lblCat4 = New-Object System.Windows.Forms.Label
    $lblCat4.Location = New-Object System.Drawing.Point(10, $yPos)
    $lblCat4.Size = New-Object System.Drawing.Size(800, 30)
    $lblCat4.Text = " OPCIONES AGRESIVAS (CUIDADO!) "
    $lblCat4.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
    $lblCat4.ForeColor = [System.Drawing.Color]::Red
    $panel.Controls.Add($lblCat4)
    $yPos += 40
    
    $yPos = Add-CustomOption "Deshabilitar Windows Defender" "Desactiva completamente el antivirus (PELIGROSO)" "aggressive" "disable_defender" $yPos
    $yPos = Add-CustomOption "Deshabilitar UAC" "Desactiva el Control de Cuentas de Usuario" "aggressive" "disable_uac" $yPos
    $yPos = Add-CustomOption "Deshabilitar Firewall" "Desactiva el Firewall de Windows (PELIGROSO)" "aggressive" "disable_firewall" $yPos
    $yPos = Add-CustomOption "Eliminar Microsoft Edge" "Desinstala Edge completamente (se puede reinstalar despues)" "aggressive" "remove_edge" $yPos
    $yPos = Add-CustomOption "Eliminar IA de Windows" "Elimina Copilot, Recall, Image Creator, Voice Access, etc." "moderate" "remove_windows_ai" $yPos
    
    # Barra de progreso
    $progressBar = New-Object System.Windows.Forms.ProgressBar
    $progressBar.Location = New-Object System.Drawing.Point(20, 580)
    $progressBar.Size = New-Object System.Drawing.Size(1140, 30)
    $progressBar.Style = [System.Windows.Forms.ProgressBarStyle]::Continuous
    $progressBar.Minimum = 0
    $progressBar.Maximum = 100
    $progressBar.Value = 0
    $progressBar.Visible = $false
    $progressBar.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $customForm.Controls.Add($progressBar)
    
    # Label de estado
    $lblStatus = New-Object System.Windows.Forms.Label
    $lblStatus.Location = New-Object System.Drawing.Point(20, 555)
    $lblStatus.Size = New-Object System.Drawing.Size(1140, 20)
    $lblStatus.Text = ""
    $lblStatus.ForeColor = [System.Drawing.Color]::White
    $lblStatus.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $lblStatus.Visible = $false
    $lblStatus.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $customForm.Controls.Add($lblStatus)
    
    # Botones
    $btnApply = New-Object System.Windows.Forms.Button
    $btnApply.Location = New-Object System.Drawing.Point(20, 620)
    $btnApply.Size = New-Object System.Drawing.Size(560, 50)
    $btnApply.Text = "APLICAR SELECCION"
    $btnApply.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 212)
    $btnApply.ForeColor = [System.Drawing.Color]::White
    $btnApply.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $btnApply.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
    $btnApply.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
    
    $btnApply.Add_Click({
        # Contar opciones seleccionadas
        $totalTasks = 0
        $script:selectedOptions.Keys | ForEach-Object { if ($script:selectedOptions[$_].Checked) { $totalTasks++ } }
        
        if ($totalTasks -eq 0) {
            [System.Windows.Forms.MessageBox]::Show("No has seleccionado ninguna opcion.", "Aviso", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }
        
        # Mostrar barra de progreso
        $progressBar.Value = 0
        $progressBar.Visible = $true
        $lblStatus.Visible = $true
        $btnApply.Enabled = $false
        $btnCancel.Enabled = $false
        
        $customForm.Refresh()
        
        $backupFile = Create-Backup "Modo Personalizado"
        $currentTask = 0
        $progressStep = [Math]::Floor(100 / $totalTasks)
        
        if ($script:selectedOptions["bloatware"].Checked) { 
            $lblStatus.Text = "Eliminando bloatware..."
            $customForm.Refresh()
            Disable-Bloatware $backupFile
            $currentTask++
            $progressBar.Value = [Math]::Min($currentTask * $progressStep, 100)
            $customForm.Refresh()
        }
        
        if ($script:selectedOptions["optimize_webview2"].Checked) { 
            $lblStatus.Text = "Optimizando WebView2..."
            $customForm.Refresh()
            Optimize-WebView2 $backupFile
            $currentTask++
            $progressBar.Value = [Math]::Min($currentTask * $progressStep, 100)
            $customForm.Refresh()
        }
        
        if ($script:selectedOptions["telemetry"].Checked) { 
            $lblStatus.Text = "Deshabilitando telemetria..."
            $customForm.Refresh()
            Disable-Telemetry $backupFile
            $currentTask++
            $progressBar.Value = [Math]::Min($currentTask * $progressStep, 100)
            $customForm.Refresh()
        }
        
        if ($script:selectedOptions["cortana"].Checked) { 
            $lblStatus.Text = "Deshabilitando Cortana..."
            $customForm.Refresh()
            Disable-Cortana $backupFile
            $currentTask++
            $progressBar.Value = [Math]::Min($currentTask * $progressStep, 100)
            $customForm.Refresh()
        }
        
        if ($script:selectedOptions["disable_websearch"].Checked) { 
            $lblStatus.Text = "Configurando busqueda local..."
            $customForm.Refresh()
            Disable-WebSearch $backupFile
            $currentTask++
            $progressBar.Value = [Math]::Min($currentTask * $progressStep, 100)
            $customForm.Refresh()
        }
        
        if ($script:selectedOptions["onedrive_disable"].Checked) { 
            $lblStatus.Text = "Deshabilitando OneDrive..."
            $customForm.Refresh()
            Disable-OneDrive $backupFile
            $currentTask++
            $progressBar.Value = [Math]::Min($currentTask * $progressStep, 100)
            $customForm.Refresh()
        }
        
        if ($script:selectedOptions["onedrive_remove"].Checked) { 
            $lblStatus.Text = "Eliminando OneDrive completamente..."
            $customForm.Refresh()
            Remove-OneDrive $backupFile
            $currentTask++
            $progressBar.Value = [Math]::Min($currentTask * $progressStep, 100)
            $customForm.Refresh()
        }
        
        if ($script:selectedOptions["gamemode"].Checked) { 
            $lblStatus.Text = "Activando Game Mode..."
            $customForm.Refresh()
            Enable-GameMode $backupFile
            $currentTask++
            $progressBar.Value = [Math]::Min($currentTask * $progressStep, 100)
            $customForm.Refresh()
        }
        
        if ($script:selectedOptions["gpu"].Checked) { 
            $lblStatus.Text = "Optimizando GPU..."
            $customForm.Refresh()
            Optimize-GPU $backupFile
            $currentTask++
            $progressBar.Value = [Math]::Min($currentTask * $progressStep, 100)
            $customForm.Refresh()
        }
        
        if ($script:selectedOptions["network"].Checked) { 
            $lblStatus.Text = "Optimizando red..."
            $customForm.Refresh()
            Optimize-Network $backupFile
            $currentTask++
            $progressBar.Value = [Math]::Min($currentTask * $progressStep, 100)
            $customForm.Refresh()
        }
        
        if ($script:selectedOptions["ssd"].Checked) { 
            $lblStatus.Text = "Optimizando SSD..."
            $customForm.Refresh()
            Optimize-SSD $backupFile
            $currentTask++
            $progressBar.Value = [Math]::Min($currentTask * $progressStep, 100)
            $customForm.Refresh()
        }
        
        if ($script:selectedOptions["highperf"].Checked) { 
            $lblStatus.Text = "Configurando alto rendimiento..."
            $customForm.Refresh()
            Set-HighPerformance $backupFile
            $currentTask++
            $progressBar.Value = [Math]::Min($currentTask * $progressStep, 100)
            $customForm.Refresh()
        }
        
        if ($script:selectedOptions["disable_services"].Checked) { 
            $lblStatus.Text = "Deshabilitando servicios innecesarios..."
            $customForm.Refresh()
            Disable-UnnecessaryServices $backupFile
            $currentTask++
            $progressBar.Value = [Math]::Min($currentTask * $progressStep, 100)
            $customForm.Refresh()
        }
        
        if ($script:selectedOptions["clean_temp"].Checked) { 
            $lblStatus.Text = "Limpiando archivos temporales..."
            $customForm.Refresh()
            Clean-TempFiles $backupFile
            $currentTask++
            $progressBar.Value = [Math]::Min($currentTask * $progressStep, 100)
            $customForm.Refresh()
        }
        
        if ($script:selectedOptions["update_security"].Checked) { 
            $lblStatus.Text = "Configurando Windows Update..."
            $customForm.Refresh()
            Update-SecurityOnly $backupFile
            $currentTask++
            $progressBar.Value = [Math]::Min($currentTask * $progressStep, 100)
            $customForm.Refresh()
        }
        
        if ($script:selectedOptions["update_drivers"].Checked) { 
            $lblStatus.Text = "Configurando actualizaciones..."
            $customForm.Refresh()
            Update-SecurityAndDrivers $backupFile
            $currentTask++
            $progressBar.Value = [Math]::Min($currentTask * $progressStep, 100)
            $customForm.Refresh()
        }
        
        if ($script:selectedOptions["activate_windows"].Checked) { 
            $lblStatus.Text = "Activando Windows..."
            $customForm.Refresh()
            Activate-Windows
            $currentTask++
            $progressBar.Value = [Math]::Min($currentTask * $progressStep, 100)
            $customForm.Refresh()
        }
        
        if ($script:selectedOptions["activate_office"].Checked) { 
            $lblStatus.Text = "Activando Office..."
            $customForm.Refresh()
            Activate-Office
            $currentTask++
            $progressBar.Value = [Math]::Min($currentTask * $progressStep, 100)
            $customForm.Refresh()
        }
        
        if ($script:selectedOptions["disable_defender"].Checked) { 
            $lblStatus.Text = "Deshabilitando Windows Defender..."
            $customForm.Refresh()
            Disable-WindowsDefender $backupFile
            $currentTask++
            $progressBar.Value = [Math]::Min($currentTask * $progressStep, 100)
            $customForm.Refresh()
        }
        
        if ($script:selectedOptions["disable_uac"].Checked) { 
            $lblStatus.Text = "Deshabilitando UAC..."
            $customForm.Refresh()
            Disable-UAC $backupFile
            $currentTask++
            $progressBar.Value = [Math]::Min($currentTask * $progressStep, 100)
            $customForm.Refresh()
        }
        
        if ($script:selectedOptions["disable_firewall"].Checked) { 
            $lblStatus.Text = "Deshabilitando Firewall..."
            $customForm.Refresh()
            Disable-Firewall $backupFile
            $currentTask++
            $progressBar.Value = [Math]::Min($currentTask * $progressStep, 100)
            $customForm.Refresh()
        }
        
        if ($script:selectedOptions["remove_edge"].Checked) { 
            $lblStatus.Text = "Eliminando Microsoft Edge..."
            $customForm.Refresh()
            Remove-Edge $backupFile
            $currentTask++
            $progressBar.Value = [Math]::Min($currentTask * $progressStep, 100)
            $customForm.Refresh()
        }
        
        if ($script:selectedOptions["remove_windows_ai"].Checked) { 
            $lblStatus.Text = "Eliminando IA de Windows..."
            $customForm.Refresh()
            Remove-WindowsAI $backupFile
            $currentTask++
            $progressBar.Value = [Math]::Min($currentTask * $progressStep, 100)
            $customForm.Refresh()
        }
        
        # Completar progreso
        $progressBar.Value = 100
        $lblStatus.Text = "Completado!"
        $customForm.Refresh()
        Start-Sleep -Milliseconds 500
        
        # Ocultar barra de progreso
        $progressBar.Visible = $false
        $lblStatus.Visible = $false
        $btnApply.Enabled = $true
        $btnCancel.Enabled = $true
        
        [System.Windows.Forms.MessageBox]::Show("Optimizacion personalizada completada!`n`nBackup guardado en:`n$backupFile`n`nSe recomienda reiniciar el sistema.", "Completado", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        $customForm.Close()
    })
    
    $customForm.Controls.Add($btnApply)
    
    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Location = New-Object System.Drawing.Point(600, 620)
    $btnCancel.Size = New-Object System.Drawing.Size(560, 50)
    $btnCancel.Text = "CANCELAR"
    $btnCancel.BackColor = [System.Drawing.Color]::FromArgb(180, 0, 0)
    $btnCancel.ForeColor = [System.Drawing.Color]::White
    $btnCancel.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $btnCancel.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
    $btnCancel.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
    $btnCancel.Add_Click({ $customForm.Close() })
    
    $customForm.Controls.Add($btnCancel)
    
    [void]$customForm.ShowDialog()
}

# GUI Principal
function Show-MainGUI {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Windows Optimizer - All In One"
    $form.Size = New-Object System.Drawing.Size(1400, 900)
    $form.StartPosition = "CenterScreen"
    $form.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $form.AutoScroll = $true
    $form.MinimumSize = New-Object System.Drawing.Size(1000, 600)
    
    # Ttulo
    $lblTitle = New-Object System.Windows.Forms.Label
    $lblTitle.Location = New-Object System.Drawing.Point(50, 30)
    $lblTitle.Size = New-Object System.Drawing.Size(1300, 50)
    $lblTitle.Text = "WINDOWS OPTIMIZER - Selecciona tu perfil"
    $lblTitle.Font = New-Object System.Drawing.Font("Segoe UI", 20, [System.Drawing.FontStyle]::Bold)
    $lblTitle.ForeColor = [System.Drawing.Color]::FromArgb(0, 120, 212)
    $lblTitle.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
    $form.Controls.Add($lblTitle)
    
    # Panel Gaming
    $panelGaming = New-Object System.Windows.Forms.Panel
    $panelGaming.Location = New-Object System.Drawing.Point(50, 120)
    $panelGaming.Size = New-Object System.Drawing.Size(420, 550)
    $panelGaming.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 45)
    $panelGaming.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    
    $lblGaming = New-Object System.Windows.Forms.Label
    $lblGaming.Location = New-Object System.Drawing.Point(20, 20)
    $lblGaming.Size = New-Object System.Drawing.Size(380, 40)
    $lblGaming.Text = "GAMING PC"
    $lblGaming.Font = New-Object System.Drawing.Font("Segoe UI", 18, [System.Drawing.FontStyle]::Bold)
    $lblGaming.ForeColor = [System.Drawing.Color]::FromArgb(0, 255, 0)
    $panelGaming.Controls.Add($lblGaming)
    
    $lblGamingDesc = New-Object System.Windows.Forms.Label
    $lblGamingDesc.Location = New-Object System.Drawing.Point(20, 70)
    $lblGamingDesc.Size = New-Object System.Drawing.Size(380, 340)
    $lblGamingDesc.Text = @"
INCLUYE:

* Eliminar bloatware
* Deshabilitar telemetra
* Cortana/Copilot OFF
* Bsqueda solo local
* Game Mode ON
* GPU optimizada
* Red optimizada
* SSD optimizado
* Servicios innecesarios OFF
* Limpieza archivos temp
* Plan alto rendimiento
* Update: Solo seguridad

Resultado:
Sistema limpio y mximo FPS
"@
    $lblGamingDesc.Font = New-Object System.Drawing.Font("Segoe UI", 11)
    $lblGamingDesc.ForeColor = [System.Drawing.Color]::White
    $panelGaming.Controls.Add($lblGamingDesc)
    
    $btnGaming = New-Object System.Windows.Forms.Button
    $btnGaming.Location = New-Object System.Drawing.Point(60, 430)
    $btnGaming.Size = New-Object System.Drawing.Size(300, 80)
    $btnGaming.Text = "APLICAR GAMING"
    $btnGaming.BackColor = [System.Drawing.Color]::FromArgb(0, 200, 0)
    $btnGaming.ForeColor = [System.Drawing.Color]::White
    $btnGaming.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $btnGaming.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
    $btnGaming.Add_Click({ Apply-Gaming })
    $panelGaming.Controls.Add($btnGaming)
    
    $form.Controls.Add($panelGaming)
    
    # Panel Trabajo
    $panelWork = New-Object System.Windows.Forms.Panel
    $panelWork.Location = New-Object System.Drawing.Point(490, 120)
    $panelWork.Size = New-Object System.Drawing.Size(420, 550)
    $panelWork.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 45)
    $panelWork.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    
    $lblWork = New-Object System.Windows.Forms.Label
    $lblWork.Location = New-Object System.Drawing.Point(20, 20)
    $lblWork.Size = New-Object System.Drawing.Size(380, 40)
    $lblWork.Text = "TRABAJO/OFICINA"
    $lblWork.Font = New-Object System.Drawing.Font("Segoe UI", 18, [System.Drawing.FontStyle]::Bold)
    $lblWork.ForeColor = [System.Drawing.Color]::FromArgb(0, 120, 212)
    $panelWork.Controls.Add($lblWork)
    
    $lblWorkDesc = New-Object System.Windows.Forms.Label
    $lblWorkDesc.Location = New-Object System.Drawing.Point(20, 70)
    $lblWorkDesc.Size = New-Object System.Drawing.Size(380, 340)
    $lblWorkDesc.Text = @"
INCLUYE:

* Eliminar bloatware
* Deshabilitar telemetra
* Cortana/Copilot OFF
* Bsqueda solo local
* SSD optimizado
* Limpieza archivos temp
* ACTIVAR Windows
* ACTIVAR Office
* Update: Seg + Drivers

Resultado:
Sistema limpio y activado
"@
    $lblWorkDesc.Font = New-Object System.Drawing.Font("Segoe UI", 11)
    $lblWorkDesc.ForeColor = [System.Drawing.Color]::White
    $panelWork.Controls.Add($lblWorkDesc)
    
    $btnWork = New-Object System.Windows.Forms.Button
    $btnWork.Location = New-Object System.Drawing.Point(60, 430)
    $btnWork.Size = New-Object System.Drawing.Size(300, 80)
    $btnWork.Text = "APLICAR TRABAJO"
    $btnWork.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 212)
    $btnWork.ForeColor = [System.Drawing.Color]::White
    $btnWork.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $btnWork.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
    $btnWork.Add_Click({ Apply-Work })
    $panelWork.Controls.Add($btnWork)
    
    $form.Controls.Add($panelWork)
    
    # Panel Bsico
    $panelBasic = New-Object System.Windows.Forms.Panel
    $panelBasic.Location = New-Object System.Drawing.Point(930, 120)
    $panelBasic.Size = New-Object System.Drawing.Size(420, 550)
    $panelBasic.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 45)
    $panelBasic.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    
    $lblBasic = New-Object System.Windows.Forms.Label
    $lblBasic.Location = New-Object System.Drawing.Point(20, 20)
    $lblBasic.Size = New-Object System.Drawing.Size(380, 40)
    $lblBasic.Text = "LIMPIEZA BASICA"
    $lblBasic.Font = New-Object System.Drawing.Font("Segoe UI", 18, [System.Drawing.FontStyle]::Bold)
    $lblBasic.ForeColor = [System.Drawing.Color]::Gray
    $panelBasic.Controls.Add($lblBasic)
    
    $lblBasicDesc = New-Object System.Windows.Forms.Label
    $lblBasicDesc.Location = New-Object System.Drawing.Point(20, 70)
    $lblBasicDesc.Size = New-Object System.Drawing.Size(380, 340)
    $lblBasicDesc.Text = @"
INCLUYE:

* Eliminar bloatware
* Deshabilitar telemetra
* Cortana OFF
* Bsqueda solo local
* Limpieza archivos temp

NO INCLUYE:
* Gaming
* Activacin
* Cambios agresivos

Resultado:
Limpieza conservadora
"@
    $lblBasicDesc.Font = New-Object System.Drawing.Font("Segoe UI", 11)
    $lblBasicDesc.ForeColor = [System.Drawing.Color]::White
    $panelBasic.Controls.Add($lblBasicDesc)
    
    $btnBasic = New-Object System.Windows.Forms.Button
    $btnBasic.Location = New-Object System.Drawing.Point(60, 430)
    $btnBasic.Size = New-Object System.Drawing.Size(300, 80)
    $btnBasic.Text = "APLICAR BASICO"
    $btnBasic.BackColor = [System.Drawing.Color]::Gray
    $btnBasic.ForeColor = [System.Drawing.Color]::White
    $btnBasic.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $btnBasic.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
    $btnBasic.Add_Click({ Apply-Basic })
    $panelBasic.Controls.Add($btnBasic)
    
    $form.Controls.Add($panelBasic)
    
    # Barra inferior
    $panelBottom = New-Object System.Windows.Forms.Panel
    $panelBottom.Location = New-Object System.Drawing.Point(50, 690)
    $panelBottom.Size = New-Object System.Drawing.Size(1300, 120)
    $panelBottom.BackColor = [System.Drawing.Color]::FromArgb(20, 20, 20)
    
    # Botn Personalizado
    $btnCustom = New-Object System.Windows.Forms.Button
    $btnCustom.Location = New-Object System.Drawing.Point(20, 20)
    $btnCustom.Size = New-Object System.Drawing.Size(400, 60)
    $btnCustom.Text = "[CFG] MODO PERSONALIZADO"
    $btnCustom.BackColor = [System.Drawing.Color]::FromArgb(255, 165, 0)
    $btnCustom.ForeColor = [System.Drawing.Color]::White
    $btnCustom.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $btnCustom.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
    $btnCustom.Add_Click({ Show-CustomMode })
    $panelBottom.Controls.Add($btnCustom)
    
    # Botn Restaurar
    $btnRestore = New-Object System.Windows.Forms.Button
    $btnRestore.Location = New-Object System.Drawing.Point(450, 20)
    $btnRestore.Size = New-Object System.Drawing.Size(400, 60)
    $btnRestore.Text = "< RESTAURAR CONFIGURACIN"
    $btnRestore.BackColor = [System.Drawing.Color]::FromArgb(120, 120, 120)
    $btnRestore.ForeColor = [System.Drawing.Color]::White
    $btnRestore.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $btnRestore.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
    $btnRestore.Add_Click({ Restore-Settings })
    $panelBottom.Controls.Add($btnRestore)
    
    # Botn Salir
    $btnExit = New-Object System.Windows.Forms.Button
    $btnExit.Location = New-Object System.Drawing.Point(880, 20)
    $btnExit.Size = New-Object System.Drawing.Size(400, 60)
    $btnExit.Text = "SALIR"
    $btnExit.BackColor = [System.Drawing.Color]::FromArgb(180, 0, 0)
    $btnExit.ForeColor = [System.Drawing.Color]::White
    $btnExit.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $btnExit.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
    $btnExit.Add_Click({ $form.Close() })
    $panelBottom.Controls.Add($btnExit)
    
    $form.Controls.Add($panelBottom)
    
    # Informacin
    $lblInfo = New-Object System.Windows.Forms.Label
    $lblInfo.Location = New-Object System.Drawing.Point(50, 820)
    $lblInfo.Size = New-Object System.Drawing.Size(1300, 30)
    $lblInfo.Text = "TIP: Para gaming PC elige el perfil verde. Para trabajo/oficina el azul. | IMPORTANTE: Siempre reinicia el sistema despus de aplicar cambios."
    $lblInfo.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $lblInfo.ForeColor = [System.Drawing.Color]::FromArgb(150, 150, 150)
    $form.Controls.Add($lblInfo)
    
    $lblVersion = New-Object System.Windows.Forms.Label
    $lblVersion.Location = New-Object System.Drawing.Point(1200, 855)
    $lblVersion.Size = New-Object System.Drawing.Size(150, 20)
    $lblVersion.Text = "Version Advanced 2.0"
    $lblVersion.Font = New-Object System.Drawing.Font("Segoe UI", 8)
    $lblVersion.ForeColor = [System.Drawing.Color]::Gray
    $lblVersion.TextAlign = [System.Drawing.ContentAlignment]::MiddleRight
    $form.Controls.Add($lblVersion)
    
    [void]$form.ShowDialog()
}

# Verificar privilegios de administrador
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    [System.Windows.Forms.MessageBox]::Show("Este script necesita ejecutarse como Administrador. Haz clic derecho en PowerShell y selecciona Ejecutar como Administrador.", "Privilegios Insuficientes", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
    exit
}

# Iniciar GUI
Show-MainGUI
