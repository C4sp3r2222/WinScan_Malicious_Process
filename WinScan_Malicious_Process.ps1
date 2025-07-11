# Powershell Script By Rubén Guerrero Muñoz. 2025


Write-Host @"
==================================================================
   Script de Analisis de Conexiones TCP y Procesos Asociados
   - Detecta procesos legitimos, sospechosos y maliciosos
   - Muestra detalles utiles para pentesting y analisis forense
   - Reporta IPs externas conectadas para procesos maliciosos
   - Exporta resultados a CSV en el escritorio
   - NOTA: Debe ejecutarse con permisos de root

   EJECUCION: 
   .\analisis_tcp2.ps1 -sospechosos
==================================================================
"@ -ForegroundColor Cyan

[int]$countLegitimo = 0
[int]$countSospechoso = 0
[int]$countMalicioso = 0

$resultados = @()

$connections = netstat -ano | Select-String "^  TCP" | ForEach-Object {
    $parts = ($_ -replace "\s+", " ").Trim().Split(" ")
    [PSCustomObject]@{
        LocalAddress  = $parts[1]
        RemoteAddress = $parts[2].Split(":")[0]
        Port          = $parts[2].Split(":")[1]
        State         = $parts[3]
        PID           = $parts[4]
    }
}

# Filtrar conexiones con PID únicos, excluyendo PID=0 y conexiones locales
$uniqueConns = $connections |
    Where-Object { $_.PID -ne 0 } |
    Where-Object { $_.RemoteAddress -ne "0.0.0.0" -and $_.RemoteAddress -ne "127.0.0.1" -and $_.RemoteAddress -notlike "192.168.*" } |
    Sort-Object PID -Unique

function Get-ProcesoInfo {
    param($procId)
    $info = @{
        UserName      = "Desconocido"
        CommandLine   = "Desconocido"
        StartTime     = "Desconocido"
    }

    try {
        $wmiProc = Get-CimInstance Win32_Process -Filter "ProcessId=$procId"
        if ($wmiProc) {
            $info.CommandLine = $wmiProc.CommandLine
            $info.StartTime = $wmiProc.CreationDate
            $owner = $wmiProc.GetOwner()
            if ($owner.ReturnValue -eq 0) {
                $info.UserName = "$($owner.Domain)\$($owner.User)"
            }
        }
    } catch {}

    try {
        $proc = Get-Process -Id $procId -ErrorAction Stop
        $info.StartTime = $proc.StartTime
    } catch {}

    return $info
}

foreach ($conn in $uniqueConns) {
    $procId = $conn.PID
    $remoteIP = $conn.RemoteAddress

    try {
        $proc = Get-Process -Id $procId -ErrorAction Stop
    } catch {
        continue
    }

    $path = "Desconocido"
    try {
        $wmiProc = Get-CimInstance Win32_Process -Filter "ProcessId=$procId"
        if ($wmiProc -and $wmiProc.ExecutablePath) {
            $path = $wmiProc.ExecutablePath
        }
    } catch {}

    $name = $proc.Name

    $category = "Sospechoso"
    $color = "DarkYellow"

    if ($path -match "\\Windows\\System32\\.*svchost\.exe$" -or
        $path -match "\\Program Files" -or
        $path -match "\\Windows\\System32") {
        $category = "Legitimo"
        $color = "Green"
        $countLegitimo++
    } elseif ($path -match "AppData" -or $path -match "Temp" -or $path -eq "Desconocido") {
        $category = "Malicioso"
        $color = "Red"
        $countMalicioso++
    } else {
        $countSospechoso++
    }

    $procInfo = Get-ProcesoInfo -procId $procId

    Write-Host "`nAnalisis de PID ${procId}:" -ForegroundColor White
    Write-Host "  Nombre        : ${name}" -ForegroundColor White
    Write-Host "  Ejecutable    : ${path}" -ForegroundColor White
    Write-Host "  Usuario      : $($procInfo.UserName)" -ForegroundColor White
    Write-Host "  Fecha Inicio : $($procInfo.StartTime)" -ForegroundColor White
    Write-Host "  Args         : $($procInfo.CommandLine)" -ForegroundColor White
    Write-Host "  Reputacion   : ${category}" -ForegroundColor $color

    if ($category -eq "Malicioso") {
        Write-Host "  IP Externa Conectada: $remoteIP" -ForegroundColor Red
        Write-Host "  --> Recomendacion: Investigar ruta y comandos, verificar firma digital y uso en sistema." -ForegroundColor Red
        Write-Host "      Si es malicioso, terminar proceso y eliminar ejecutable." -ForegroundColor Red
    }

    Write-Host "`n------------------------------------------------------------------`n"

    $resultados += [PSCustomObject]@{
        PID           = $procId
        Nombre        = $name
        Ejecutable    = $path
        Usuario       = $procInfo.UserName
        FechaInicio   = $procInfo.StartTime
        Argumentos    = $procInfo.CommandLine
        Reputacion    = $category
        IP_Externa    = if ($category -eq "Malicioso") { $remoteIP } else { "" }
        Estado        = $conn.State
        Puerto        = $conn.Port
    }
}

$exportPath = "$env:USERPROFILE\Desktop\analisis_tcp_resultados.csv"
$resultados | Export-Csv -Path $exportPath -NoTypeInformation -Encoding UTF8

Write-Host "`nAnalisis finalizado." -ForegroundColor Cyan
Write-Host "Legitimos : $countLegitimo" -ForegroundColor Green
Write-Host "Sospechosos: $countSospechoso" -ForegroundColor Yellow
Write-Host "Maliciosos: $countMalicioso" -ForegroundColor Red
Write-Host "Resultados exportados a: $exportPath" -ForegroundColor Cyan
