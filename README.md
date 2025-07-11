============================================================
 HERRAMIENTA DE ANALISIS DE CONEXIONES TCP EN WINDOWS
============================================================

Descripcion:
------------
Este script en PowerShell permite analizar las conexiones TCP activas en un sistema Windows y obtener informacion detallada de los procesos asociados.
Es especialmente util para analistas de seguridad, administradores de sistemas y pentesters que deseen identificar procesos maliciosos, sospechosos o legitimos en tiempo real.

Funciones principales:
----------------------
- Analiza conexiones TCP activas (PID unico).
- Filtra procesos con PID 0 y conexiones locales.
- Muestra:
   * Nombre del proceso
   * Ruta del ejecutable
   * Usuario propietario
   * Fecha de inicio del proceso
   * Argumentos de ejecucion
   * IP externa conectada (si aplica)
   * Estado y puerto TCP
- Clasifica el proceso como:
   * Legitimo (verde)
   * Sospechoso (amarillo)
   * Malicioso (rojo)
- Exporta los resultados en formato .CSV al escritorio.
- Colores en consola para facilitar la visualizacion.

Requisitos:
-----------
- Windows con PowerShell 5.0 o superior
- Permisos para ejecutar scripts:
  Puedes usar el siguiente comando antes de ejecutarlo:
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

Uso:
----
1. Guarda el script como "WinScan_Malicious_Process.ps1"
2. Abre PowerShell como administrador.
3. Ejecuta el script con:
    .\WinScan_Malicious_Process.ps1

4. Al finalizar, revisa los resultados exportados en:
   %USERPROFILE%\Desktop\analisis_tcp_resultados.csv

Notas:
------
- Este script no requiere herramientas externas.
- No analiza protocolos distintos de TCP (por ahora).
- Puede personalizarse para conectarse a motores de reputacion online.
- Puedes integrarlo en procesos de monitoreo o respuesta ante incidentes.

Autor:
------
Rubén Guerrero Muñoz

2025
