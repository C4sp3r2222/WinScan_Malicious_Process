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

-------------------------------------------------------------------------

-------------------------------------------------------------------------


DEMOSTRACIÓN:

-NOTA: En caso de tener restringida la ejecución, poner estos comandos:

PS C:\WINDOWS\system32> Set-ExecutionPolicy RemoteSigned -Scope Process
 ¿Quieres cambiar la directiva de ejecución?
 ...
[S] Sí  [O] Sí a todo  [N] No  [T] No a todo  [U] Suspender  [?] Ayuda (el valor predeterminado es "N"): S   <----- (Marcar S) (solo en ésta ventana PS, no afectará al resto)

PS C:\WINDOWS\system32> cd "$env:USERPROFILE\Desktop"

PS C:\Users\USER\Desktop> .\WinScan_Malicious_Process.ps1



![scanprog2](https://github.com/user-attachments/assets/54bf9035-7384-4e09-9f97-9a2a9ff79928)


![scanprog1](https://github.com/user-attachments/assets/0ad01abe-76d6-45b9-ae8b-6cf6c2018ad2)


![scanprog3](https://github.com/user-attachments/assets/5b5d5dad-fbaf-414b-a804-1982628c2c36)

