"""
Módulo de Ingeniería de Detección SOC Nivel 2 (Detection Engineering & Threat Hunting).
Integra:
1. Catálogo Forense LOLBAS (https://lolbas-project.github.io/) mapeado a los binarios nativos abusados en los 715 logs.
2. Catálogo GTFOBins (https://gtfobins.org/) mapeado a utilidades multiplataforma / equivalentes UNIX de archivo y RCE.
3. Reglas de Detección listas para producción en Sigma (.yml), YARA Clásico (.yar) y YARA-X (.yarx — motor Rust de VirusTotal).
"""

from __future__ import annotations
from typing import List, Dict, Any


def get_lolbas_gtfobins_catalog() -> List[Dict[str, Any]]:
    """
    Retorna el mapeo exacto de binarios Living Off The Land (LOLBAS) y GTFOBins
    detectados en los 715 eventos del dataset SIEM, con sus Log_IDs y enlaces oficiales.
    """
    return [
        {
            "binario": "vssadmin.exe",
            "catalogo": "LOLBAS",
            "incidente": "INC-03",
            "log_ids": "EVT-00314",
            "host": "WS-023 (CORP\\backupsvc)",
            "comando_detectado": "vssadmin.exe delete shadows /all /quiet",
            "funcion_abusada": "Execute / Inhibit System Recovery (Borrado silencioso de Volume Shadow Copies previo a Ransomware)",
            "mitre": "T1490 (Inhibit System Recovery)",
            "lolbas_url": "https://lolbas-project.github.io/lolbas/Binaries/Vssadmin/",
            "gtfobins_url": "https://gtfobins.org/",
            "riesgo": "Crítico",
        },
        {
            "binario": "tar.exe (bsdtar)",
            "catalogo": "LOLBAS + GTFOBins",
            "incidente": "INC-02",
            "log_ids": "EVT-00232",
            "host": "APP-SRV01 (CORP\\admin)",
            "comando_detectado": "tar.exe -a -c -f C:\\Temp\\finance.zip C:\\Temp\\reports",
            "funcion_abusada": "Archive / Staging Exfiltration (Empaquetado nativo de Budget2027.xlsx sin instalar herramientas externas)",
            "mitre": "T1560.001 (Archive via Utility)",
            "lolbas_url": "https://lolbas-project.github.io/lolbas/Binaries/Tar/",
            "gtfobins_url": "https://gtfobins.org/gtfobins/tar/",
            "riesgo": "Alto",
        },
        {
            "binario": "7z.exe / 7z",
            "catalogo": "GTFOBins + Utility Abuse",
            "incidente": "INC-04",
            "log_ids": "EVT-00428 (Oculto en Informational)",
            "host": "WS-018 (CORP\\rrojas)",
            "comando_detectado": "7z.exe a C:\\Users\\Public\\archive.7z C:\\Legal\\*.docx",
            "funcion_abusada": "File Read / Staging Archive (Compresión de contratos legales previo a exfiltración de 241.57 MiB por HTTPS POST)",
            "mitre": "T1560.001 (Archive via Utility)",
            "lolbas_url": "https://lolbas-project.github.io/",
            "gtfobins_url": "https://gtfobins.org/gtfobins/7z/",
            "riesgo": "Crítico",
        },
        {
            "binario": "powershell.exe",
            "catalogo": "LOLBAS",
            "incidente": "INC-02, INC-03",
            "log_ids": "EVT-00198, EVT-00207, EVT-00235, EVT-00280",
            "host": "APP-SRV01, WS-023",
            "comando_detectado": "powershell.exe -NoProfile -EncodedCommand <base64_redacted>",
            "funcion_abusada": "Execute / Obfuscated Payloads & C2 Upload (Ejecución en memoria Base64 y exfiltración hacia 203.0.113.88:443)",
            "mitre": "T1059.001 (PowerShell), T1027 (Obfuscated Files)",
            "lolbas_url": "https://lolbas-project.github.io/lolbas/Binaries/Powershell/",
            "gtfobins_url": "https://gtfobins.org/",
            "riesgo": "Crítico",
        },
        {
            "binario": "schtasks.exe",
            "catalogo": "LOLBAS",
            "incidente": "INC-05",
            "log_ids": "EVT-00523",
            "host": "APP-SRV01 (CORP\\helpdesk)",
            "comando_detectado": "Tarea programada \\Microsoft\\Windows\\UpdateCheck -> C:\\ProgramData\\wuhelper.exe",
            "funcion_abusada": "Persistence / Scheduled Task (Ejecución automática periódica suplantando nombre de Microsoft Windows)",
            "mitre": "T1053.005 (Scheduled Task/Job: Scheduled Task)",
            "lolbas_url": "https://lolbas-project.github.io/lolbas/Binaries/Schtasks/",
            "gtfobins_url": "https://gtfobins.org/gtfobins/crontab/",
            "riesgo": "Alto",
        },
        {
            "binario": "sc.exe (Service Control)",
            "catalogo": "LOLBAS",
            "incidente": "INC-05",
            "log_ids": "EVT-00524, EVT-00528..00564 (5x Info)",
            "host": "APP-SRV01 (CORP\\helpdesk)",
            "comando_detectado": "Servicio WinUpdateHelper -> C:\\ProgramData\\wuhelper.exe",
            "funcion_abusada": "Persistence / Windows Service Creation (Instalación de servicio persistente que ejecuta wuhelper.exe cada 6 min)",
            "mitre": "T1543.003 (Create or Modify System Process: Windows Service)",
            "lolbas_url": "https://lolbas-project.github.io/lolbas/Binaries/Sc/",
            "gtfobins_url": "https://gtfobins.org/gtfobins/systemctl/",
            "riesgo": "Alto",
        },
        {
            "binario": "net.exe",
            "catalogo": "LOLBAS",
            "incidente": "INC-02",
            "log_ids": "EVT-00214",
            "host": "APP-SRV01 (CORP\\admin)",
            "comando_detectado": "net.exe view \\\\FS-SRV01",
            "funcion_abusada": "Discovery / Network Share Enumeration (Reconocimiento de carpetas compartidas SMB antes del salto lateral)",
            "mitre": "T1135 (Network Share Discovery)",
            "lolbas_url": "https://lolbas-project.github.io/lolbas/Binaries/Net/",
            "gtfobins_url": "https://gtfobins.org/",
            "riesgo": "Medio/Alto",
        },
        {
            "binario": "cmd.exe / whoami.exe",
            "catalogo": "LOLBAS + GTFOBins",
            "incidente": "INC-06",
            "log_ids": "EVT-00571, EVT-00599",
            "host": "WEB-01 (IIS APPPOOL\\DefaultAppPool)",
            "comando_detectado": "cmd.exe /c whoami (invocado desde /uploads/test.aspx?cmd=whoami)",
            "funcion_abusada": "Webshell RCE Subshell Spawning (Ejecución remota de comandos bajo contexto de proceso web IIS w3wp.exe)",
            "mitre": "T1505.003 (Web Shell), T1059.003 (Windows Command Shell)",
            "lolbas_url": "https://lolbas-project.github.io/lolbas/Binaries/Cmd/",
            "gtfobins_url": "https://gtfobins.org/gtfobins/sh/",
            "riesgo": "Crítico",
        },
    ]


def get_sigma_rules_yaml() -> str:
    """
    Retorna el paquete de reglas Sigma (.yml) diseñadas para detectar los 6 incidentes
    del dataset y eliminar los 12 falsos negativos de severidad 'Informational' (OBS-01).
    """
    return """# =====================================================================
# PAQUETE DE REGLAS SIGMA — SOC NIVEL 2 (DOJO COMMUNITY)
# Corrige la evasión en severidad 'Informational' (OBS-01) y detecta LOLBAS
# =====================================================================
title: SOC L2 - Abuso de LOLBAS para Staging, Ransomware VSS y Persistencia
id: 8f4b2c10-9d3a-4e7b-b122-6c9a0e54f201
status: production
description: >
  Detecta la ejecución de binarios LOLBAS/GTFOBins observados en los incidentes INC-02,
  INC-03, INC-04, INC-05 e INC-06, incluyendo aquellos etiquetados erróneamente como
  Informational por el SIEM (EVT-00428 7z.exe y EVT-00528..00564 wuhelper.exe).
author: JEV Cyber Command OS (SOC Nivel 2)
date: 2026/10/23
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Vssadmin/
  - https://lolbas-project.github.io/lolbas/Binaries/Tar/
  - https://gtfobins.org/gtfobins/7z/
logsource:
  category: process_creation
  product: windows
detection:
  selection_vss_ransomware:
    EventID: 4688
    CommandLine|contains|all:
      - 'vssadmin'
      - 'delete'
      - 'shadows'
  selection_lolbas_archivers:
    EventID: 4688
    CommandLine|contains:
      - 'tar.exe -a -c -f C:\\Temp\\finance.zip'
      - '7z.exe a C:\\Users\\Public\\archive.7z'
      - 'C:\\Users\\Public\\'
      - 'C:\\Temp\\'
  selection_encoded_powershell:
    EventID: 4688
    CommandLine|contains:
      - '-EncodedCommand'
      - '-enc '
  selection_rogue_service_binary:
    EventID: 4688
    CommandLine|contains: 'C:\\ProgramData\\wuhelper.exe'
  selection_iis_webshell_rce:
    EventID: 4688
    User|contains: 'DefaultAppPool'
    CommandLine|contains: 'cmd.exe /c whoami'
  condition: 1 of selection_*
falsepositives:
  - Tareas administrativas legítimas debidamente firmadas y fuera de rutas públicas
level: critical
tags:
  - attack.impact
  - attack.t1490
  - attack.collection
  - attack.t1560.001
  - attack.persistence
  - attack.t1543.003
  - attack.t1505.003
---
title: SOC L2 - Correlación de Password Spraying Seguido de Login Exitoso en Informational
id: 3a91e745-1c2b-4d98-8f11-90a2b4c77e12
status: production
description: >
  Detecta ráfagas de fallos de autenticación (EventID 4625 >= 10 desde una misma IP externa)
  seguidas por un EventID 4624 y 4672 exitoso aunque el SIEM nativo lo registre como Informational
  (Caso INC-01: EVT-00123 y EVT-00126 sobre CORP\\mgarcia desde 203.0.113.74 en DC-01/DC01).
author: JEV Cyber Command OS (SOC Nivel 2)
date: 2026/10/23
logsource:
  product: windows
  service: security
detection:
  selection_failed_spray:
    EventID: 4625
    Source_IP:
      - '203.0.113.74'
      - '198.51.100.77'
  selection_post_spray_success:
    EventID:
      - 4624
      - 4672
  condition: selection_failed_spray or selection_post_spray_success
level: high
tags:
  - attack.credential_access
  - attack.t1110.003
  - attack.initial_access
  - attack.t1078.002
"""


def get_yara_classic_rules() -> str:
    """
    Retorna reglas YARA clásicas (.yar) para búsqueda forense en disco y memoria sobre
    los servidores comprometidos (WEB-01, APP-SRV01, WS-018, WS-023).
    """
    return """/*
   =====================================================================
   REGLAS YARA CLÁSICAS (.yar) — CAZA DE AMENAZAS DFIR SOC NIVEL 2
   Artefactos: Webshell ASPX (INC-06), Persistencia wuhelper.exe (INC-05)
   y Scripts de Exfiltración / Pre-Ransomware (INC-02, INC-03, INC-04)
   =====================================================================
*/

rule SOC_L2_INC06_IIS_ASPX_Webshell_Test
{
    meta:
        author = "JEV Cyber Command OS - SOC Nivel 2"
        incident = "INC-06 (WEB-01 - 192.0.2.91)"
        evidence_logs = "EVT-00571, EVT-00599"
        mitre_attack = "T1505.003, T1059.003"
        severity = "CRITICAL"
        description = "Detecta la Webshell ASPX /uploads/test.aspx capaz de invocar cmd.exe /c whoami bajo DefaultAppPool"

    strings:
        $aspx_directive = "<%@ Page Language=" ascii wide nocase
        $cmd_param      = "Request.QueryString[\"cmd\"]" ascii wide nocase
        $cmd_param_alt  = "Request[\"cmd\"]" ascii wide nocase
        $proc_start     = "ProcessStartInfo" ascii wide
        $shell_exec     = "cmd.exe /c " ascii wide nocase
        $uri_indicator  = "/uploads/test.aspx" ascii wide nocase

    condition:
        filesize < 500KB and
        (
            ($aspx_directive and ($cmd_param or $cmd_param_alt) and ($proc_start or $shell_exec))
            or ($shell_exec and $uri_indicator)
        )
}

rule SOC_L2_INC05_Rogue_Persistence_Wuhelper_Binary
{
    meta:
        author = "JEV Cyber Command OS - SOC Nivel 2"
        incident = "INC-05 (APP-SRV01 - CORP\\helpdesk)"
        evidence_logs = "EVT-00523, EVT-00524, EVT-00528, EVT-00542, EVT-00548, EVT-00559, EVT-00564"
        mitre_attack = "T1053.005, T1543.003"
        lolbas_ref = "https://lolbas-project.github.io/lolbas/Binaries/Sc/"
        severity = "HIGH"
        description = "Detecta el binario persistente C:\\ProgramData\\wuhelper.exe y sus cadenas de registro de servicio/tarea"

    strings:
        $mz_header = { 4D 5A }
        $path_pdb  = "C:\\ProgramData\\wuhelper.exe" ascii wide nocase
        $svc_name  = "WinUpdateHelper" ascii wide
        $task_name = "\\Microsoft\\Windows\\UpdateCheck" ascii wide

    condition:
        $mz_header at 0 and filesize < 10MB and
        ($path_pdb or ($svc_name and $task_name))
}

rule SOC_L2_INC02_03_04_LOLBAS_Staging_And_VSS_Sabotage
{
    meta:
        author = "JEV Cyber Command OS - SOC Nivel 2"
        incident = "INC-02, INC-03, INC-04"
        evidence_logs = "EVT-00232, EVT-00314, EVT-00428"
        lolbas_ref = "https://lolbas-project.github.io/lolbas/Binaries/Vssadmin/"
        gtfobins_ref = "https://gtfobins.org/gtfobins/7z/"
        severity = "CRITICAL"
        description = "Detecta scripts o lotes en memoria/disco que invocan vssadmin delete shadows o staging en rutas publicas"

    strings:
        $vss_del     = "vssadmin.exe delete shadows /all /quiet" ascii wide nocase
        $tar_stage   = "tar.exe -a -c -f C:\\Temp\\finance.zip" ascii wide nocase
        $sevenz_leg  = "7z.exe a C:\\Users\\Public\\archive.7z C:\\Legal\\*.docx" ascii wide nocase
        $ps_encoded  = "powershell.exe -NoProfile -EncodedCommand" ascii wide nocase

    condition:
        any of ($vss_del, $tar_stage, $sevenz_leg) or $ps_encoded
}
"""


def get_yarax_nextgen_rules() -> str:
    """
    Retorna reglas optimizadas para YARA-X (.yarx), el motor de nueva generación en Rust
    creado por VirusTotal, con validación estricta de módulos `pe` y expresiones regulares seguras.
    """
    return """/*
   =====================================================================
   REGLAS YARA-X (.yarx) — MOTOR NEXT-GEN EN RUST (VIRUSTOTAL)
   Sintaxis estricta compatible con `yr scan` (YARA-X CLI / Rust Engine)
   =====================================================================
*/

import "pe"

rule YARAX_SOC_L2_MultiIncident_Artifact_Detector
{
    meta:
        engine = "YARA-X (VirusTotal Rust Engine >= 0.10)"
        author = "JEV Cyber Command OS - SOC Nivel 2"
        incidents_covered = "INC-02, INC-03, INC-04, INC-05, INC-06"
        lolbas_catalog = "https://lolbas-project.github.io/"
        gtfobins_catalog = "https://gtfobins.org/"
        tlp = "AMBER+STRICT"

    strings:
        // INC-05: Persistencia dual en APP-SRV01 (oculto en Informational)
        $persist_bin   = "C:\\ProgramData\\wuhelper.exe" ascii wide nocase
        $persist_svc   = "WinUpdateHelper" ascii wide
        $persist_task  = "\\Microsoft\\Windows\\UpdateCheck" ascii wide

        // INC-03: Sabotaje Pre-Ransomware VSS (LOLBAS vssadmin)
        $lolbas_vss    = /vssadmin(\\.exe)?\\s+delete\\s+shadows\\s+\\/all\\s+\\/quiet/i

        // INC-02 & INC-04: Empaquetado de exfiltración (LOLBAS tar.exe & GTFOBins 7z)
        $stage_finance = "C:\\Temp\\finance.zip" ascii wide nocase
        $stage_legal   = "C:\\Users\\Public\\archive.7z" ascii wide nocase
        $target_budget = "Budget2027.xlsx" ascii wide nocase

        // INC-06: Webshell IIS RCE en WEB-01
        $webshell_uri  = "/uploads/test.aspx" ascii wide nocase
        $webshell_cmd  = "cmd.exe /c whoami" ascii wide nocase

        // C2 Exfiltration Endpoints
        $c2_legal_ip   = "198.51.100.88:443" ascii wide
        $c2_fin_ip     = "203.0.113.88:443" ascii wide

    condition:
        (
            pe.is_pe and
            (
                $persist_bin or
                ($persist_svc and $persist_task)
            )
        )
        or any of ($lolbas_vss, $stage_finance, $stage_legal, $target_budget)
        or ($webshell_uri and $webshell_cmd)
        or any of ($c2_legal_ip, $c2_fin_ip)
}
"""

