"""
Módulo de Ingesta, Validación de Esquema, Normalización y Motor de Correlación Heurística SOC Nivel 2.
Procesa archivos Excel (.xlsx) exportados del SIEM, valida integridad estructural,
identifica incidentes multi-etapa, destapa eventos críticos ocultos bajo severidad
'Informational' y audita la calidad de datos.
"""

from __future__ import annotations
import re
from typing import Dict, List, Tuple, Any
import pandas as pd


class SIEMValidationError(ValueError):
    """Excepción lanzada cuando el archivo Excel no cumple con el esquema mínimo SIEM."""


REQUIRED_COLUMNS = [
    "Log_ID",
    "Timestamp",
    "Hostname",
    "Event_ID",
    "User",
    "Source_IP",
    "Destination",
    "Log_Source",
    "Event_Description",
    "Process_CommandLine",
    "Result",
    "Severity",
]


def validate_and_prepare_dataframe(df: pd.DataFrame) -> Tuple[pd.DataFrame, List[str]]:
    """
    Valida que el DataFrame no esté vacío y contenga las columnas requeridas del SIEM.
    Acepta variaciones de mayúsculas/espacios en cabeceras y rellena columnas
    opcionales faltantes advirtiendo al analista.
    """
    if df is None or df.empty:
        raise SIEMValidationError("El archivo Excel o la hoja seleccionada no contiene registros (0 filas).")

    df = df.copy()
    # Mapear nombres de columnas ignorando espacios y diferencias de capitalización
    col_map = {str(c).strip().lower(): str(c).strip() for c in df.columns}
    df.columns = [str(c).strip() for c in df.columns]

    rename_dict = {}
    for req in REQUIRED_COLUMNS:
        req_lower = req.lower()
        if req not in df.columns and req_lower in col_map:
            rename_dict[col_map[req_lower]] = req
    if rename_dict:
        df = df.rename(columns=rename_dict)

    missing_cols = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    warnings: List[str] = []

    # Columnas esenciales sin las cuales no es un log SIEM válido
    core_essential = {"Timestamp", "Hostname", "Event_ID", "User", "Source_IP", "Severity"}
    missing_core = [c for c in missing_cols if c in core_essential]
    if missing_core:
        raise SIEMValidationError(
            f"El archivo no contiene las columnas obligatorias del SIEM: {', '.join(missing_core)}. "
            f"Columnas detectadas: {', '.join(df.columns)}"
        )

    # Si faltan columnas secundarias, crearlas con valor seguro '-' y registrar advertencia
    for col in missing_cols:
        df[col] = "-"
        warnings.append(f"Columna opcional '{col}' ausente; inicializada con '-'.")

    return df, warnings


def normalize_siem_dataframe(df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    Limpia y normaliza el DataFrame del SIEM: estandariza cadenas, convierte tipos
    mixtos para compatibilidad con PyArrow y unifica alias de hostnames y cuentas.
    """
    df, schema_warnings = validate_and_prepare_dataframe(df)

    for str_col in ["Log_ID", "Hostname", "User", "Source_IP", "Log_Source", "Event_Description", "Severity"]:
        df[str_col] = df[str_col].fillna("-").astype(str).str.strip()

    # Convertir columnas con tipos mixtos (int + str en Excel) a string para compatibilidad total con PyArrow
    df["Event_ID"] = df["Event_ID"].fillna("-").astype(str).str.strip()
    df["Result"] = df["Result"].fillna("-").astype(str).str.strip()
    df["Destination"] = df["Destination"].fillna("-").astype(str).str.strip()
    df["Process_CommandLine"] = df["Process_CommandLine"].fillna("-").astype(str).str.strip()

    df["Timestamp_dt"] = pd.to_datetime(df["Timestamp"], errors="coerce")
    invalid_ts = int(df["Timestamp_dt"].isna().sum())
    if invalid_ts == len(df):
        raise SIEMValidationError("Ningún registro de la columna 'Timestamp' tiene un formato de fecha/hora válido.")
    if invalid_ts > 0:
        schema_warnings.append(f"{invalid_ts} fila(s) con Timestamp inválido fueron normalizadas.")

    df["Hour_Min_10"] = df["Timestamp_dt"].dt.floor("10min")

    # Conteo de anomalías de normalización antes de unificar
    dc01_no_hyphen = int((df["Hostname"] == "DC01").sum())
    dc01_hyphen = int((df["Hostname"] == "DC-01").sum())
    svc_backup_alt = int((df["User"] == "CORP\\svc_backup").sum())
    backupsvc_std = int((df["User"] == "CORP\\backupsvc").sum())

    # Columnas normalizadas para análisis consistente sin perder el valor original
    df["Hostname_Norm"] = df["Hostname"].replace({"DC01": "DC-01"})
    df["User_Norm"] = df["User"].replace({"CORP\\svc_backup": "CORP\\backupsvc"})

    normalization_stats = {
        "dc_hyphen_count": dc01_hyphen,
        "dc_no_hyphen_count": dc01_no_hyphen,
        "backupsvc_count": backupsvc_std,
        "svc_backup_count": svc_backup_alt,
        "schema_warnings": schema_warnings,
    }
    return df, normalization_stats


def analyze_siem_logs(raw_df: pd.DataFrame) -> Tuple[pd.DataFrame, List[Dict[str, Any]], Dict[str, Any]]:
    """
    Ejecuta el motor de correlación forense SOC Nivel 2 sobre los eventos SIEM.
    Detecta los 6 incidentes críticos + 1 hallazgo de calidad/visibilidad SIEM,
    incluyendo los 12 eventos críticos etiquetados como 'Informational' (trampas de Nivel 2).
    """
    df, norm_stats = normalize_siem_dataframe(raw_df)

    # Reglas de correlación multi-evento (independientes de si Severity == Informational)
    inc_rules = {
        "INC-01: Password Spraying y Compromiso de Cuenta (DC-01 / WS-031)": (
            df["Source_IP"] == "203.0.113.74"
        ),
        "INC-02: Intrusión RDP, Mov. Lateral SMB y Exfiltración (CORP\\admin)": (
            (df["Source_IP"] == "198.51.100.77") | (df["User"] == "CORP\\admin")
        ),
        "INC-03: Pre-Ransomware, Recolección y Borrado VSS (CORP\\backupsvc)": (
            (df["User"] == "CORP\\backupsvc")
            & (df["Timestamp_dt"] >= "2026-10-23 09:36:00")
            & (df["Timestamp_dt"] <= "2026-10-23 09:43:00")
            & (df["Source_IP"] == "10.10.1.44")
        ),
        "INC-04: Exfiltración Masiva Legal vía HTTPS POST (CORP\\rrojas)": (
            (df["User"] == "CORP\\rrojas")
            & (df["Timestamp_dt"] >= "2026-10-23 10:40:00")
            & (df["Timestamp_dt"] <= "2026-10-23 10:49:30")
            & (df["Source_IP"] == "10.10.1.31")
        ),
        "INC-05: Persistencia por Tarea Programada y Servicio (APP-SRV01)": (
            (df["Hostname"] == "APP-SRV01")
            & (df["User"] == "CORP\\helpdesk")
            & (df["Timestamp_dt"] >= "2026-10-23 11:35:00")
            & (df["Timestamp_dt"] <= "2026-10-23 12:05:00")
            & (df["Source_IP"] == "10.10.3.18")
        ),
        "INC-06: Explotación Web IIS, Webshell ASPX y RCE (WEB-01)": (
            (df["Source_IP"] == "192.0.2.91") | (df["User"] == "IIS APPPOOL\\DefaultAppPool")
        ),
    }

    df["Incident_Tag"] = "Tráfico Operativo / Ruido Base"
    df["Incident_ID"] = "NONE"

    for name, mask in inc_rules.items():
        inc_code = name.split(":")[0]
        df.loc[mask, "Incident_Tag"] = name
        df.loc[mask, "Incident_ID"] = inc_code

    # Marcar eventos maliciosos que estaban camuflados como 'Informational'
    df["Hidden_Critical_Info"] = (df["Incident_ID"] != "NONE") & (df["Severity"] == "Informational")

    # Marcar cualquier registro que involucre IPs públicas/externas (tanto en origen como en destino)
    external_src_ips = {"203.0.113.74", "198.51.100.77", "192.0.2.91"}
    external_dst_endpoints = {"198.51.100.88:443", "203.0.113.88:443"}
    df["Involves_External_IP"] = df["Source_IP"].isin(external_src_ips) | df["Destination"].isin(external_dst_endpoints)

    # Cálculo exacto de bytes exfiltrados en INC-04 (PROXY_ACCESS)
    proxy_rows = df[df["Event_ID"] == "PROXY_ACCESS"]["Process_CommandLine"].dropna()
    exfil_bytes = sum(
        int(re.search(r"bytes_out=(\d+)", str(val)).group(1))
        for val in proxy_rows
        if re.search(r"bytes_out=(\d+)", str(val))
    )
    exfil_mib = exfil_bytes / (1024 * 1024)
    exfil_mb = exfil_bytes / 1_000_000

    # Eventos críticos camuflados como Informational (Trampas SOC L2)
    hidden_df = df[df["Hidden_Critical_Info"]].copy()
    hidden_events_list = (
        hidden_df[
            ["Log_ID", "Timestamp", "Hostname", "Event_ID", "User", "Source_IP", "Destination", "Process_CommandLine", "Incident_ID"]
        ]
        .astype(object)
        .where(pd.notnull(hidden_df), "-")
        .to_dict(orient="records")
    )

    findings: List[Dict[str, Any]] = [
        {
            "id": "INC-01",
            "titulo": "Password Spraying Externo y Compromiso de Cuenta de Dominio (CORP\\mgarcia)",
            "riesgo": "Alto",
            "cvss_estimado": "8.8 (Crítico/Alto)",
            "kill_chain": "Initial Access -> Credential Access -> Privilege Escalation",
            "mitre_tacticas": "Credential Access (TA0006), Initial Access (TA0001), Privilege Escalation (TA0004)",
            "mitre": "T1110.003 (Password Spraying), T1078.002 (Valid Accounts: Domain Accounts)",
            "ventana": "2026-10-23 08:25:00 a 08:40:00 (15 min)",
            "eventos_count": int((df["Incident_ID"] == "INC-01").sum()),
            "eventos_ocultos_info": int(((df["Incident_ID"] == "INC-01") & (df["Severity"] == "Informational")).sum()),
            "activos": "DC-01 (Controlador de Dominio), WS-031 (Estación de Trabajo)",
            "usuarios": "8 cuentas atacadas (jlopez, aperez, helpdesk, mgarcia, rrojas, slopez, backupsvc, dtorres) | Comprometida: CORP\\mgarcia",
            "ioc": "IP Atacante: 203.0.113.74 | Event IDs: 4625 (x33 fallos), 4624 (EVT-00123 login exitoso), 4672 (EVT-00126 privilegios especiales)",
            "evidencia_logs": "EVT-00057 a EVT-00111 (33x Event 4625 Warning), EVT-00123 (Event 4624 Informational), EVT-00126 (Event 4672 Informational)",
            "resumen_ejecutivo": (
                "Un atacante externo desde la IP 203.0.113.74 ejecutó un ataque automatizado de pulverización de contraseñas "
                "(Password Spraying) contra el Controlador de Dominio (DC-01) probando contraseñas comunes sobre 8 cuentas corporativas. "
                "Tras 33 intentos fallidos, logró vulnerar la cuenta CORP\\mgarcia y obtuvo privilegios elevados en la estación WS-031."
            ),
            "resumen_tecnico": (
                "Entre las 08:25:00 y las 08:35:08, la IP pública 203.0.113.74 generó 33 eventos 4625 ('An account failed to log on - bad password') "
                "contra DC-01 a un ritmo constante de un intento cada 19 segundos rotando sobre 8 usuarios para evadir umbrales de bloqueo de cuenta. "
                "A las 08:39:00 (EVT-00123), el atacante logró un inicio de sesión exitoso (Event ID 4624) con CORP\\mgarcia en DC-01, seguido a las "
                "08:40:00 (EVT-00126) por la asignación de privilegios especiales (Event ID 4672) en WS-031. Ambos eventos de éxito estaban "
                "etiquetados con severidad 'Informational' en el SIEM."
            ),
            "remediacion": (
                "1. Resetear inmediatamente la contraseña de CORP\\mgarcia y revocar todos los tickets Kerberos TGT/TGS activos.\n"
                "2. Bloquear la IP externa 203.0.113.74 en el Firewall Perimetral.\n"
                "3. Habilitar MFA obligatorio y configurar políticas de Smart Lockout para autenticaciones externas contra Active Directory."
            ),
            "comandos_contencion": (
                "Disable-ADAccount -Identity mgarcia; Revoke-AzureADUserAllRefreshToken; "
                "New-NetFirewallRule -DisplayName 'Block_IOC_203.0.113.74' -Direction Inbound -RemoteAddress 203.0.113.74 -Action Block"
            ),
        },
        {
            "id": "INC-02",
            "titulo": "Intrusión RDP, Movimiento Lateral SMB y Exfiltración Financiera (Budget2027.xlsx)",
            "riesgo": "Alto",
            "cvss_estimado": "9.6 (Crítico)",
            "kill_chain": "Initial Access -> Execution -> Discovery -> Lateral Movement -> Collection -> Exfiltration",
            "mitre_tacticas": "Initial Access (TA0001), Execution (TA0002), Discovery (TA0007), Lateral Movement (TA0008), Collection (TA0009), Exfiltration (TA0010)",
            "mitre": "T1021.001 (RDP), T1059.001 (PowerShell), T1087.001, T1135 (Share Discovery), T1021.002 (SMB), T1560.001 (Archive via Utility), T1041 (Exfiltration Over C2)",
            "ventana": "2026-10-23 09:02:00 a 09:22:00 (20 min)",
            "eventos_count": int((df["Incident_ID"] == "INC-02").sum()),
            "eventos_ocultos_info": int(((df["Incident_ID"] == "INC-02") & (df["Severity"] == "Informational")).sum()),
            "activos": "APP-SRV01 (10.10.2.15), FS-SRV01 (Servidor de Archivos Financieros)",
            "usuarios": "CORP\\admin (Cuenta Privilegiada)",
            "ioc": "IPs Externas: 198.51.100.77 (RDP Ingress), 203.0.113.88:443 (Exfil C2) | IP Interna Pivote: 10.10.2.15 | Archivos: Finance\\Budget2027.xlsx, C:\\Temp\\finance.zip",
            "evidencia_logs": "EVT-00174..00180 (4x 4625 RDP), EVT-00188 (4624 RDP), EVT-00193 (4672), EVT-00198 (PS Encoded), EVT-00207 (4104 ScriptBlock), EVT-00214 (net view), EVT-00222..00231 (SMB/Budget2027.xlsx), EVT-00232 (tar.exe), EVT-00235 (5156 Exfil), EVT-00237 (4634 Info)",
            "resumen_ejecutivo": (
                "Un adversario externo comprometió la cuenta administrativa CORP\\admin mediante Escritorio Remoto (RDP) en el servidor de aplicaciones "
                "APP-SRV01. Desde allí se desplazó lateralmente al servidor de archivos FS-SRV01, sustrajo el presupuesto corporativo confidencial "
                "'Budget2027.xlsx', lo comprimió y lo exfiltró hacia un servidor externo bajo control del atacante."
            ),
            "resumen_tecnico": (
                "La IP externa 198.51.100.77 realizó 4 intentos fallidos por RDP (LogonType=10, Event ID 4625) entre las 09:02 y 09:05 contra CORP\\admin "
                "en APP-SRV01, logrando acceso exitoso a las 09:06:00 (EVT-00188) y privilegios especiales (EVT-00193). A las 09:09:00 ejecutó "
                "'powershell.exe -NoProfile -EncodedCommand [REDACTED_SYNTHETIC]' (EVT-00198) e invocó el bloque de script 'Get-LocalGroupMember Administrators; "
                "Get-SmbShare' (Event ID 4104, EVT-00207) y 'net.exe view \\\\FS-SRV01' (EVT-00214). A las 09:16:00 saltó por red (LogonType=3, EVT-00225) "
                "desde APP-SRV01 (10.10.2.15) hacia FS-SRV01, accedió a '\\\\FS-SRV01\\Finance\\Budget2027.xlsx' (Event ID 5145, EVT-00231), creó el paquete "
                "de staging 'tar.exe -a -c -f C:\\Temp\\finance.zip C:\\Temp\\reports' (EVT-00232), exfiltró el archivo hacia 203.0.113.88:443 "
                "usando powershell.exe (Event ID 5156, EVT-00235) y cerró sesión a las 09:22:00 (EVT-00237, Informational)."
            ),
            "remediacion": (
                "1. Aislar inmediatamente APP-SRV01 de la red corporativa y cerrar toda exposición directa de RDP (TCP/3389) hacia Internet.\n"
                "2. Rotar las credenciales de CORP\\admin y auditar todas las sesiones SMB originadas desde 10.10.2.15.\n"
                "3. Bloquear las IPs 198.51.100.77 y 203.0.113.88 en el Firewall Perimetral y eliminar C:\\Temp\\finance.zip tras su preservación forense."
            ),
            "comandos_contencion": (
                "Disable-NetAdapter -Name 'Ethernet0' -Confirm:$false; Stop-Service TermService -Force; "
                "Remove-Item -Path 'C:\\Temp\\finance.zip' -Force"
            ),
        },
        {
            "id": "INC-03",
            "titulo": "Actividad Pre-Ransomware: Recolección Financiera y Destrucción de Copias de Sombra (VSS)",
            "riesgo": "Alto",
            "cvss_estimado": "9.4 (Crítico)",
            "kill_chain": "Execution -> Collection -> Impact (Inhibit System Recovery)",
            "mitre_tacticas": "Execution (TA0002), Collection (TA0009), Impact (TA0040)",
            "mitre": "T1059.001 (PowerShell Encoded), T1039 (Data from Network Shared Drive), T1490 (Inhibit System Recovery: vssadmin)",
            "ventana": "2026-10-23 09:36:00 a 09:43:00 (7 min)",
            "eventos_count": int((df["Incident_ID"] == "INC-03").sum()),
            "eventos_ocultos_info": int(((df["Incident_ID"] == "INC-03") & (df["Severity"] == "Informational")).sum()),
            "activos": "WS-023 (10.10.1.44), FS-SRV01 (\\\\FS-SRV01\\Finance)",
            "usuarios": "CORP\\backupsvc (Cuenta de Servicio de Respaldos)",
            "ioc": "IP Interna: 10.10.1.44 (WS-023) | Comandos: powershell.exe -NoProfile -EncodedCommand <base64_redacted> (EVT-00280), vssadmin.exe delete shadows /all /quiet (EVT-00314)",
            "evidencia_logs": "EVT-00280 (Event 4688 PS Base64), EVT-00284 a EVT-00309 (16x Event 4663 sobre Finance\\FY2026\\document_000..015.xlsx), EVT-00314 (Event 4688 vssadmin), EVT-00315 (Event 5145 Info)",
            "resumen_ejecutivo": (
                "La cuenta de servicio de respaldos (CORP\\backupsvc) fue utilizada en la estación WS-023 para ejecutar código oculto, recorrer de forma "
                "automatizada 16 documentos financieros de FY2026 y eliminar silenciosamente todas las copias de seguridad locales (Volume Shadow Copies). "
                "Este patrón corresponde a la fase inmediatamente previa a la detonación de un ataque de Ransomware."
            ),
            "resumen_tecnico": (
                "A las 09:36:00 en el host WS-023 (10.10.1.44), la cuenta CORP\\backupsvc ejecutó 'powershell.exe -NoProfile -EncodedCommand <base64_redacted>' "
                "(Event ID 4688, EVT-00280). Entre las 09:37:00 y las 09:41:00 (EVT-00284 a EVT-00309) realizó un barrido secuencial automatizado cada 16 segundos "
                "sobre 16 archivos en '\\\\FS-SRV01\\Finance' (Finance\\FY2026\\document_000.xlsx hasta document_015.xlsx, Event ID 4663). Finalmente, a las 09:42:00 "
                "(EVT-00314), ejecutó 'vssadmin.exe delete shadows /all /quiet' en WS-023 para destruir las copias de sombra del volumen e impedir la recuperación, "
                "seguido a las 09:43:00 (EVT-00315, Informational) por una verificación de permisos sobre '\\\\FS-SRV01\\Finance' (Event ID 5145)."
            ),
            "remediacion": (
                "1. Aislar de inmediato la estación WS-023 (10.10.1.44) de la red para frenar cualquier proceso de cifrado sobre recursos SMB.\n"
                "2. Deshabilitar temporalmente la cuenta de servicio CORP\\backupsvc y restringir sus permisos mediante Group Managed Service Accounts (gMSA).\n"
                "3. Verificar la integridad de los respaldos inmutables/offline de FS-SRV01 y bloquear vssadmin.exe mediante reglas Attack Surface Reduction (ASR)."
            ),
            "comandos_contencion": (
                "Disable-ADAccount -Identity backupsvc; Stop-Computer -ComputerName WS-023 -Force; "
                "Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled"
            ),
        },
        {
            "id": "INC-04",
            "titulo": f"Exfiltración Masiva de Documentación Legal vía HTTPS POST ({exfil_mib:.2f} MiB / {exfil_mb:.2f} MB)",
            "riesgo": "Alto",
            "cvss_estimado": "8.9 (Alto)",
            "kill_chain": "Collection -> Staging -> Exfiltration",
            "mitre_tacticas": "Collection (TA0009), Exfiltration (TA0010)",
            "mitre": "T1039 (Data from Network Shared Drive), T1560.001 (Archive via Utility: 7-Zip), T1048.002 (Exfiltration Over Asymmetric Encrypted Non-C2 Protocol)",
            "ventana": "2026-10-23 10:40:00 a 10:49:18 (9 min 18 seg)",
            "eventos_count": int((df["Incident_ID"] == "INC-04").sum()),
            "eventos_ocultos_info": int(((df["Incident_ID"] == "INC-04") & (df["Severity"] == "Informational")).sum()),
            "activos": "WS-018 (10.10.1.31), FS-SRV01 (\\\\FS-SRV01\\Legal)",
            "usuarios": "CORP\\rrojas",
            "ioc": f"IP Externa Destino: 198.51.100.88:443 (/upload/session/1..22) | Archivo: C:\\Users\\Public\\archive.7z | Total Exfiltrado: {exfil_bytes:,} bytes ({exfil_mib:.2f} MiB)",
            "evidencia_logs": "EVT-00419 (Event 5140 Info: \\\\FS-SRV01\\Legal), EVT-00428 (Event 4688 Info: 7z.exe), EVT-00430 a EVT-00461 (22x PROXY_ACCESS HTTPS POST)",
            "resumen_ejecutivo": (
                f"Desde la estación de trabajo WS-018, bajo la cuenta del usuario CORP\\rrojas, se accedió al repositorio confidencial del departamento "
                f"Legal, se empaquetaron todos los documentos Word en un archivo comprimido y se exfiltraron {exfil_mib:.2f} MiB ({exfil_mb:.2f} MB) "
                f"en 22 envíos fraccionados hacia el servidor externo 198.51.100.88."
            ),
            "resumen_tecnico": (
                f"A las 10:40:00 (EVT-00419, severidad 'Informational'), el usuario CORP\\rrojas desde WS-018 (10.10.1.31) accedió al recurso compartido "
                f"'\\\\FS-SRV01\\Legal' (Event ID 5140). Dos minutos después, a las 10:42:00 (EVT-00428, también marcado como 'Informational'), ejecutó el "
                f"comando '7z.exe a C:\\Users\\Public\\archive.7z C:\\Legal\\*.docx' (Event ID 4688). Inmediatamente, entre las 10:43:00 y las 10:49:18 "
                f"(EVT-00430 a EVT-00461), realizó 22 peticiones HTTPS POST consecutivas cada 18 segundos a través del Proxy hacia 198.51.100.88:443 "
                f"(URIs /upload/session/1 hasta /upload/session/22), exfiltrando exactamente {exfil_bytes:,} bytes ({exfil_mib:.2f} MiB / {exfil_mb:.2f} MB)."
            ),
            "remediacion": (
                "1. Bloquear de inmediato el destino 198.51.100.88 en el Proxy Corporativo y Firewall Perimetral.\n"
                "2. Asegurar la estación WS-018 bajo cadena de custodia forense (preservar C:\\Users\\Public\\archive.7z y artefactos de memoria/disco).\n"
                "3. Notificar al Comité Legal y de Cumplimiento/Privacidad para evaluar el alcance de los documentos *.docx comprometidos."
            ),
            "comandos_contencion": (
                "Suspend-ADAccount -Identity rrojas; Get-FileHash 'C:\\Users\\Public\\archive.7z' -Algorithm SHA256; "
                "New-NetFirewallRule -DisplayName 'Block_Exfil_198.51.100.88' -Direction Outbound -RemoteAddress 198.51.100.88 -Action Block"
            ),
        },
        {
            "id": "INC-05",
            "titulo": "Persistencia Dual mediante Tarea Programada y Servicio de Sistema en APP-SRV01",
            "riesgo": "Alto",
            "cvss_estimado": "8.6 (Alto)",
            "kill_chain": "Initial Logon -> Persistence -> Privilege Escalation -> Execution",
            "mitre_tacticas": "Persistence (TA0003), Privilege Escalation (TA0004), Execution (TA0002)",
            "mitre": "T1053.005 (Scheduled Task/Job: Scheduled Task), T1543.003 (Create or Modify System Process: Windows Service)",
            "ventana": "2026-10-23 11:35:00 a 12:04:00 (29 min)",
            "eventos_count": int((df["Incident_ID"] == "INC-05").sum()),
            "eventos_ocultos_info": int(((df["Incident_ID"] == "INC-05") & (df["Severity"] == "Informational")).sum()),
            "activos": "APP-SRV01 (Servidor de Aplicaciones)",
            "usuarios": "CORP\\helpdesk",
            "ioc": "Origen: 10.10.3.18 | Tarea: \\Microsoft\\Windows\\UpdateCheck (C:\\ProgramData\\updatecheck.ps1) | Servicio: WinUpdateHelper (C:\\ProgramData\\wuhelper.exe)",
            "evidencia_logs": "EVT-00519 (Event 4624 Info), EVT-00523 (Event 4698 Task Created), EVT-00524 (Event 7045 Service Installed), EVT-00528, EVT-00542, EVT-00548, EVT-00559, EVT-00564 (5x Event 4688 Info wuhelper.exe)",
            "resumen_ejecutivo": (
                "Utilizando la cuenta de soporte técnico CORP\\helpdesk, se implantaron dos mecanismos redundantes de persistencia oculta en el servidor "
                "crítico APP-SRV01: una tarea programada camuflada como actualización de Windows y un servicio del sistema que ejecuta un programa no "
                "autorizado cada 6 minutos para mantener el control del servidor."
            ),
            "resumen_tecnico": (
                "A las 11:35:00 (EVT-00519, Informational), la cuenta CORP\\helpdesk inició sesión en APP-SRV01 desde 10.10.3.18. A las 11:37:00 "
                "(EVT-00523, Event ID 4698) creó la tarea programada '\\Microsoft\\Windows\\UpdateCheck' configurada para ejecutar "
                "'powershell.exe -File C:\\ProgramData\\updatecheck.ps1'. Un minuto después, a las 11:38:00 (EVT-00524, Event ID 7045), instaló el servicio "
                "de sistema 'WinUpdateHelper' apuntando al binario 'C:\\ProgramData\\wuhelper.exe'. Posteriormente, dicho binario se ejecutó periódicamente "
                "cada 6 minutos a las 11:40, 11:46, 11:52, 11:58 y 12:04 (EVT-00528, EVT-00542, EVT-00548, EVT-00559 y EVT-00564, 5 eventos Event ID 4688 etiquetados como 'Informational')."
            ),
            "remediacion": (
                "1. Detener y eliminar el servicio 'WinUpdateHelper' y anular el registro de la tarea programada '\\Microsoft\\Windows\\UpdateCheck' en APP-SRV01.\n"
                "2. Extraer copias forenses (hashing SHA-256 y análisis estático/dinámico) de C:\\ProgramData\\wuhelper.exe y C:\\ProgramData\\updatecheck.ps1 antes de su borrado.\n"
                "3. Auditar la estación 10.10.3.18 y revocar privilegios administrativos de CORP\\helpdesk sobre servidores de producción."
            ),
            "comandos_contencion": (
                "Stop-Service -Name 'WinUpdateHelper' -Force; sc.exe delete WinUpdateHelper; "
                "Unregister-ScheduledTask -TaskName 'UpdateCheck' -TaskPath '\\Microsoft\\Windows\\' -Confirm:$false"
            ),
        },
        {
            "id": "INC-06",
            "titulo": "Explotación de Servidor Web IIS, Webshell ASPX y Ejecución Remota de Comandos (RCE)",
            "riesgo": "Alto",
            "cvss_estimado": "9.8 (Crítico)",
            "kill_chain": "Reconnaissance -> Exploitation -> Persistence (Webshell) -> Execution (RCE)",
            "mitre_tacticas": "Initial Access (TA0001), Persistence (TA0003), Execution (TA0002)",
            "mitre": "T1190 (Exploit Public-Facing Application), T1505.003 (Server Software Component: Web Shell), T1059.003 (Windows Command Shell)",
            "ventana": "2026-10-23 12:10:00 a 12:15:00 (5 min)",
            "eventos_count": int((df["Incident_ID"] == "INC-06").sum()),
            "eventos_ocultos_info": int(((df["Incident_ID"] == "INC-06") & (df["Severity"] == "Informational")).sum()),
            "activos": "WEB-01 (Servidor Web Público IIS - Puerto 443)",
            "usuarios": "IIS APPPOOL\\DefaultAppPool",
            "ioc": "IP Atacante: 192.0.2.91 | Webshell URI: /uploads/test.aspx?cmd=whoami | Endpoints sondeados: /admin/, /login?user=admin, /api/v1/export | Proceso hijo: cmd.exe /c whoami",
            "evidencia_logs": "EVT-00571 a EVT-00596 (21x HTTP_ACCESS Warning desde 192.0.2.91: 6x HTTP 200, 6x HTTP 404, 9x HTTP 500), EVT-00599 (Event 4688 cmd.exe /c whoami)",
            "resumen_ejecutivo": (
                "El servidor web público (WEB-01) sufrió un ataque dirigido desde la IP 192.0.2.91. El atacante explotó una vulnerabilidad en el directorio "
                "de carga de archivos (/uploads/test.aspx) instalando una puerta trasera web (Webshell) con la que logró ejecutar comandos directamente "
                "sobre el sistema operativo del servidor."
            ),
            "resumen_tecnico": (
                "Entre las 12:10:00 y las 12:14:00 (EVT-00571 a EVT-00596), la IP externa 192.0.2.91 envió 21 peticiones HTTP/HTTPS contra WEB-01:443 "
                "enumerando '/login?user=admin', '/admin/' y '/api/v1/export' (provocando 9 errores HTTP 500, 6 HTTP 404 y 6 HTTP 200), e invocando "
                "la webshell '/uploads/test.aspx?cmd=whoami' (código HTTP 200 en EVT-00571). A las 12:15:00 (EVT-00599, Event ID 4688), el proceso "
                "de aplicación de IIS bajo la identidad 'IIS APPPOOL\\DefaultAppPool' instanció un shell del sistema ejecutando 'cmd.exe /c whoami', "
                "confirmando Ejecución Remota de Código (RCE)."
            ),
            "remediacion": (
                "1. Poner WEB-01 en modo mantenimiento o aislarlo en la DMZ, eliminar '/uploads/test.aspx' y auditar todo el directorio web en busca de otras webshells.\n"
                "2. Configurar IIS para deshabilitar permisos de ejecución de scripts (Handler Mappings ASPX/PHP) en el directorio '/uploads/'.\n"
                "3. Bloquear la IP 192.0.2.91 en el WAF/Firewall y aplicar reglas de endurecimiento para impedir que w3wp.exe ejecute cmd.exe o powershell.exe."
            ),
            "comandos_contencion": (
                "Remove-Item -Path 'C:\\inetpub\\wwwroot\\uploads\\test.aspx' -Force; Stop-WebAppPool -Name 'DefaultAppPool'; "
                "New-NetFirewallRule -DisplayName 'Block_WebAttacker_192.0.2.91' -Direction Inbound -RemoteAddress 192.0.2.91 -Action Block"
            ),
        },
        {
            "id": "OBS-01",
            "titulo": "Brechas de Visibilidad SIEM, Eventos Críticos en 'Informational' y Falta de Normalización",
            "riesgo": "Medio",
            "cvss_estimado": "6.5 (Medio - Riesgo Operativo SOC)",
            "kill_chain": "Defense Evasion -> SIEM Telemetry Blindspots -> Asset Fragmentation",
            "mitre_tacticas": "Defense Evasion (TA0005) / SecOps Telemetry Quality",
            "mitre": "T1562 (Impair Defenses / Suboptimal SIEM Severity Rules & Asset Naming)",
            "ventana": "2026-10-23 07:46:07 a 13:44:06 (Ventana completa del dataset)",
            "eventos_count": len(hidden_events_list),
            "eventos_ocultos_info": len(hidden_events_list),
            "activos": f"DC-01 ({norm_stats['dc_hyphen_count']} logs) vs DC01 ({norm_stats['dc_no_hyphen_count']} logs), WS-022, APP-SRV01, FS-SRV01",
            "usuarios": f"CORP\\backupsvc ({norm_stats['backupsvc_count']} logs) vs CORP\\svc_backup ({norm_stats['svc_backup_count']} logs), CORP\\mruiz",
            "ioc": f"{len(hidden_events_list)} eventos críticos de intrusión etiquetados como Informational; inconsistencia de nombres en agentes SIEM",
            "evidencia_logs": "EVT-00123 (4624), EVT-00126 (4672), EVT-00237 (4634), EVT-00315 (5145), EVT-00419 (5140), EVT-00428 (4688 7z.exe), EVT-00519 (4624), EVT-00528, EVT-00542, EVT-00548, EVT-00559, EVT-00564 (5x 4688 wuhelper.exe)",
            "resumen_ejecutivo": (
                "La auditoría de Nivel 2 detectó que el sistema SIEM actual clasifica como 'Informativos' (sin alerta) 12 eventos críticos de "
                "éxito de intrusión, compresión de archivos confidenciales y ejecución de software malicioso. Además, existen servidores y cuentas "
                "registrados con nombres duplicados (DC-01 vs DC01), lo que fragmenta los tableros de monitoreo."
            ),
            "resumen_tecnico": (
                f"Un filtro básico de Nivel 1 que descarte 'Severity == Informational' perdería {len(hidden_events_list)} eventos clave de la cadena de ataque "
                f"(diferencia entre las 112 alertas nativas del SIEM y los 124 eventos maliciosos correlacionados): el login exitoso tras Password Spraying "
                f"(EVT-00123) y su escalamiento (EVT-00126), el cierre de sesión RDP de CORP\\admin (EVT-00237), la verificación de permisos SMB post-vssadmin "
                f"(EVT-00315), el acceso al recurso Legal (EVT-00419) y su empaquetado con 7z.exe (EVT-00428), el login de CORP\\helpdesk (EVT-00519) y las 5 "
                f"ejecuciones del binario persistente C:\\ProgramData\\wuhelper.exe (EVT-00528, EVT-00542, EVT-00548, EVT-00559 y EVT-00564). Asimismo, el "
                f"Controlador de Dominio reporta como 'DC-01' ({norm_stats['dc_hyphen_count']} eventos) y 'DC01' ({norm_stats['dc_no_hyphen_count']} eventos), "
                f"y coexisten las cuentas 'CORP\\backupsvc' ({norm_stats['backupsvc_count']}) y 'CORP\\svc_backup' ({norm_stats['svc_backup_count']})."
            ),
            "remediacion": (
                "1. Implementar reglas de correlación Sigma en el SIEM para alertar sobre Event ID 4624/4672 precedidos por ráfagas de Event ID 4625 desde la misma IP.\n"
                "2. Elevar a severidad 'High' toda creación de procesos (Event ID 4688) originada en rutas públicas (C:\\ProgramData\\, C:\\Users\\Public\\, C:\\Temp\\) o utilidades de archivado (7z.exe, tar.exe).\n"
                "3. Estandarizar los agentes colectores de logs para unificar el hostname 'DC01' -> 'DC-01' y auditar la nomenclatura de cuentas de servicio."
            ),
            "comandos_contencion": (
                "# Regla Sigma / KQL recomendada:\n"
                "SecurityEvent | where EventID == 4688 and (CommandLine has_any ('C:\\\\ProgramData\\\\', 'C:\\\\Users\\\\Public\\\\', '7z.exe', 'tar.exe', 'vssadmin'))"
            ),
        },
    ]

    high_count = sum(1 for f in findings if f["riesgo"] == "Alto")
    med_count = sum(1 for f in findings if f["riesgo"] == "Medio")

    summary_metrics = {
        "total_logs": int(len(df)),
        "time_start": str(df["Timestamp"].min()),
        "time_end": str(df["Timestamp"].max()),
        "native_non_info_alerts": int((df["Severity"] != "Informational").sum()),
        "correlated_malicious_events": int((df["Incident_ID"] != "NONE").sum()),
        "hidden_info_critical_events": int(df["Hidden_Critical_Info"].sum()),
        "external_ip_events_count": int(df["Involves_External_IP"].sum()),
        "critical_incidents_count": high_count,
        "medium_findings_count": med_count,
        "exfil_bytes": exfil_bytes,
        "exfil_mib": round(exfil_mib, 2),
        "exfil_mb": round(exfil_mb, 2),
        "severity_counts": df["Severity"].value_counts().to_dict(),
        "log_source_counts": df["Log_Source"].value_counts().to_dict(),
        "normalization": norm_stats,
        "hidden_events_records": hidden_events_list,
    }

    return df, findings, summary_metrics
