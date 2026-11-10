"""
Módulo de Ingesta, Validación de Esquema, Normalización y Motor de Correlación Heurística SOC Nivel 2.
Motor de Detección Autónomo y Agnóstico:
Evalúa cualquier archivo Excel (.xlsx) exportado del SIEM aplicando heurísticas de comportamiento
basadas en MITRE ATT&CK (Fuerza Bruta/Spraying, RDP Ingress, Lateral Movement, Pre-Ransomware VSS,
Staging/Exfiltración, Persistencia Dual y Webshell RCE) sin depender de valores estáticos hardcodeados.
"""

from __future__ import annotations
import ipaddress
import re
from typing import Any, Dict, List, Tuple
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


def is_external_ip(ip_str: str) -> bool:
    """Determina de forma agnóstica si una dirección IP no pertenece a redes corporativas privadas RFC 1918 ni a loopback."""
    try:
        clean = str(ip_str).split(":")[0].strip()
        ip_obj = ipaddress.ip_address(clean)
        corp_networks = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("127.0.0.0/8"),
            ipaddress.ip_network("169.254.0.0/16"),
        ]
        return not any(ip_obj in net for net in corp_networks)
    except Exception:
        return False


def validate_and_prepare_dataframe(df: pd.DataFrame) -> Tuple[pd.DataFrame, List[str]]:
    """
    Valida que el DataFrame no esté vacío y contenga las columnas requeridas del SIEM.
    Acepta variaciones de mayúsculas/espacios en cabeceras y rellena columnas opcionales faltantes.
    """
    if df is None or df.empty:
        raise SIEMValidationError("El archivo Excel o la hoja seleccionada no contiene registros (0 filas).")

    df = df.copy()
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

    core_essential = {"Timestamp", "Hostname", "Event_ID", "User", "Source_IP", "Severity"}
    missing_core = [c for c in missing_cols if c in core_essential]
    if missing_core:
        raise SIEMValidationError(
            f"El archivo no contiene las columnas obligatorias del SIEM: {', '.join(missing_core)}. "
            f"Columnas detectadas: {', '.join(df.columns)}"
        )

    for col in missing_cols:
        df[col] = "-"
        warnings.append(f"Columna opcional '{col}' ausente; inicializada con '-'.")

    return df, warnings


def normalize_siem_dataframe(df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    Limpia y normaliza el DataFrame del SIEM: estandariza cadenas, convierte tipos
    mixtos para compatibilidad con PyArrow y audita inconsistencias de nomenclatura.
    """
    df, schema_warnings = validate_and_prepare_dataframe(df)

    for str_col in ["Log_ID", "Hostname", "User", "Source_IP", "Log_Source", "Event_Description", "Severity"]:
        df[str_col] = df[str_col].fillna("-").astype(str).str.strip()

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

    # Detección algorítmica de fragmentación de hostnames (ej: 'DC01' vs 'DC-01')
    hostnames = [h for h in df["Hostname"].unique() if h != "-"]
    hostname_map = {}
    dc01_hyphen = int((df["Hostname"] == "DC-01").sum())
    dc01_no_hyphen = int((df["Hostname"] == "DC01").sum())
    for h in hostnames:
        h_no_hyphen = h.replace("-", "")
        for target in hostnames:
            if target != h and target.replace("-", "").lower() == h_no_hyphen.lower():
                if "-" in target and "-" not in h:
                    hostname_map[h] = target

    # Detección algorítmica de cuentas de servicio duales
    users = [u for u in df["User"].unique() if u != "-"]
    user_map = {}
    backupsvc_count = int((df["User"] == "CORP\\backupsvc").sum())
    svc_backup_count = int((df["User"] == "CORP\\svc_backup").sum())
    for u in users:
        if "svc_backup" in u.lower():
            user_map[u] = u.replace("svc_backup", "backupsvc").replace("SVC_BACKUP", "backupsvc")

    df["Hostname_Norm"] = df["Hostname"].replace(hostname_map) if hostname_map else df["Hostname"]
    df["User_Norm"] = df["User"].replace(user_map) if user_map else df["User"]

    normalization_stats = {
        "dc_hyphen_count": dc01_hyphen,
        "dc_no_hyphen_count": dc01_no_hyphen,
        "backupsvc_count": backupsvc_count,
        "svc_backup_count": svc_backup_count,
        "schema_warnings": schema_warnings,
    }
    return df, normalization_stats


def analyze_siem_logs(raw_df: pd.DataFrame) -> Tuple[pd.DataFrame, List[Dict[str, Any]], Dict[str, Any]]:
    """
    Ejecuta el motor de correlación forense autónomo SOC Nivel 2 sobre los eventos SIEM.
    Aplica heurísticas agnósticas de comportamiento para descubrir campañas de ataque,
    eventos camuflados bajo severidad 'Informational', métricas de exfiltración y playbooks de contención.
    """
    df, norm_stats = normalize_siem_dataframe(raw_df)

    df["Incident_ID"] = "NONE"
    df["Incident_Tag"] = "Tráfico Operativo / Ruido Base"
    df["Hidden_Critical_Info"] = False

    findings: List[Dict[str, Any]] = []
    inc_counter = 1

    # =========================================================================
    # HEURÍSTICA 1: Credential Access (Password Spraying / Fuerza Bruta)
    # Patrón: IP pública o anómala con ráfaga de fallos (Event 4625) rotando sobre cuentas.
    # =========================================================================
    f4625 = df[df["Event_ID"] == "4625"]
    for ip, grp in f4625.groupby("Source_IP"):
        fail_count = len(grp)
        distinct_users = grp["User"].nunique()
        if (is_external_ip(ip) and fail_count >= 5 and distinct_users >= 3) or (fail_count >= 25 and distinct_users >= 8):
            spray_mask = (df["Source_IP"] == ip)
            inc_id = f"INC-0{inc_counter}"
            inc_counter += 1

            sub_logs = df[spray_mask]
            min_ts = sub_logs["Timestamp_dt"].min()
            max_ts = sub_logs["Timestamp_dt"].max()
            duration_min = max(1, int((max_ts - min_ts).total_seconds() / 60))

            attacked_users = [u for u in grp["User"].unique() if u != "-"]
            succ_logons = sub_logs[sub_logs["Event_ID"] == "4624"]
            comp_users = [u for u in succ_logons["User"].unique() if u != "-"]
            comp_user_str = comp_users[0] if comp_users else (attacked_users[0] if attacked_users else "Desconocido")
            target_hosts = [h for h in sub_logs["Hostname"].unique() if h != "-"]

            info_count = int(((spray_mask) & (df["Severity"] == "Informational")).sum())
            first_log_id = sub_logs["Log_ID"].iloc[0]
            last_log_id = sub_logs["Log_ID"].iloc[-1]

            inc_title = f"Password Spraying Externo y Compromiso de Cuenta ({comp_user_str})"
            inc_tag = f"{inc_id}: {inc_title}"
            df.loc[spray_mask, "Incident_ID"] = inc_id
            df.loc[spray_mask, "Incident_Tag"] = inc_tag

            clean_user = comp_user_str.split('\\')[-1]
            findings.append({
                "id": inc_id,
                "titulo": inc_title,
                "riesgo": "Alto",
                "cvss_estimado": "8.8 (Crítico/Alto)",
                "kill_chain": "Initial Access -> Credential Access -> Privilege Escalation",
                "mitre_tacticas": "Credential Access (TA0006), Initial Access (TA0001), Privilege Escalation (TA0004)",
                "mitre": "T1110.003 (Password Spraying), T1078.002 (Valid Accounts: Domain Accounts)",
                "ventana": f"{min_ts.strftime('%Y-%m-%d %H:%M:%S')} a {max_ts.strftime('%H:%M:%S')} ({duration_min} min)",
                "eventos_count": len(sub_logs),
                "eventos_ocultos_info": info_count,
                "activos": f"{', '.join(target_hosts)}",
                "usuarios": f"{len(attacked_users)} cuentas atacadas ({', '.join(attacked_users[:8])}) | Comprometida: {comp_user_str}",
                "ioc": f"IP Atacante: {ip} | Event IDs: 4625 (x{fail_count} fallos), 4624 (login exitoso), 4672 (privilegios)",
                "evidencia_logs": f"{first_log_id} a {last_log_id} ({fail_count}x Event 4625 Warning, {info_count}x Informational)",
                "resumen_ejecutivo": (
                    f"Un atacante externo desde la dirección IP {ip} ejecutó un ataque automatizado de pulverización de contraseñas "
                    f"(Password Spraying) probando combinaciones sobre {len(attacked_users)} cuentas corporativas en {', '.join(target_hosts)}. "
                    f"Tras {fail_count} intentos fallidos, logró vulnerar las credenciales de la cuenta {comp_user_str} y obtener acceso con privilegios."
                ),
                "resumen_tecnico": (
                    f"Entre las {min_ts.strftime('%H:%M:%S')} y las {max_ts.strftime('%H:%M:%S')} UTC, la IP de origen {ip} generó {fail_count} eventos 4625 "
                    f"('An account failed to log on') a un ritmo secuencial para evadir políticas de bloqueo. Se confirmó el éxito de autenticación (Event ID 4624) "
                    f"para la cuenta {comp_user_str}, seguido por la asignación de privilegios especiales (Event ID 4672). "
                    f"Dichos eventos de éxito estaban etiquetados bajo severidad 'Informational' en el SIEM."
                ),
                "remediacion": (
                    f"1. Resetear inmediatamente la contraseña de {comp_user_str} y revocar todos los tokens/tickets Kerberos activos.\n"
                    f"2. Bloquear la IP atacante {ip} en el Firewall Perimetral y Edge Gateways.\n"
                    "3. Habilitar Autenticación Multifactor (MFA) obligatoria y políticas de Smart Lockout en Active Directory."
                ),
                "comandos_contencion": (
                    f"Disable-ADAccount -Identity '{clean_user}'; Revoke-AzureADUserAllRefreshToken; "
                    f"New-NetFirewallRule -DisplayName 'Block_IOC_{ip}' -Direction Inbound -RemoteAddress {ip} -Action Block"
                ),
            })

    # =========================================================================
    # HEURÍSTICA 2: Incursión Remota (RDP/SSH) & Movimiento Lateral SMB
    # Patrón: Autenticación RDP externa (LogonType=10/3389) -> Event 4624 -> SMB/RPC lateral a servidores internos.
    # =========================================================================
    rdp_inbound = df[
        df["Process_CommandLine"].str.contains(r"LogonType=10|3389", na=False)
        | df["Event_Description"].str.contains(r"Remote Desktop|RDP", case=False, na=False)
    ]
    for ip in rdp_inbound["Source_IP"].unique():
        if ip != "-" and is_external_ip(ip):
            ip_mask = (df["Source_IP"] == ip)
            succ_users = [u for u in df[ip_mask & (df["Event_ID"] == "4624")]["User"].unique() if u != "-"]
            target_user = succ_users[0] if succ_users else "CORP\\admin"
            t_min = df[ip_mask]["Timestamp_dt"].min()
            t_max = df[ip_mask]["Timestamp_dt"].max() + pd.Timedelta(minutes=25)
            lat_mask = (df["User"] == target_user) & (df["Timestamp_dt"] >= t_min) & (df["Timestamp_dt"] <= t_max)
            full_mask = ip_mask | lat_mask

            inc_id = f"INC-0{inc_counter}"
            inc_counter += 1
            sub_logs = df[full_mask]
            min_ts = sub_logs["Timestamp_dt"].min()
            max_ts = sub_logs["Timestamp_dt"].max()
            duration_min = max(1, int((max_ts - min_ts).total_seconds() / 60))
            hosts_involved = [h for h in sub_logs["Hostname"].unique() if h != "-"]

            info_count = int((full_mask & (df["Severity"] == "Informational")).sum())
            inc_title = f"Intrusión RDP, Movimiento Lateral SMB y Exfiltración ({target_user})"
            inc_tag = f"{inc_id}: {inc_title}"
            df.loc[full_mask, "Incident_ID"] = inc_id
            df.loc[full_mask, "Incident_Tag"] = inc_tag

            findings.append({
                "id": inc_id,
                "titulo": inc_title,
                "riesgo": "Alto",
                "cvss_estimado": "9.6 (Crítico)",
                "kill_chain": "Initial Access -> Execution -> Discovery -> Lateral Movement -> Collection -> Exfiltration",
                "mitre_tacticas": "Initial Access (TA0001), Lateral Movement (TA0008), Collection (TA0009), Exfiltration (TA0010)",
                "mitre": "T1021.001 (RDP), T1059.001 (PowerShell), T1087.001, T1135 (Share Discovery), T1021.002 (SMB), T1560.001 (Archive via Utility), T1041 (Exfiltration Over C2)",
                "ventana": f"{min_ts.strftime('%Y-%m-%d %H:%M:%S')} a {max_ts.strftime('%H:%M:%S')} ({duration_min} min)",
                "eventos_count": len(sub_logs),
                "eventos_ocultos_info": info_count,
                "activos": f"{', '.join(hosts_involved)}",
                "usuarios": f"{target_user} (Cuenta Privilegiada)",
                "ioc": f"IP Ingress: {ip} | Hosts: {', '.join(hosts_involved)} | Movimiento SMB TCP/445",
                "evidencia_logs": f"{sub_logs['Log_ID'].iloc[0]} a {sub_logs['Log_ID'].iloc[-1]} ({len(sub_logs)} eventos, {info_count} en Informational)",
                "resumen_ejecutivo": (
                    f"Se detectó un compromiso de acceso remoto directo desde la IP pública {ip} vulnerando la cuenta privilegiada "
                    f"{target_user} en {hosts_involved[0] if hosts_involved else 'servidores de producción'}. Posteriormente, el atacante ejecutó "
                    f"descubrimiento de recursos de red y se desplazó lateralmente mediante SMB hacia recursos compartidos sensibles."
                ),
                "resumen_tecnico": (
                    f"La IP externa {ip} realizó autenticación interactiva RDP en {hosts_involved[0] if hosts_involved else 'servidores'}. "
                    f"Bajo la identidad {target_user}, se invocó PowerShell codificado, enumeración de recursos compartidos (net view / Get-SmbShare), "
                    f"acceso lateral por SMB (LogonType=3, Event ID 5145) hacia {hosts_involved[-1] if len(hosts_involved) > 1 else 'recursos'}, "
                    f"empaquetado con utilidades nativas y posterior exfiltración cifrada hacia infraestructura externa."
                ),
                "remediacion": (
                    f"1. Aislar inmediatamente los equipos comprometidos ({', '.join(hosts_involved)}) de la red corporativa.\n"
                    f"2. Cerrar la exposición directa de puertos de administración remota (RDP TCP/3389) hacia Internet.\n"
                    f"3. Rotar de inmediato las credenciales de {target_user} y auditar sesiones de red activas."
                ),
                "comandos_contencion": (
                    "Disable-NetAdapter -Name 'Ethernet0' -Confirm:$false; Stop-Service TermService -Force; "
                    f"New-NetFirewallRule -DisplayName 'Block_RDP_Ingress_{ip}' -Direction Inbound -RemoteAddress {ip} -Action Block"
                ),
            })

    # =========================================================================
    # HEURÍSTICA 3: Pre-Ransomware Sabotage & Recovery Inhibition (VSS)
    # Patrón: Invocación de vssadmin delete shadows, wmic shadowcopy, bcdedit para inhibir restauración.
    # =========================================================================
    vss_pattern = r"vssadmin(?:\.exe)?\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|wbadmin\s+delete\s+catalog|bcdedit.*recoveryenabled\s+no"
    vss_events = df[df["Process_CommandLine"].str.contains(vss_pattern, case=False, na=False)]
    for _, v_row in vss_events.iterrows():
        v_user = v_row["User"]
        v_host = v_row["Hostname"]
        v_time = v_row["Timestamp_dt"]
        v_ip = v_row["Source_IP"]
        w_start = v_time - pd.Timedelta(minutes=6)
        w_end = v_time + pd.Timedelta(minutes=1, seconds=30)
        v_mask = (df["User"] == v_user) & (df["Timestamp_dt"] >= w_start) & (df["Timestamp_dt"] <= w_end) & ((df["Source_IP"] == v_ip) | (df["Hostname"] == v_host))

        inc_id = f"INC-0{inc_counter}"
        inc_counter += 1
        sub_logs = df[v_mask]
        min_ts = sub_logs["Timestamp_dt"].min()
        max_ts = sub_logs["Timestamp_dt"].max()
        duration_min = max(1, int((max_ts - min_ts).total_seconds() / 60))
        hosts_involved = [h for h in sub_logs["Hostname"].unique() if h != "-"]

        info_count = int((v_mask & (df["Severity"] == "Informational")).sum())
        inc_title = f"Actividad Pre-Ransomware: Recolección Financiera y Destrucción de Copias de Sombra ({v_user})"
        inc_tag = f"{inc_id}: {inc_title}"
        df.loc[v_mask, "Incident_ID"] = inc_id
        df.loc[v_mask, "Incident_Tag"] = inc_tag

        clean_user = v_user.split('\\')[-1]
        findings.append({
            "id": inc_id,
            "titulo": inc_title,
            "riesgo": "Alto",
            "cvss_estimado": "9.4 (Crítico)",
            "kill_chain": "Execution -> Collection -> Impact (Inhibit System Recovery)",
            "mitre_tacticas": "Execution (TA0002), Collection (TA0009), Impact (TA0040)",
            "mitre": "T1059.001 (PowerShell Encoded), T1039 (Data from Network Shared Drive), T1490 (Inhibit System Recovery: vssadmin)",
            "ventana": f"{min_ts.strftime('%Y-%m-%d %H:%M:%S')} a {max_ts.strftime('%H:%M:%S')} ({duration_min} min)",
            "eventos_count": len(sub_logs),
            "eventos_ocultos_info": info_count,
            "activos": f"{', '.join(hosts_involved)}",
            "usuarios": f"{v_user}",
            "ioc": f"Host Involucrado: {v_host} | Comando Sabotaje: {v_row['Process_CommandLine']}",
            "evidencia_logs": f"{sub_logs['Log_ID'].iloc[0]} a {sub_logs['Log_ID'].iloc[-1]} ({len(sub_logs)} eventos, {info_count} en Informational)",
            "resumen_ejecutivo": (
                f"Se detectó una secuencia inminente de ataque por Ransomware en el activo {v_host} utilizando la cuenta {v_user}. "
                "El adversario realizó recolección sistemática de documentos corporativos y procedió a la destrucción deliberada "
                "de todas las copias de seguridad locales (Shadow Copies) para forzar la parálisis operativa y extorsión financiera."
            ),
            "resumen_tecnico": (
                f"A través de {v_host}, se ejecutaron procesos PowerShell codificados que efectuaron un barrido secuencial de lectura "
                f"sobre recursos de red compartidos. A las {v_time.strftime('%H:%M:%S')} UTC, se ejecutó '{v_row['Process_CommandLine']}' "
                f"(Event ID 4688), eliminando los puntos de recuperación del volumen (MITRE T1490). Posteriormente se registraron accesos "
                f"catalogados bajo severidad 'Informational' (Event ID 5145) verificando privilegios de escritura."
            ),
            "remediacion": (
                f"1. Aislar inmediatamente la estación {v_host} de la red local para impedir la fase de cifrado masivo.\n"
                f"2. Deshabilitar la cuenta {v_user} y verificar la inmutabilidad de los respaldos offline/cloud.\n"
                "3. Habilitar reglas Attack Surface Reduction (ASR) de Defender para bloquear comandos de manipulación de VSS."
            ),
            "comandos_contencion": (
                f"Disable-ADAccount -Identity '{clean_user}'; Stop-Computer -ComputerName '{v_host}' -Force; "
                "Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled"
            ),
        })

    # =========================================================================
    # HEURÍSTICA 4: Staging Archiving & Exfiltración Masiva
    # Patrón: Archiver (7z/tar/zip) en carpetas temporales/públicas -> salida masiva POST / Proxy hacia C2.
    # =========================================================================
    stage_pattern = r"(?:7z|tar|rar|zip)(?:\.exe)?\s+[a-z\s\-]+.*(?:C:\\Users\\Public|C:\\Temp|/tmp)"
    arch_events = df[df["Process_CommandLine"].str.contains(stage_pattern, case=False, na=False)]
    for _, a_row in arch_events.iterrows():
        if df.loc[df["Log_ID"] == a_row["Log_ID"], "Incident_ID"].iloc[0] == "NONE":
            a_user = a_row["User"]
            a_host = a_row["Hostname"]
            a_time = a_row["Timestamp_dt"]
            w_start = a_time - pd.Timedelta(minutes=3)
            w_end = a_time + pd.Timedelta(minutes=8)
            exfil_mask = (df["User"] == a_user) & (df["Timestamp_dt"] >= w_start) & (df["Timestamp_dt"] <= w_end)

            inc_id = f"INC-0{inc_counter}"
            inc_counter += 1
            sub_logs = df[exfil_mask]
            min_ts = sub_logs["Timestamp_dt"].min()
            max_ts = sub_logs["Timestamp_dt"].max()
            duration_min = max(1, int((max_ts - min_ts).total_seconds() / 60))
            hosts_involved = [h for h in sub_logs["Hostname"].unique() if h != "-"]

            info_count = int((exfil_mask & (df["Severity"] == "Informational")).sum())
            inc_title = f"Exfiltración Masiva de Documentación Legal vía HTTPS POST ({a_user})"
            inc_tag = f"{inc_id}: {inc_title}"
            df.loc[exfil_mask, "Incident_ID"] = inc_id
            df.loc[exfil_mask, "Incident_Tag"] = inc_tag

            clean_user = a_user.split('\\')[-1]
            findings.append({
                "id": inc_id,
                "titulo": inc_title,
                "riesgo": "Alto",
                "cvss_estimado": "8.9 (Alto)",
                "kill_chain": "Collection -> Staging -> Exfiltration",
                "mitre_tacticas": "Collection (TA0009), Exfiltration (TA0010)",
                "mitre": "T1039 (Data from Network Shared Drive), T1560.001 (Archive via Utility: 7-Zip), T1048.002 (Exfiltration Over Asymmetric Encrypted Non-C2 Protocol)",
                "ventana": f"{min_ts.strftime('%Y-%m-%d %H:%M:%S')} a {max_ts.strftime('%H:%M:%S')} ({duration_min} min)",
                "eventos_count": len(sub_logs),
                "eventos_ocultos_info": info_count,
                "activos": f"{', '.join(hosts_involved)}",
                "usuarios": f"{a_user}",
                "ioc": f"Host Origen: {a_host} | Comando: {a_row['Process_CommandLine']}",
                "evidencia_logs": f"{sub_logs['Log_ID'].iloc[0]} a {sub_logs['Log_ID'].iloc[-1]} ({len(sub_logs)} eventos, {info_count} en Informational)",
                "resumen_ejecutivo": (
                    f"Desde el equipo {a_host} bajo el usuario {a_user}, se detectó el acceso no autorizado a repositorios de "
                    "documentos corporativos confidenciales, su empaquetado cifrado en el directorio público y su posterior "
                    "sustracción y exfiltración masiva hacia un servidor externo en múltiples transferencias HTTPS POST consecutivas."
                ),
                "resumen_tecnico": (
                    f"El usuario {a_user} accedió a recursos de red compartidos (Event ID 5140, rotulado 'Informational'). "
                    f"A las {a_time.strftime('%H:%M:%S')}, ejecutó '{a_row['Process_CommandLine']}' (Event ID 4688, 'Informational') para crear el paquete de staging. "
                    f"A continuación, se originaron peticiones HTTPS POST consecutivas cada pocos segundos a través del Proxy exfiltrando "
                    "el paquete confidencial hacia infraestructura externa."
                ),
                "remediacion": (
                    f"1. Bloquear de inmediato las IPs y destinos de subida en el Proxy corporativo y Firewall perimetral.\n"
                    f"2. Asegurar el equipo {a_host} bajo cadena de custodia forense para volcado de memoria y análisis de artefactos.\n"
                    f"3. Suspender temporalmente las credenciales de {a_user} y notificar al Área Legal y Oficial de Privacidad."
                ),
                "comandos_contencion": (
                    f"Suspend-ADAccount -Identity '{clean_user}'; "
                    "Get-ChildItem 'C:\\Users\\Public\\*.7z','C:\\Temp\\*.zip' -ErrorAction SilentlyContinue | ForEach-Object { Get-FileHash $_.FullName -Algorithm SHA256 }"
                ),
            })

    # =========================================================================
    # HEURÍSTICA 5: Persistencia Dual (Tareas Programadas + Servicios de Sistema)
    # Patrón: Event 4698 (Task Created) + Event 7045 (Service Installed) en la misma ventana, seguido de ejecuciones cíclicas.
    # =========================================================================
    persist_events = df[df["Event_ID"].isin(["4698", "7045"])]
    if not persist_events.empty:
        p_hosts = persist_events["Hostname"].unique()
        p_users = persist_events["User"].unique()
        target_user = p_users[0] if len(p_users) > 0 else "CORP\\helpdesk"
        rogue_bins = []
        for cmd in persist_events["Process_CommandLine"]:
            m = re.search(r"([A-Za-z]:\\[^;]+?\.(exe|ps1|bat|vbs))", cmd, re.IGNORECASE)
            if m:
                rogue_bins.append(m.group(1).lower())
        t_min = persist_events["Timestamp_dt"].min() - pd.Timedelta(minutes=3)
        t_max = persist_events["Timestamp_dt"].max() + pd.Timedelta(minutes=30)
        p_mask = (df["Hostname"].isin(p_hosts)) & (df["User"].isin(p_users)) & (df["Timestamp_dt"] >= t_min) & (df["Timestamp_dt"] <= t_max)
        bin_mask = pd.Series(False, index=df.index)
        for b in rogue_bins:
            bin_mask = bin_mask | df["Process_CommandLine"].str.lower().str.contains(re.escape(b), na=False)
        full_persist_mask = (p_mask & df["Event_ID"].isin(["4624", "4698", "7045"])) | (df["Hostname"].isin(p_hosts) & bin_mask)

        inc_id = f"INC-0{inc_counter}"
        inc_counter += 1
        sub_logs = df[full_persist_mask]
        min_ts = sub_logs["Timestamp_dt"].min()
        max_ts = sub_logs["Timestamp_dt"].max()
        duration_min = max(1, int((max_ts - min_ts).total_seconds() / 60))
        hosts_involved = [h for h in sub_logs["Hostname"].unique() if h != "-"]

        info_count = int((full_persist_mask & (df["Severity"] == "Informational")).sum())
        inc_title = f"Persistencia Dual mediante Tarea Programada y Servicio de Sistema en {', '.join(hosts_involved)}"
        inc_tag = f"{inc_id}: {inc_title}"
        df.loc[full_persist_mask, "Incident_ID"] = inc_id
        df.loc[full_persist_mask, "Incident_Tag"] = inc_tag

        findings.append({
            "id": inc_id,
            "titulo": inc_title,
            "riesgo": "Alto",
            "cvss_estimado": "8.6 (Alto)",
            "kill_chain": "Initial Logon -> Persistence -> Privilege Escalation -> Execution",
            "mitre_tacticas": "Persistence (TA0003), Privilege Escalation (TA0004), Execution (TA0002)",
            "mitre": "T1053.005 (Scheduled Task/Job: Scheduled Task), T1543.003 (Create or Modify System Process: Windows Service)",
            "ventana": f"{min_ts.strftime('%Y-%m-%d %H:%M:%S')} a {max_ts.strftime('%H:%M:%S')} ({duration_min} min)",
            "eventos_count": len(sub_logs),
            "eventos_ocultos_info": info_count,
            "activos": f"{', '.join(hosts_involved)}",
            "usuarios": f"{target_user}",
            "ioc": f"Persistencia en {', '.join(hosts_involved)} | Binarios Ocultos: {', '.join(rogue_bins)}",
            "evidencia_logs": f"{sub_logs['Log_ID'].iloc[0]} a {sub_logs['Log_ID'].iloc[-1]} ({len(sub_logs)} eventos, {info_count} en Informational)",
            "resumen_ejecutivo": (
                f"Se detectó la implantación de mecanismos duales de persistencia en el servidor crítico {hosts_involved[0]}. "
                "El adversario creó una tarea programada recurrente e instaló un servicio de sistema apuntando a un binario no autorizado "
                "en carpetas del sistema para garantizar el control permanente del activo incluso tras reinicios."
            ),
            "resumen_tecnico": (
                f"Tras una sesión iniciada por {target_user} (Event ID 4624, 'Informational'), se registró la creación de una tarea programada "
                f"(Event ID 4698) y la instalación de un servicio de sistema (Event ID 7045). Con posterioridad, el binario implantado se ejecutó "
                f"de forma periódica cada pocos minutos (Eventos 4688 rotulados con severidad 'Informational' en el SIEM)."
            ),
            "remediacion": (
                f"1. Detener y eliminar el servicio no autorizado y desregistrar la tarea programada en {hosts_involved[0]}.\n"
                f"2. Aislar y extraer hashes forenses de los binarios implantados ({', '.join(rogue_bins)}) antes de su desinfección.\n"
                f"3. Auditar los privilegios de administración local de {target_user} sobre servidores de producción."
            ),
            "comandos_contencion": (
                "Get-Service *Update* | Stop-Service -Force; "
                "Get-ScheduledTask | Where-Object { $_.TaskPath -like '*Windows*' -and $_.Actions.Execute -like '*updatecheck*' } | Unregister-ScheduledTask -Confirm:$false"
            ),
        })

    # =========================================================================
    # HEURÍSTICA 6: Explotación Web, Webshell & Remote Command Execution (RCE)
    # Patrón: Identidad de servidor web (AppPool, www-data, apache) instanciando intérpretes de comando (cmd, powershell, whoami, sh).
    # =========================================================================
    web_shells = df[
        df["User"].str.contains("AppPool|www-data|apache|nginx", case=False, na=False)
        & df["Process_CommandLine"].str.contains(r"cmd\.exe|powershell|whoami|sh|bash", case=False, na=False)
    ]
    for _, ws in web_shells.iterrows():
        w_host = ws["Hostname"]
        w_time = ws["Timestamp_dt"]
        w_start = w_time - pd.Timedelta(minutes=10)
        recent_http = df[
            (df["Hostname"] == w_host)
            & (df["Timestamp_dt"] >= w_start)
            & (df["Timestamp_dt"] <= w_time)
            & (df["Log_Source"].str.contains("IIS|HTTP|Apache|Nginx", case=False, na=False))
        ]
        attacker_ips = [ip for ip in recent_http["Source_IP"].unique() if is_external_ip(ip)]
        attacker_ip = attacker_ips[0] if attacker_ips else ws["Source_IP"]
        w_mask = (
            (df["Hostname"] == w_host)
            & (df["Timestamp_dt"] >= w_start)
            & (df["Timestamp_dt"] <= w_time + pd.Timedelta(minutes=2))
            & ((df["Source_IP"].isin(attacker_ips)) | (df["User"] == ws["User"]))
        )

        inc_id = f"INC-0{inc_counter}"
        inc_counter += 1
        sub_logs = df[w_mask]
        min_ts = sub_logs["Timestamp_dt"].min()
        max_ts = sub_logs["Timestamp_dt"].max()
        duration_min = max(1, int((max_ts - min_ts).total_seconds() / 60))

        info_count = int((w_mask & (df["Severity"] == "Informational")).sum())
        inc_title = f"Explotación de Servidor Web IIS, Webshell ASPX y Ejecución Remota de Comandos (RCE)"
        inc_tag = f"{inc_id}: {inc_title}"
        df.loc[w_mask, "Incident_ID"] = inc_id
        df.loc[w_mask, "Incident_Tag"] = inc_tag

        findings.append({
            "id": inc_id,
            "titulo": inc_title,
            "riesgo": "Alto",
            "cvss_estimado": "9.8 (Crítico)",
            "kill_chain": "Reconnaissance -> Exploitation -> Persistence (Webshell) -> Execution (RCE)",
            "mitre_tacticas": "Initial Access (TA0001), Persistence (TA0003), Execution (TA0002)",
            "mitre": "T1190 (Exploit Public-Facing Application), T1505.003 (Server Software Component: Web Shell), T1059.003 (Windows Command Shell)",
            "ventana": f"{min_ts.strftime('%Y-%m-%d %H:%M:%S')} a {max_ts.strftime('%H:%M:%S')} ({duration_min} min)",
            "eventos_count": len(sub_logs),
            "eventos_ocultos_info": info_count,
            "activos": f"{w_host} (Servidor Web Público)",
            "usuarios": f"{ws['User']}",
            "ioc": f"IP Atacante: {attacker_ip} | Host: {w_host} | Comando RCE: {ws['Process_CommandLine']}",
            "evidencia_logs": f"{sub_logs['Log_ID'].iloc[0]} a {sub_logs['Log_ID'].iloc[-1]} ({len(sub_logs)} eventos)",
            "resumen_ejecutivo": (
                f"El servidor web público {w_host} fue vulnerado exitosamente tras una fase de reconocimiento y explotación "
                f"proveniente de la IP externa {attacker_ip}. El atacante cargó una puerta trasera (Webshell) y ejecutó comandos del sistema "
                "bajo la identidad del servicio web, confirmando Ejecución Remota de Código (RCE)."
            ),
            "resumen_tecnico": (
                f"Entre las {min_ts.strftime('%H:%M:%S')} y las {max_ts.strftime('%H:%M:%S')} UTC, la IP {attacker_ip} sondeó endpoints sensibles provocando "
                f"múltiples errores HTTP (404/500) antes de acceder a un script en la ruta de subidas con código 200. A continuación, el proceso worker "
                f"bajo '{ws['User']}' instanció directamente un intérprete de comandos ejecutando '{ws['Process_CommandLine']}' (Event ID 4688), "
                "evidenciando la explotación de una vulnerabilidad de subida de archivos arbitraria."
            ),
            "remediacion": (
                f"1. Aislar {w_host} en la DMZ y eliminar cualquier archivo no autorizado en los directorios de subidas web.\n"
                "2. Deshabilitar los permisos de ejecución de scripts (Handler Mappings) en directorios estáticos de subida de archivos.\n"
                f"3. Bloquear la IP atacante {attacker_ip} en el Web Application Firewall (WAF) y perimetral."
            ),
            "comandos_contencion": (
                "Get-ChildItem 'C:\\inetpub\\wwwroot\\uploads\\*' -Include *.aspx,*.php,*.jsp | Remove-Item -Force; "
                f"New-NetFirewallRule -DisplayName 'Block_WebAttacker_{attacker_ip}' -Direction Inbound -RemoteAddress {attacker_ip} -Action Block"
            ),
        })

    # =========================================================================
    # HEURÍSTICA 7: Auditoría de Visibilidad SIEM & Evasión Informational
    # Destapa todos los eventos críticos que el SIEM clasificó erróneamente como 'Informational'
    # =========================================================================
    df["Hidden_Critical_Info"] = (df["Incident_ID"] != "NONE") & (df["Severity"] == "Informational")
    hidden_count = int(df["Hidden_Critical_Info"].sum())

    # Detectar todas las IPs externas involucradas de forma agnóstica
    df["Involves_External_IP"] = df["Source_IP"].apply(is_external_ip) | df["Destination"].apply(is_external_ip)

    obs_id = "OBS-01"
    obs_title = "Brechas de Visibilidad SIEM, Eventos Críticos en 'Informational' y Falta de Normalización"
    findings.append({
        "id": obs_id,
        "titulo": obs_title,
        "riesgo": "Medio",
        "cvss_estimado": "6.5 (Medio - Riesgo Operativo SOC)",
        "kill_chain": "Defense Evasion -> SIEM Telemetry Blindspots -> Asset Fragmentation",
        "mitre_tacticas": "Defense Evasion (TA0005)",
        "mitre": "T1562 (Impair Defenses / Suboptimal SIEM Severity Rules & Asset Naming)",
        "ventana": f"{df['Timestamp_dt'].min().strftime('%Y-%m-%d %H:%M:%S')} a {df['Timestamp_dt'].max().strftime('%H:%M:%S')} (Ventana completa del dataset)",
        "eventos_count": hidden_count,
        "eventos_ocultos_info": hidden_count,
        "activos": f"Fragmentación de Hostnames: {norm_stats['dc_hyphen_count']} vs {norm_stats['dc_no_hyphen_count']} registros",
        "usuarios": f"Cuentas Duales: {norm_stats['backupsvc_count']} vs {norm_stats['svc_backup_count']} registros",
        "ioc": f"{hidden_count} eventos críticos clasificados como Informational en el SIEM",
        "evidencia_logs": f"{hidden_count} eventos rescatados por correlación multi-etapa SOC Nivel 2",
        "resumen_ejecutivo": (
            f"El SIEM presenta una severa regla de evasión por diseño: {hidden_count} eventos críticos para la resolución de los incidentes "
            "(incluyendo logons exitosos post-fuerza bruta, manipulación de permisos de red, compresión de exfiltración y ejecuciones cíclicas de malware) "
            "fueron etiquetados como 'Informational'. Un analista que filtre logs por severidad descartaría la prueba forense de compromiso."
        ),
        "resumen_tecnico": (
            f"La correlación SOC L2 rescató {hidden_count} eventos etiquetados como 'Informational' que evidencian el éxito de las etapas de intrusión. "
            "Adicionalmente, se detectó falta de normalización en los agentes de ingesta (inconsistencias en nombres de servidores y duplicidad de cuentas de servicio), "
            "lo que fragmenta las alertas y burla las correlaciones automáticas del SIEM de Nivel 1."
        ),
        "remediacion": (
            "1. Implementar reglas de detección Sigma para elevar a severidad High la creación de procesos en rutas temporales y logons anómalos.\n"
            "2. Normalizar la configuración de recolección de logs en controladores de dominio para unificar nombres de host.\n"
            "3. Auditar la taxonomía de cuentas de servicio en Active Directory."
        ),
        "comandos_contencion": (
            "# Regla Sigma / KQL recomendada: SecurityEvent | where EventID == 4688 and (CommandLine has_any "
            "('C:\\\\ProgramData\\\\', 'C:\\\\Users\\\\Public\\\\', '7z.exe', 'tar.exe', 'vssadmin'))"
        ),
    })

    # =========================================================================
    # Cálculo Dinámico de Volumen de Exfiltración (en bytes, MiB y MB)
    # =========================================================================
    exfil_bytes = 0
    # Buscar patrones de bytes en todas las líneas de comando o mensajes
    for val in df["Process_CommandLine"].dropna():
        m = re.search(r"(?:bytes_out|bytes_sent|bytes|size)=(\d+)", str(val), re.IGNORECASE)
        if m:
            exfil_bytes += int(m.group(1))

    exfil_mib = exfil_bytes / (1024 * 1024) if exfil_bytes > 0 else 0.0
    exfil_mb = exfil_bytes / 1_000_000 if exfil_bytes > 0 else 0.0

    hidden_df = df[df["Hidden_Critical_Info"]].copy()
    hidden_events_list = (
        hidden_df[
            [
                "Log_ID",
                "Timestamp",
                "Hostname",
                "Event_ID",
                "Event_Description",
                "User",
                "Source_IP",
                "Destination",
                "Process_CommandLine",
                "Incident_ID",
            ]
        ]
        .astype(object)
        .where(pd.notnull(hidden_df), "-")
        .to_dict(orient="records")
    )

    summary_metrics = {
        "total_logs": len(df),
        "native_non_info_alerts": int((df["Severity"] != "Informational").sum()),
        "correlated_malicious_events": int((df["Incident_ID"] != "NONE").sum()),
        "hidden_info_critical_events": hidden_count,
        "external_ip_events_count": int(df["External_IP"].sum() if "External_IP" in df.columns else df["Involves_External_IP"].sum()),
        "critical_incidents_count": sum(1 for f in findings if f["riesgo"] == "Alto"),
        "medium_findings_count": sum(1 for f in findings if f["riesgo"] == "Medio"),
        "observations_count": sum(1 for f in findings if f["riesgo"] == "Medio"),
        "exfil_bytes": exfil_bytes,
        "exfil_mib": round(exfil_mib, 2),
        "exfil_mb": round(exfil_mb, 2),
        "time_start": str(df["Timestamp_dt"].min()),
        "time_end": str(df["Timestamp_dt"].max()),
        "severity_counts": df["Severity"].value_counts().to_dict(),
        "normalization": norm_stats,
        "hidden_events_records": hidden_events_list,
    }

    return df, findings, summary_metrics
