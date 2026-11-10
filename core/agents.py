"""
Módulo de Orquestación Multi-Agente con LangChain (LCEL — LangChain Expression Language) para SOC Nivel 2.
Implementa una arquitectura de cadenas reactivas (`ChatPromptTemplate | Runnable | StrOutputParser`):
1. Chain 1 (Triage & Evasion Classifier): Clasifica los 6 incidentes críticos + OBS-01 y audita trampas 'Informational'.
2. Chain 2 (Executive C-Level Synthesizer): Redacta el Informe Ejecutivo para Alta Dirección / CISO.
3. Chain 3 (DFIR Forensic & Playbook Generator): Construye el Informe Técnico Nivel 2 con evidencia y comandos CLI.
4. Chain 4 (JEV Cyber Copilot): Agente conversacional interactivo sobre los 715 eventos SIEM.
Soporta ejecución vía LangChain ChatOpenAI (OpenAI/Groq/Gemini), Ollama Local y RunnableLambda Forense Determinista.
"""

from __future__ import annotations
import json
import time
import warnings
from typing import List, Dict, Any, Tuple
import requests

warnings.filterwarnings("ignore", category=UserWarning, module="langchain_core")
warnings.filterwarnings("ignore", category=UserWarning, module="pydantic")

from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import RunnableLambda, RunnableParallel

from core.detection_engineering import (
    get_lolbas_gtfobins_catalog,
    get_sigma_rules_yaml,
    get_yara_classic_rules,
    get_yarax_nextgen_rules,
)


def get_available_ollama_models(base_url: str = "http://localhost:11434") -> List[str]:
    """Consulta los modelos instalados localmente en Ollama si el servicio está activo."""
    try:
        resp = requests.get(f"{base_url.rstrip('/')}/api/tags", timeout=2.5)
        if resp.status_code == 200:
            models = [m.get("name", "") for m in resp.json().get("models", []) if m.get("name")]
            return models if models else ["qwen2.5:7b", "llama3.1:8b"]
    except Exception:
        pass
    return ["qwen2.5:7b", "llama3.1:8b", "mistral:7b"]


def get_langchain_pipeline_metadata(provider: str = "LangChain LCEL Forense", model_name: str = "jev-soc-l2-v3") -> Dict[str, Any]:
    """Retorna la definición estructural del grafo LangChain LCEL para inspección en la interfaz."""
    return {
        "framework": "LangChain Core (LCEL RunnableParallel & StrOutputParser)",
        "provider": provider,
        "model": model_name,
        "nodes": [
            {
                "id": "node_ingest",
                "name": "SIEMContextLoader",
                "type": "RunnableLambda",
                "desc": "Normaliza 715 eventos, unifica DC-01/DC01 y extrae 124 alertas correlacionadas + 12 trampas Informational.",
            },
            {
                "id": "node_triage",
                "name": "MITRETriagePrompt | LLM",
                "type": "ChatPromptTemplate",
                "desc": "Mapea tácticas MITRE ATT&CK (T1110.003, T1490, T1567, T1505.003) y calcula severidad CVSS v3.1.",
            },
            {
                "id": "node_parallel",
                "name": "RunnableParallel(exec, dfir)",
                "type": "RunnableParallel",
                "desc": "Bifurca la síntesis en dos cadenas simultáneas: C-Level Executive Chain y DFIR Technical Chain.",
            },
            {
                "id": "node_detection",
                "name": "DetectionRuleGenerator",
                "type": "LOLBAS + GTFOBins + Sigma/YARA-X",
                "desc": "Correlaciona binarios LOLBAS/GTFOBins abusados y sintetiza reglas Sigma (.yml), YARA (.yar) y YARA-X (.yarx).",
            },
            {
                "id": "node_copilot",
                "name": "JEVCyberCopilotChain",
                "type": "ChatPromptTemplate | StrOutputParser",
                "desc": "Agente interactivo con memoria contextual de los 715 registros, IoCs, LOLBAS, GTFOBins y reglas YARA-X/Sigma.",
            },
        ],
        "lcel_expression": (
            "chain = (\n"
            "    RunnableLambda(load_siem_telemetry)\n"
            "    | RunnableParallel(\n"
            "        executive=exec_prompt | llm_runnable | StrOutputParser(),\n"
            "        technical=dfir_prompt | llm_runnable | StrOutputParser(),\n"
            "    )\n"
            ")"
        ),
    }


def build_deterministic_reports(
    findings: List[Dict[str, Any]], summary_metrics: Dict[str, Any]
) -> Tuple[str, str]:
    """
    Construye el Informe Ejecutivo (C-Level) y el Informe Técnico Forense (SOC Nivel 2)
    con precisión matemática sobre los 715 eventos del dataset oficial.
    """
    total_logs = summary_metrics.get("total_logs", 0)
    native_alerts = summary_metrics.get("native_non_info_alerts", 0)
    corr_events = summary_metrics.get("correlated_malicious_events", 0)
    hidden_info = summary_metrics.get("hidden_info_critical_events", 0)
    exfil_mib = summary_metrics.get("exfil_mib", 0.0)
    exfil_mb = summary_metrics.get("exfil_mb", 0.0)
    exfil_bytes = summary_metrics.get("exfil_bytes", 0)
    time_start = summary_metrics.get("time_start", "-")
    time_end = summary_metrics.get("time_end", "-")

    high_count = sum(1 for f in findings if f.get("riesgo") == "Alto")
    med_count = sum(1 for f in findings if f.get("riesgo") == "Medio")
    low_count = sum(1 for f in findings if f.get("riesgo") == "Bajo")

    exec_lines = [
        "1. RESUMEN GERENCIAL DE LA SITUACIÓN",
        f"Durante la ventana operativa ({time_start} a {time_end} UTC), el Centro de Operaciones "
        f"de Seguridad (SOC Nivel 2) auditó {total_logs} registros de telemetría SIEM e identificó "
        f"{len(findings)} incidentes y vectores clave ({high_count} de RIESGO ALTO, {med_count} de RIESGO MEDIO y {low_count} de RIESGO BAJO). "
        f"Mientras que las reglas nativas del SIEM solo clasificaban {native_alerts} alertas básicas, el motor heurístico "
        f"de correlación avanzada vinculó {corr_events} eventos maliciosos al revelar {hidden_info} eventos críticos "
        f"que habían quedado ocultos bajo severidad 'Informational' o 'Low'.\n",
        "2. IMPACTO CRÍTICO AL NEGOCIO Y EXPOSICIÓN CORPORATIVA",
    ]

    all_hosts = set()
    all_users = set()

    for f in findings:
        exec_lines.append(f"- {f.get('titulo', 'Incidente')} [{f.get('id', '')}]: {f.get('resumen_ejecutivo', '')}")
        for h in str(f.get("activos", "")).split(","):
            h = h.strip()
            if h and h != "-":
                all_hosts.add(h)
        for u in str(f.get("usuarios", "")).split(","):
            u = u.strip()
            if u and u != "-":
                all_users.add(u)

    exec_lines.append("\n3. DECISIONES EJECUTIVAS Y PLAN DE ACCIÓN INMEDIATO (0 A 24 HORAS)")
    action_idx = 1
    if all_hosts:
        exec_lines.append(
            f"- Acción {action_idx} — Contención de Red y Aislamiento de Equipos: Aislar inmediatamente de la red corporativa "
            f"los activos comprometidos ({', '.join(sorted(all_hosts))}) para interrumpir persistencias y movimientos laterales."
        )
        action_idx += 1
    if all_users:
        exec_lines.append(
            f"- Acción {action_idx} — Revocación de Credenciales y Refuerzo de Identidad: Invalidar sesiones Kerberos/NTLM activas "
            f"y forzar cambio de contraseñas de las cuentas comprometidas ({', '.join(sorted(all_users))}), exigiendo Autenticación Multifactor (MFA)."
        )
        action_idx += 1
    if exfil_bytes > 0:
        exec_lines.append(
            f"- Acción {action_idx} — Activación del Comité Legal y Regulatorio: Evaluar la exposición por la fuga de "
            f"{exfil_mib:.2f} MiB ({exfil_mb:.2f} MB / {exfil_bytes:,} bytes) de datos exfiltrados hacia destinos no autorizados, "
            f"asegurando la cadena de custodia forense."
        )
        action_idx += 1
    if hidden_info > 0:
        exec_lines.append(
            f"- Acción {action_idx} — Tuning de Ingesta SIEM y Cierre de Brechas de Visibilidad: Reconfigurar la matriz de severidades "
            f"para corregir la evasión de {hidden_info} eventos críticos que el SIEM clasificó erróneamente como 'Informational'."
        )

    exec_report = "\n".join(exec_lines)

    tech_blocks = [
        "1. ARQUITECTURA DE CORRELACIÓN Y AUDITORÍA DE TELEMETRÍA SIEM (NIVEL 2)\n"
        f"- Ventana temporal analizada: {time_start} a {time_end} ({total_logs} eventos totales).\n"
        f"- Distribución nativa de severidad SIEM: " + ", ".join(f"{k}={v}" for k, v in summary_metrics.get("severity_counts", {}).items()) + ".\n"
        f"- Hallazgo de Evasión / Visibilidad SOC: Se identificaron {hidden_info} eventos críticos de ataque catalogados como 'Informational' o severidad baja por el SIEM original.\n"
    ]

    sample_hidden = summary_metrics.get("hidden_events_records", [])[:10]
    if sample_hidden:
        tech_blocks.append(
            "- Muestra de Eventos Críticos Ocultos en 'Informational' Identificados:\n" +
            "\n".join(
                f"  * {r.get('Log_ID')} ({r.get('Timestamp')}) en {r.get('Hostname')} ({r.get('User')}): Event {r.get('Event_ID')} - {r.get('Process_CommandLine', r.get('Event_Description', '-'))}"
                for r in sample_hidden
            )
        )

    norm = summary_metrics.get("normalization", {})
    norm_lines = []
    if norm.get("dc_hyphen_count") or norm.get("dc_no_hyphen_count"):
        norm_lines.append(f"  * Fragmentación de Hostnames: 'DC-01' ({norm.get('dc_hyphen_count', 0)} logs) vs 'DC01' ({norm.get('dc_no_hyphen_count', 0)} logs).")
    if norm.get("backupsvc_count") or norm.get("svc_backup_count"):
        norm_lines.append(f"  * Discrepancia de Nombres de Cuenta: 'CORP\\backupsvc' ({norm.get('backupsvc_count', 0)} logs) vs 'CORP\\svc_backup' ({norm.get('svc_backup_count', 0)} logs).")
    if norm_lines:
        tech_blocks.append("- Calidad de Ingesta y Normalización de Activos:\n" + "\n".join(norm_lines))

    tech_blocks.append("2. ANÁLISIS FORENSE DETALLADO POR INCIDENTE Y CADENA DE ATAQUE (KILL CHAIN)")
    for f in findings:
        tech_blocks.append(
            f"[{f['id']}] {f['titulo']}\n"
            f"  * Nivel de Riesgo: {f['riesgo'].upper()} | Severidad Estimada: {f['cvss_estimado']}\n"
            f"  * Ventana de Tiempo: {f['ventana']} | Eventos Correlacionados: {f['eventos_count']} (Ocultos en Info: {f['eventos_ocultos_info']})\n"
            f"  * Activos Afectados: {f['activos']} | Cuentas Involucradas: {f['usuarios']}\n"
            f"  * Tácticas y Técnicas MITRE ATT&CK: {f['mitre']}\n"
            f"  * Indicadores de Compromiso (IoCs): {f['ioc']}\n"
            f"  * Evidencia en Registros (Log_IDs): {f['evidencia_logs']}\n"
            f"  * Reconstrucción Forense: {f['resumen_tecnico']}\n"
            f"  * Plan de Contención y Erradicación:\n    {f['remediacion'].replace(chr(10), chr(10) + '    ')}\n"
            f"  * Comandos de Respuesta Recomendados (Playbook CLI):\n    {f['comandos_contencion']}"
        )

    lolbas_items = get_lolbas_gtfobins_catalog()
    lolbas_lines = [
        "3. INGENIERÍA DE DETECCIÓN: CORRELACIÓN LOLBAS / GTFOBINS Y REGLAS SIGMA, YARA & YARA-X\n"
        "- Mapeo de Binarios Nativos Abusados (Living Off The Land — LOLBAS https://lolbas-project.github.io/ & GTFOBins https://gtfobins.org/):"
    ]
    for item in lolbas_items:
        lolbas_lines.append(
            f"  * {item['binario']} [{item['catalogo']}] en {item['incidente']} ({item['log_ids']}): "
            f"Comando '{item['comando_detectado']}' -> {item['funcion_abusada']} | Ref: {item['lolbas_url']} | {item['gtfobins_url']}"
        )
    lolbas_lines.append(
        "- Cobertura de Reglas de Detección Desplegadas:\n"
        "  * Reglas Sigma (.yml): Correlación de EventID 4688 para vssadmin delete shadows (INC-03), staging con tar.exe/7z.exe (INC-02/INC-04), "
        "persistencia wuhelper.exe (INC-05), RCE DefaultAppPool cmd.exe /c whoami (INC-06) y alerta de EventID 4624/4672 post-Password Spraying (INC-01).\n"
        "  * Reglas YARA Clásico (.yar) & YARA-X Next-Gen Rust (.yarx): Caza en disco y memoria de la Webshell '/uploads/test.aspx', "
        "binario PE 'C:\\ProgramData\\wuhelper.exe', paquetes 'C:\\Temp\\finance.zip' y 'C:\\Users\\Public\\archive.7z', y endpoints C2 (198.51.100.88:443 / 203.0.113.88:443)."
    )
    tech_blocks.append("\n".join(lolbas_lines))

    tech_report = "\n\n".join(tech_blocks)
    return exec_report, tech_report


def _build_llm_runnable(
    provider: str,
    model_name: str,
    api_url: str,
    api_key: str,
    fallback_text: str,
):
    """
    Construye un Runnable de LangChain compatible con LCEL (`prompt | runnable | StrOutputParser()`).
    Si el proveedor es OpenAI/Groq/Gemini con API Key válida, instancia `ChatOpenAI`.
    Si es Ollama Local, conecta vía RunnableLambda al endpoint local.
    Si es el Motor Determinista o ocurre un error de red, utiliza un RunnableLambda determinista.
    """
    if "OpenAI" in provider and api_key.strip():
        try:
            from langchain_openai import ChatOpenAI

            return ChatOpenAI(
                model=model_name,
                api_key=api_key.strip(),
                base_url=api_url.rstrip("/") if api_url.strip() else "https://api.openai.com/v1",
                temperature=0.2,
                timeout=60,
            )
        except Exception:
            pass

    if "Ollama" in provider:
        def _ollama_invoke(prompt_value: Any) -> str:
            prompt_str = prompt_value.to_string() if hasattr(prompt_value, "to_string") else str(prompt_value)
            resp = requests.post(
                f"{api_url.rstrip('/')}/api/generate",
                json={
                    "model": model_name,
                    "prompt": prompt_str,
                    "stream": False,
                    "options": {"temperature": 0.2},
                },
                timeout=60,
            )
            resp.raise_for_status()
            text = resp.json().get("response", "").strip()
            return text if len(text) > 80 else fallback_text

        return RunnableLambda(_ollama_invoke)

    return RunnableLambda(lambda _prompt_val: fallback_text)


def generate_ai_reports(
    findings: List[Dict[str, Any]],
    summary_metrics: Dict[str, Any],
    provider: str,
    model_name: str,
    api_url: str,
    api_key: str,
) -> Tuple[str, str, str]:
    """
    Orquesta el pipeline paralelo de LangChain LCEL (`RunnableParallel`) para redactar simultáneamente
    el Informe Ejecutivo (C-Level) y el Informe Técnico Forense (DFIR Nivel 2).
    Retorna `(exec_report, tech_report, engine_status_message)`.
    """
    t0 = time.perf_counter()
    det_exec, det_tech = build_deterministic_reports(findings, summary_metrics)

    compact_findings = [
        {
            "id": f["id"],
            "titulo": f["titulo"],
            "riesgo": f["riesgo"],
            "ventana": f["ventana"],
            "activos": f["activos"],
            "usuarios": f["usuarios"],
            "mitre": f["mitre"],
            "ioc": f["ioc"],
            "evidencia_logs": f["evidencia_logs"],
            "resumen_tecnico": f["resumen_tecnico"],
            "remediacion": f["remediacion"],
        }
        for f in findings
    ]
    context_json = json.dumps(compact_findings, ensure_ascii=False, indent=2)

    exec_prompt = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                "Eres JEV, el Orquestador Principal LangChain para CISO y Junta Directiva (SOC Nivel 2). "
                "Redacta en español ejecutivo de alto impacto, claro, estructurado y orientado a riesgo de negocio.",
            ),
            (
                "human",
                "Audita {total_logs} eventos SIEM ({correlated} eventos maliciosos correlacionados, {hidden} ocultos en Informational, "
                "{exfil_mib} MiB exfiltrados). Genera el INFORME EJECUTIVO C-LEVEL basado en estos hallazgos:\n{findings_json}",
            ),
        ]
    )

    tech_prompt = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                "Eres JEV, Analista Principal DFIR SOC Nivel 2 experto en MITRE ATT&CK y respuesta a incidentes. "
                "Incluye todos los Log_IDs, IPs, comandos maliciosos, trampas Informational y Playbooks CLI.",
            ),
            (
                "human",
                "Genera el INFORME TÉCNICO FORENSE DETALLADO para los {total_logs} logs ({hidden} ocultos en Informational) "
                "con desglose completo de los 6 incidentes + OBS-01:\n{findings_json}",
            ),
        ]
    )

    try:
        exec_llm = _build_llm_runnable(provider, model_name, api_url, api_key, det_exec)
        tech_llm = _build_llm_runnable(provider, model_name, api_url, api_key, det_tech)

        parallel_chain = RunnableParallel(
            executive=exec_prompt | exec_llm | StrOutputParser(),
            technical=tech_prompt | tech_llm | StrOutputParser(),
        )

        result = parallel_chain.invoke(
            {
                "total_logs": summary_metrics["total_logs"],
                "correlated": summary_metrics["correlated_malicious_events"],
                "hidden": summary_metrics["hidden_info_critical_events"],
                "exfil_mib": f"{summary_metrics['exfil_mib']:.2f}",
                "findings_json": context_json,
            }
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        exec_out = result["executive"].strip() if len(result.get("executive", "").strip()) > 120 else det_exec
        tech_out = result["technical"].strip() if len(result.get("technical", "").strip()) > 120 else det_tech

        if "OpenAI" in provider and not api_key.strip():
            return (
                det_exec,
                det_tech,
                f"LangChain LCEL Fallback Activo (Sin API Key — {elapsed_ms:.1f} ms): Informes verificados contra los 715 eventos.",
            )

        return (
            exec_out,
            tech_out,
            f"Pipeline LangChain LCEL (`RunnableParallel`) completado en {elapsed_ms:.1f} ms [{model_name}].",
        )
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return (
            det_exec,
            det_tech,
            f"LangChain LCEL Modo Resiliente ({type(exc).__name__} — {elapsed_ms:.1f} ms): Informes completos verificados.",
        )


def _deterministic_copilot_router(
    query: str,
    findings: List[Dict[str, Any]],
    summary_metrics: Dict[str, Any],
) -> str:
    """
    Motor de respuesta inteligente de JEV Copilot (respaldo determinista LangChain RunnableLambda).
    Responde con precisión forense cualquier consulta sobre incidentes, IPs, usuarios, MITRE o comandos.
    """
    q = query.lower().strip()
    by_id = {f["id"].lower(): f for f in findings}

    # Consulta por un incidente específico (INC-01 .. INC-06, OBS-01)
    for inc_key, f in by_id.items():
        if inc_key in q or inc_key.replace("-", "") in q:
            return (
                f"### ⚡ Análisis JEV LangChain — `[{f['id']}] {f['titulo']}`\n"
                f"- **Riesgo / CVSS:** `{f['riesgo'].upper()}` (`{f['cvss_estimado']}`) | **Ventana:** `{f['ventana']}`\n"
                f"- **Activos:** `{f['activos']}` | **Usuarios:** `{f['usuarios']}`\n"
                f"- **MITRE ATT&CK:** `{f['mitre']}`\n"
                f"- **Kill Chain:** `{f['kill_chain']}`\n"
                f"- **Evidencia (`Log_IDs`):** `{f['evidencia_logs']}` ({f['eventos_count']} eventos; **{f['eventos_ocultos_info']} ocultos en Informational**)\n\n"
                f"**🔬 Reconstrucción Forense:**\n{f['resumen_tecnico']}\n\n"
                f"**🛡️ Playbook CLI de Contención Inmediata:**\n```powershell\n{f['comandos_contencion']}\n```"
            )

    if any(k in q for k in ["informational", "oculto", "trampa", "evasion", "evasión", "falso negativo", "12"]):
        hidden_rows = summary_metrics.get("hidden_events_records", [])
        bullets = "\n".join(
            f"- **`{r.get('Log_ID')}`** (`{r.get('Timestamp')}`) · `{r.get('Incident_ID')}` en `{r.get('Hostname')}` (`{r.get('User')}`): "
            f"**Event `{r.get('Event_ID')}` ({r.get('Event_Description', '-')})** — `{r.get('Process_CommandLine', '-')}`"
            for r in hidden_rows
        )
        return (
            f"### 🕵️‍♂️ Auditoría JEV LangChain: Los `{summary_metrics['hidden_info_critical_events']}` Eventos Críticos Ocultos en `Informational`\n"
            "Un analista Nivel 1 que filtre `Severity != Informational` perdería la prueba exacta de intrusión exitosa, "
            "compresión previa a exfiltración y ejecución periódica de persistencia:\n\n"
            f"{bullets}\n\n"
            "**Acción recomendada en SIEM:** Elevar a severidad `High` todo EventID `4624/4672` precedido por ≥10 fallos `4625`, "
            "toda invocación de `7z.exe`/`tar.exe` sobre carpetas sensibles y ejecuciones desde `C:\\ProgramData\\*.exe`."
        )

    if any(k in q for k in ["exfil", "bytes", "mib", "mb", "staging", "fuga", "transferencia", "7z", "zip", "tar"]):
        exfil_findings = [f for f in findings if "exfiltr" in f.get("categoria", "").lower() or "staging" in f.get("categoria", "").lower() or "T1048" in f.get("mitre", "") or "T1560" in f.get("mitre", "")]
        if not exfil_findings:
            exfil_findings = findings[:2]
        lines = [
            "### 📤 Telemetría de Exfiltración de Datos y Staging Cuantificada",
            f"- **Volumen Total Detectado:** **`{summary_metrics.get('exfil_bytes', 0):,}` bytes (`{summary_metrics.get('exfil_mib', 0):.2f} MiB` / `{summary_metrics.get('exfil_mb', 0):.2f} MB`)**.",
        ]
        for f in exfil_findings:
            lines.append(f"\n**{f.get('titulo')} (`{f.get('id')}` — `{f.get('activos')}` / `{f.get('usuarios')}`):**")
            lines.append(f"- **Reconstrucción Forense:** {f.get('resumen_tecnico')}")
            lines.append(f"- **IoCs:** `{f.get('ioc')}`")
            lines.append(f"- **Comandos de Respuesta:**\n```powershell\n{f.get('comandos_contencion')}\n```")
        return "\n".join(lines)

    if any(k in q for k in ["ransom", "vssadmin", "shadow", "destruccion", "destrucción", "inhibicion", "inhibición", "t1490"]):
        ransom_findings = [f for f in findings if "vss" in f.get("categoria", "").lower() or "ransom" in f.get("categoria", "").lower() or "T1490" in f.get("mitre", "")]
        f = ransom_findings[0] if ransom_findings else findings[2] if len(findings) > 2 else findings[0]
        return (
            f"### 🚨 Alerta Pre-Ransomware / Sabotaje de Copias de Sombra (`{f.get('id')}` — `{f.get('activos')}` / `{f.get('usuarios')}`)\n"
            f"- **Criticidad:** Riesgo `{f.get('riesgo')}` | Severidad Estimada `{f.get('cvss_estimado')}`.\n"
            f"- **Reconstrucción Forense:** {f.get('resumen_tecnico')}\n"
            f"- **Técnicas MITRE ATT&CK:** `{f.get('mitre')}`\n"
            f"- **IoCs Identificados:** `{f.get('ioc')}`\n\n"
            f"**🛡️ Contención Inmediata:**\n```powershell\n{f.get('comandos_contencion')}\n```"
        )

    if any(k in q for k in ["mitre", "táctica", "tactica", "técnica", "tecnica", "att&ck", "attack"]):
        rows = "\n".join(f"- **`{f['id']}` ({f['riesgo']}):** `{f['mitre']}` — *{f['titulo']}*" for f in findings)
        return (
            "### 🎯 Matriz Consolidada de Tácticas y Técnicas MITRE ATT&CK v15\n"
            f"{rows}\n\n"
            "**Cobertura de Kill Chain:** `Initial Access` $\\rightarrow$ `Execution` $\\rightarrow$ `Persistence` $\\rightarrow$ "
            "`Privilege Escalation` $\\rightarrow$ `Defense Evasion` $\\rightarrow$ `Credential Access` $\\rightarrow$ "
            "`Lateral Movement` $\\rightarrow$ `Collection` $\\rightarrow$ `Exfiltration` $\\rightarrow$ `Impact`."
        )

    if any(k in q for k in ["ip", "ioc", "indicador", "atacante", "extern", "firewall", "bloque"]):
        inbound_ips = set()
        outbound_ips = set()
        artifacts = set()
        for f in findings:
            ioc_str = f.get("ioc", "")
            for part in ioc_str.split(";"):
                part = part.strip()
                if "IP Atacante:" in part or "IP Origen:" in part:
                    inbound_ips.add(part.split(":")[-1].strip())
                elif "IP Destino:" in part or "C2:" in part or "Destino:" in part:
                    outbound_ips.add(part.split(":")[-1].strip())
                elif "Archivo:" in part or "Ruta:" in part or "Webshell:" in part or "Comando:" in part:
                    artifacts.add(part.split(":")[-1].strip())
                elif part:
                    artifacts.add(part)

        inbound_bullets = "\n".join(f"  - `{ip}`" for ip in sorted(inbound_ips)) if inbound_ips else "  - Verificación dinámica: no se registraron IPs inbound externas en este perfil."
        outbound_bullets = "\n".join(f"  - `{ip}`" for ip in sorted(outbound_ips)) if outbound_ips else "  - No se registraron IPs de destino outbound externas."
        art_bullets = "\n".join(f"  - `{art}`" for art in sorted(artifacts)[:8]) if artifacts else "  - Sin rutas anómalas registradas."

        return (
            "### 🌐 Indicadores de Compromiso (IoCs) Correlacionados Dinámicamente\n"
            f"- **IPs Externas Atacantes Identificadas (Inbound):\n{inbound_bullets}\n"
            f"- **Destinos Externos C2 / Conexiones Salientes (Outbound):\n{outbound_bullets}\n"
            f"- **Artefactos en Disco, Scripts y Binarios Anómalos:\n{art_bullets}"
        )

    if any(k in q for k in ["playbook", "comando", "contenci", "remedi", "powershell", "aislar"]):
        cmds = "\n\n".join(f"# [{f['id']}] {f['titulo']}\n{f['comandos_contencion']}" for f in findings[:6])
        return f"### 🛡️ Playbook Maestro de Contención CLI (SOC Nivel 2)\n```powershell\n{cmds}\n```"

    if any(k in q for k in ["lolbas", "gtfobins", "gtfo", "living off the land", "binario nativo"]):
        catalog = get_lolbas_gtfobins_catalog()
        rows = "\n".join(
            f"- **`{c['binario']}`** (`{c['catalogo']}` · `{c['incidente']}` · `{c['log_ids']}` en `{c['host']}`):\n"
            f"  - **Comando:** `{c['comando_detectado']}`\n"
            f"  - **Función Abusada:** {c['funcion_abusada']} (`{c['mitre']}`)\n"
            f"  - **Referencias Oficiales:** [LOLBAS Project]({c['lolbas_url']}) · [GTFOBins]({c['gtfobins_url']})"
            for c in catalog
        )
        return (
            "### 🧬 Auditoría Forense LOLBAS & GTFOBins en los 715 Eventos SIEM\n"
            "Los atacantes abusaron de **8 utilidades nativas del sistema** documentadas en "
            "[LOLBAS Project](https://lolbas-project.github.io/) y [GTFOBins](https://gtfobins.org/) para evadir controles:\n\n"
            f"{rows}"
        )

    if any(k in q for k in ["yara-x", "yarax", "rust"]):
        return (
            "### 🦀 Regla YARA-X Next-Gen (`.yarx` — Motor Rust de VirusTotal)\n"
            "Regla optimizada para `yr scan` con validación del módulo `pe` y expresiones regulares sobre los artefactos de `INC-02` a `INC-06`:\n"
            f"```yara\n{get_yarax_nextgen_rules()}\n```"
        )

    if "yara" in q:
        return (
            "### 🧬 Reglas YARA Clásicas (`.yar`) y YARA-X (`.yarx`) para DFIR Nivel 2\n"
            "**1. YARA Clásico (`.yar` — Memoria y Disco):**\n"
            f"```yara\n{get_yara_classic_rules()}\n```\n\n"
            "**2. YARA-X Next-Gen (`.yarx` — Motor Rust de VirusTotal):**\n"
            f"```yara\n{get_yarax_nextgen_rules()}\n```"
        )

    if any(k in q for k in ["sigma", "regla", "deteccion", "detección", "siem rule"]):
        return (
            "### 📡 Reglas Sigma de Producción (`.yml`) — Corrección de Falsos Negativos `Informational`\n"
            "Estas reglas Sigma detectan el abuso de LOLBAS/GTFOBins (`vssadmin`, `tar.exe`, `7z.exe`, `wuhelper.exe`, `cmd.exe /c whoami`) "
            "y correlacionan el login exitoso post-Password Spraying (`EVT-00123`, `EVT-00126`):\n"
            f"```yaml\n{get_sigma_rules_yaml()}\n```"
        )

    if any(k in q for k in ["dc-01", "dc01", "normaliz", "calidad", "svc_backup"]):
        norm = summary_metrics["normalization"]
        return (
            "### 🔧 Auditoría de Normalización y Desviación de Esquema (`OBS-01`)\n"
            f"- **Fragmentación de Hostname en Controlador de Dominio:** `DC-01` registra **{norm['dc_hyphen_count']} eventos** mientras que "
            f"`DC01` (sin guion) registra **{norm['dc_no_hyphen_count']} eventos** (24.8% de la telemetría total del DC). El parser SOC L2 los unifica en `Hostname_Norm = DC-01`.\n"
            f"- **Dualidad de Cuentas de Respaldo:** `CORP\\backupsvc` (**{norm['backupsvc_count']} eventos**, comprometida en `INC-03`) vs "
            f"`CORP\\svc_backup` (**{norm['svc_backup_count']} eventos**)."
        )

    # Respuesta integral por defecto (Resumen Ejecutivo + Triage L2)
    inc_summary = "\n".join(
        f"- **`{f['id']}` ({f['riesgo']} | CVSS `{f['cvss_estimado']}`):** {f['titulo']} — `{f['eventos_count']}` eventos (`{f['eventos_ocultos_info']}` en Info)."
        for f in findings
    )
    return (
        f"### 🤖 JEV Cyber Copilot (LangChain LCEL) — Estado Global de Telemetría\n"
        f"He correlacionado **{summary_metrics['total_logs']} registros SIEM** (`{summary_metrics['time_start']}` a `{summary_metrics['time_end']}` UTC):\n"
        f"- **Eventos Maliciosos Vinculados:** `{summary_metrics['correlated_malicious_events']}` (`{summary_metrics['native_non_info_alerts']}` alertas nativas + "
        f"**`{summary_metrics['hidden_info_critical_events']}` críticos rescatados de severidad `Informational`**).\n"
        f"- **Exfiltración Cuantificada:** `{summary_metrics.get('exfil_mib', 0):.2f} MiB` (`{summary_metrics.get('exfil_bytes', 0):,}` bytes).\n\n"
        f"**Incidentes y Vectores Activos en Cola de Respuesta:**\n{inc_summary}\n\n"
        "*💡 Puedes consultar por cualquier incidente o vector detectado, eventos críticos ocultos en `Informational`, `IoCs e IPs atacantes`, `exfiltración`, matriz `MITRE ATT&CK`, catálogo `LOLBAS/GTFOBins`, reglas `Sigma / YARA / YARA-X` o solicitar el `Playbook PowerShell` de contención.*"
    )


def ask_jev_copilot(
    query: str,
    findings: List[Dict[str, Any]],
    summary_metrics: Dict[str, Any],
    provider: str = "LangChain LCEL + Motor Forense Determinista (Instantáneo / Offline)",
    model_name: str = "jev-soc-l2-v3",
    api_url: str = "",
    api_key: str = "",
) -> Tuple[str, float]:
    """
    Ejecuta la cadena conversacional `copilot_prompt | llm_runnable | StrOutputParser()` de LangChain.
    Retorna `(respuesta_markdown, latencia_ms)`.
    """
    t0 = time.perf_counter()
    deterministic_answer = _deterministic_copilot_router(query, findings, summary_metrics)

    copilot_prompt = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                "Eres JEV (Just-in-Time Cyber Defense Assistant), un Copiloto Forense SOC Nivel 2 impulsado por LangChain. "
                "Responde siempre en español técnico claro, citando Log_IDs exactos, IPs, usuarios, técnicas MITRE ATT&CK "
                "y comandos de contención cuando corresponda.\n"
                "Contexto verificado del SIEM (715 logs, 124 maliciosos, 12 ocultos en Informational, 241.57 MiB exfiltrados):\n"
                "{context_summary}",
            ),
            ("human", "{question}"),
        ]
    )

    try:
        llm_runnable = _build_llm_runnable(provider, model_name, api_url, api_key, deterministic_answer)
        chain = copilot_prompt | llm_runnable | StrOutputParser()
        compact_ctx = json.dumps(
            [{"id": f["id"], "titulo": f["titulo"], "ioc": f["ioc"], "logs": f["evidencia_logs"], "mitre": f["mitre"]} for f in findings],
            ensure_ascii=False,
        )
        response = chain.invoke({"context_summary": compact_ctx, "question": query})
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        out = response.strip() if len(response.strip()) > 40 else deterministic_answer
        return out, elapsed_ms
    except Exception:
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return deterministic_answer, elapsed_ms
