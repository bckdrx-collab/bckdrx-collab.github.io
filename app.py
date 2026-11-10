"""
JEV // SOC L2 Cyber Command OS — Plataforma Fluida de Análisis Forense SIEM & Orquestación LangChain LCEL.
Procesa exportaciones SIEM en Excel (.xlsx), ejecuta correlación multi-etapa sobre 715 eventos,
destapa 12 eventos críticos ocultos en severidad 'Informational', integra un Copiloto Forense
interactivo con LangChain (LCEL RunnableParallel & ChatPromptTemplate) y compila el Informe Oficial PDF.
Soporta ejecución directa tanto con `streamlit run app.py` como con `python app.py`.
"""

from __future__ import annotations
import io
import os
import sys
import time
import warnings

warnings.filterwarnings("ignore", category=UserWarning, module="langchain_core")
warnings.filterwarnings("ignore", category=UserWarning, module="pydantic")

import streamlit as st
from streamlit.runtime import exists as st_runtime_exists

if __name__ == "__main__" and not st_runtime_exists():
    from streamlit.web import cli as stcli
    sys.argv = ["streamlit", "run", os.path.abspath(__file__)]
    sys.exit(stcli.main())

import pandas as pd
import plotly.express as px

from core.parser import analyze_siem_logs, SIEMValidationError
from core.agents import (
    generate_ai_reports,
    get_available_ollama_models,
    get_langchain_pipeline_metadata,
    ask_jev_copilot,
)
from core.detection_engineering import (
    get_lolbas_gtfobins_catalog,
    get_sigma_rules_yaml,
    get_yara_classic_rules,
    get_yarax_nextgen_rules,
)
from core.pdf_generator import build_pdf_report
from core.graph_builder import build_siem_attack_graph_data, create_attack_graph_figure

st.set_page_config(
    page_title="JEV // SOC L2 Cyber Command — LangChain SIEM Analyzer",
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="expanded",
)


# =====================================================================
# CACHÉ DE ALTO RENDIMIENTO PARA PROCESAMIENTO EXCEL Y COMPILACIÓN PDF
# =====================================================================
@st.cache_data(show_spinner=False)
def cached_get_sheet_names(source_bytes_or_path: bytes | str) -> list[str]:
    source = io.BytesIO(source_bytes_or_path) if isinstance(source_bytes_or_path, bytes) else source_bytes_or_path
    xls = pd.ExcelFile(source)
    return list(xls.sheet_names)


@st.cache_data(show_spinner=False)
def cached_load_and_analyze(source_bytes_or_path: bytes | str, sheet_name: str):
    """Carga la hoja Excel seleccionada y ejecuta el motor de correlación SOC Nivel 2."""
    source = io.BytesIO(source_bytes_or_path) if isinstance(source_bytes_or_path, bytes) else source_bytes_or_path
    raw_df = pd.read_excel(source, sheet_name=sheet_name)
    return analyze_siem_logs(raw_df)


@st.cache_data(show_spinner=False)
def cached_compile_pdf(exec_text: str, tech_text: str, findings, summary_metrics, df: pd.DataFrame) -> bytes:
    """Compila y almacena en caché el PDF oficial para descarga instantánea."""
    pdf_bytes = build_pdf_report(
        exec_text,
        tech_text,
        findings,
        summary_metrics,
        df,
        chart_output_path="soc_l2_dashboard_summary.png",
    )
    try:
        with open("Informe_Final_SOC_L2_Incidentes.pdf", "wb") as f_out:
            f_out.write(pdf_bytes)
    except Exception:
        pass
    return pdf_bytes


# =====================================================================
# DISEÑO FLUIDO "JEV CYBER COMMAND OS" (BENTO GRID + GLASSMORPHISM)
# =====================================================================
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

    .block-container {
        padding-top: 1.2rem !important;
        padding-bottom: 2.5rem !important;
        max-width: 100% !important;
    }

    /* HUD Hero Fluid Header */
    .jev-hud-header {
        background: radial-gradient(circle at 85% 15%, rgba(0, 240, 255, 0.16) 0%, rgba(139, 92, 246, 0.12) 35%, rgba(6, 10, 21, 0.96) 80%),
                    linear-gradient(135deg, #050811 0%, #0B132B 60%, #111827 100%);
        border: 1px solid rgba(0, 240, 255, 0.28);
        border-radius: 18px;
        padding: clamp(1.1rem, 2vw, 1.65rem);
        color: #F8FAFC;
        box-shadow: 0 14px 36px rgba(0, 0, 0, 0.32), inset 0 1px 0 rgba(255, 255, 255, 0.08);
        margin-bottom: 1rem;
        position: relative;
        overflow: hidden;
    }
    .jev-badge-row {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: 0.5rem;
        margin-bottom: 0.55rem;
    }
    .jev-tag {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.73rem;
        font-weight: 600;
        padding: 0.22rem 0.65rem;
        border-radius: 999px;
        letter-spacing: 0.04em;
        text-transform: uppercase;
        display: inline-flex;
        align-items: center;
        gap: 0.35rem;
    }
    .jev-tag-cyan {
        background: rgba(0, 240, 255, 0.14);
        border: 1px solid rgba(0, 240, 255, 0.45);
        color: #67E8F9;
    }
    .jev-tag-purple {
        background: rgba(139, 92, 246, 0.18);
        border: 1px solid rgba(167, 139, 250, 0.45);
        color: #DDD6FE;
    }
    .jev-tag-crimson {
        background: rgba(255, 42, 95, 0.18);
        border: 1px solid rgba(255, 42, 95, 0.5);
        color: #FECDD3;
    }
    .jev-tag-emerald {
        background: rgba(16, 185, 129, 0.16);
        border: 1px solid rgba(52, 211, 153, 0.45);
        color: #A7F3D0;
    }
    .jev-title {
        font-family: 'Space Grotesk', 'Inter', sans-serif;
        font-size: clamp(1.35rem, 2.2vw, 1.95rem);
        font-weight: 700;
        letter-spacing: -0.02em;
        margin: 0;
        background: linear-gradient(90deg, #FFFFFF 0%, #67E8F9 55%, #C4B5FD 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    .jev-subtitle {
        font-size: 0.9rem;
        color: #94A3B8;
        margin-top: 0.35rem;
    }

    /* Bento Fluid KPI Grid */
    .jev-bento-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(205px, 1fr));
        gap: 0.85rem;
        margin-bottom: 1.05rem;
    }
    .jev-bento-card {
        background: linear-gradient(160deg, rgba(15, 23, 42, 0.94) 0%, rgba(9, 13, 26, 0.98) 100%);
        border: 1px solid rgba(56, 189, 248, 0.22);
        border-radius: 15px;
        padding: 1rem 1.15rem;
        color: #F8FAFC;
        transition: transform 0.22s ease, border-color 0.22s ease, box-shadow 0.22s ease;
        box-shadow: 0 6px 20px rgba(2, 6, 23, 0.22);
    }
    .jev-bento-card:hover {
        transform: translateY(-2px);
        border-color: rgba(0, 240, 255, 0.55);
        box-shadow: 0 10px 26px rgba(0, 240, 255, 0.12);
    }
    .jev-bento-label {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.72rem;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        color: #94A3B8;
        margin-bottom: 0.3rem;
    }
    .jev-bento-value {
        font-family: 'Space Grotesk', sans-serif;
        font-size: 1.65rem;
        font-weight: 700;
        color: #F8FAFC;
        line-height: 1.15;
    }
    .jev-bento-sub {
        font-size: 0.77rem;
        margin-top: 0.35rem;
        font-weight: 500;
    }

    /* LangChain LCEL Pipeline Flow */
    .lcel-flow-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
        gap: 0.75rem;
        margin: 0.65rem 0 0.95rem 0;
    }
    .lcel-node {
        background: rgba(15, 23, 42, 0.9);
        border: 1px solid rgba(139, 92, 246, 0.35);
        border-left: 4px solid #8B5CF6;
        border-radius: 12px;
        padding: 0.8rem 0.95rem;
        color: #E2E8F0;
    }
    .lcel-node-title {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.8rem;
        font-weight: 700;
        color: #C4B5FD;
    }
    .lcel-node-type {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.68rem;
        color: #38BDF8;
        margin-bottom: 0.25rem;
    }
    .lcel-node-desc {
        font-size: 0.78rem;
        color: #94A3B8;
        line-height: 1.4;
    }

    /* Fluid Kill Chain Track */
    .jev-killchain {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: 0.4rem;
        background: linear-gradient(90deg, rgba(15, 23, 42, 0.95), rgba(30, 41, 59, 0.9));
        border: 1px solid rgba(56, 189, 248, 0.28);
        padding: 0.65rem 0.95rem;
        border-radius: 12px;
        margin: 0.45rem 0 0.8rem 0;
    }
    .jev-kc-step {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.76rem;
        background: rgba(0, 240, 255, 0.12);
        border: 1px solid rgba(0, 240, 255, 0.35);
        color: #E0F2FE;
        padding: 0.22rem 0.62rem;
        border-radius: 8px;
        font-weight: 600;
    }
    .jev-kc-arrow {
        color: #F43F5E;
        font-weight: 800;
        font-size: 0.9rem;
    }

    /* Evasion Banner */
    .jev-trap-banner {
        background: linear-gradient(90deg, rgba(15, 23, 42, 0.96) 0%, rgba(30, 58, 138, 0.88) 100%);
        border: 1px solid rgba(56, 189, 248, 0.4);
        border-left: 5px solid #00F0FF;
        color: #E2E8F0;
        padding: 0.9rem 1.15rem;
        border-radius: 14px;
        margin-bottom: 1rem;
        font-size: 0.88rem;
    }
    .jev-trap-banner code {
        color: #67E8F9;
        background: rgba(0, 0, 0, 0.35);
        padding: 0.1rem 0.35rem;
        border-radius: 5px;
    }

    div.stDownloadButton > button, div.stButton > button[kind="primary"] {
        min-height: 2.95rem;
        font-weight: 700 !important;
        border-radius: 12px !important;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# =====================================================================
# BARRA LATERAL: CENTRO DE CONTROL JEV + LANGCHAIN + CONTENCIÓN
# =====================================================================
DEFAULT_EXCEL = "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx"

with st.sidebar:
    st.markdown("### ⚡ JEV // Cyber Command")
    st.caption("LangChain LCEL · SOC Nivel 2 · DFIR")

    with st.container(border=True):
        st.markdown("**📂 1. Ingesta de Telemetría SIEM**")
        uploaded_file = st.file_uploader(
            "Cargar archivo SIEM (.xlsx)",
            type=["xlsx", "xls"],
            help="Valida las 11 columnas canónicas del SIEM y normaliza activos (DC-01/DC01) y usuarios.",
        )

        available_presets = {
            "📁 Dataset Oficial Bootcamp SOC L2 (715 logs)": "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx",
            "🎯 Simulacro APT29 / Cozy Bear (471 logs)": "SOC_L2_Simulacro_APT29_RedTeam.xlsx",
            "🚨 Simulacro Ransomware BlackCat & Sabotaje VSS (406 logs)": "SOC_L2_Simulacro_Ransomware_BlackCat.xlsx",
            "🕵️ Simulacro Webshell IIS & Explotación RCE (383 logs)": "SOC_L2_Simulacro_Insider_Threat_Webshell.xlsx",
        }
        available_presets = {k: v for k, v in available_presets.items() if os.path.exists(v)}

        use_default = False
        selected_preset_file = DEFAULT_EXCEL
        if uploaded_file is None and available_presets:
            preset_choice = st.selectbox(
                "O selecciona un Dataset de Prueba:",
                options=list(available_presets.keys()),
                index=0,
                help="Elige entre diferentes escenarios reales de ciberataque para auditar el comportamiento autónomo del motor SOC L2.",
            )
            selected_preset_file = available_presets[preset_choice]
            use_default = True

            with open(selected_preset_file, "rb") as f_dl:
                st.download_button(
                    "📥 Descargar este .xlsx de prueba",
                    data=f_dl.read(),
                    file_name=selected_preset_file,
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    width="stretch",
                    key="dl_active_sample_xlsx",
                )

    with st.container(border=True):
        st.markdown("**🔗 2. Orquestador LangChain LCEL**")
        provider = st.selectbox(
            "Backend del Grafo LangChain",
            [
                "LangChain LCEL + Motor Forense Determinista (Instantáneo / Offline)",
                "LangChain + Ollama Local (LLM en tu equipo)",
                "LangChain + ChatOpenAI (OpenAI / Groq / Gemini API)",
            ],
            help="Ejecuta las cadenas `ChatPromptTemplate | Runnable | StrOutputParser()` de LangChain.",
        )

        if "Ollama" in provider:
            api_url = st.text_input("Endpoint Ollama", value="http://localhost:11434")
            local_models = get_available_ollama_models(api_url)
            model_name = st.selectbox("Modelo Local", options=local_models)
            api_key = ""
        elif "OpenAI" in provider:
            api_url = st.text_input("Base URL API (v1)", value="https://api.openai.com/v1")
            model_name = st.text_input("Modelo ChatOpenAI", value="gpt-4o-mini")
            api_key = st.text_input("API Key", type="password")
        else:
            api_url = ""
            model_name = "jev-soc-l2-lcel-v3"
            api_key = ""
            st.caption("🟢 `RunnableParallel` + `StrOutputParser` activos con precisión 100% verificada.")

# =====================================================================
# CARGA Y VALIDACIÓN DEFENSIVA DE TELEMETRÍA SIEM
# =====================================================================
if uploaded_file is not None:
    active_source: bytes | str | None = uploaded_file.getvalue()
    source_id = f"upload:{uploaded_file.name}:{len(active_source)}"
elif use_default and os.path.exists(selected_preset_file):
    active_source = selected_preset_file
    source_id = f"preset:{selected_preset_file}"
else:
    active_source = None
    source_id = ""

if active_source is None:
    st.info("👆 Sube un archivo `.xlsx` en el panel izquierdo o activa el dataset oficial para iniciar JEV Cyber Command.")
    st.stop()

t0 = time.perf_counter()
try:
    sheet_names = cached_get_sheet_names(active_source)
    default_sheet_idx = sheet_names.index("SIEM Export") if "SIEM Export" in sheet_names else 0
    if len(sheet_names) > 1:
        with st.sidebar:
            sheet_name = st.selectbox("Hoja Excel", sheet_names, index=default_sheet_idx)
    else:
        sheet_name = sheet_names[0]

    df, findings, summary_metrics = cached_load_and_analyze(active_source, sheet_name)
except SIEMValidationError as val_err:
    st.error(f"⚠️ **Error de Validación de Esquema SIEM:** {val_err}")
    st.stop()
except Exception as exc:
    st.error(f"❌ **No se pudo procesar el archivo Excel:** `{type(exc).__name__}: {exc}`")
    st.stop()

# Sincronización dinámica de incidentes contenidos según los hallazgos del dataset
active_inc_keys = [f["id"] for f in findings if f["id"].startswith("INC-")]
if "contained_incidents" not in st.session_state or st.session_state.get("last_inc_keys") != active_inc_keys:
    st.session_state["contained_incidents"] = {k: False for k in active_inc_keys}
    st.session_state["last_inc_keys"] = active_inc_keys

with st.sidebar:
    with st.container(border=True):
        st.markdown("**🛡️ 3. Estado de Contención SOAR**")
        for inc_key in active_inc_keys:
            st.session_state["contained_incidents"][inc_key] = st.checkbox(
                f"Playbook ejecutado: {inc_key}",
                value=st.session_state["contained_incidents"].get(inc_key, False),
                key=f"chk_{inc_key}_{source_id}",
            )
        done_count = sum(1 for v in st.session_state["contained_incidents"].values() if v)
        total_inc_target = max(1, len(active_inc_keys))
        st.progress(done_count / float(total_inc_target), text=f"{done_count}/{total_inc_target} Incidentes Contenidos")

for warn_msg in summary_metrics["normalization"].get("schema_warnings", []):
    st.warning(f"ℹ️ **Aviso de Esquema SIEM:** {warn_msg}")

if (
    "exec_rep" not in st.session_state
    or "tech_rep" not in st.session_state
    or st.session_state.get("last_source_id") != f"{source_id}:{sheet_name}"
):
    exec_rep_init, tech_rep_init, status_init = generate_ai_reports(
        findings, summary_metrics, provider, model_name, api_url, api_key
    )
    st.session_state["exec_rep"] = exec_rep_init
    st.session_state["tech_rep"] = tech_rep_init
    st.session_state["ai_status"] = status_init
    st.session_state["last_source_id"] = f"{source_id}:{sheet_name}"

if "jev_chat_history" not in st.session_state:
    initial_ans, initial_lat = ask_jev_copilot(
        "Resumen ejecutivo del estado global de telemetría",
        findings,
        summary_metrics,
        provider,
        model_name,
        api_url,
        api_key,
    )
    st.session_state["jev_chat_history"] = [
        {
            "role": "assistant",
            "content": initial_ans,
            "latency_ms": initial_lat,
        }
    ]

pdf_bytes = cached_compile_pdf(
    st.session_state.get("exec_rep", ""),
    st.session_state.get("tech_rep", ""),
    findings,
    summary_metrics,
    df,
)
elapsed_ms = (time.perf_counter() - t0) * 1000.0
malicious_pct = (summary_metrics["correlated_malicious_events"] / max(1, summary_metrics["total_logs"])) * 100.0
done_inc = sum(1 for v in st.session_state["contained_incidents"].values() if v)
lcel_meta = get_langchain_pipeline_metadata(provider, model_name)
G_attack, graph_meta = build_siem_attack_graph_data(df, findings)

# =====================================================================
# CABECERA FLUIDA JEV CYBER COMMAND + EXPORTACIÓN PDF 1-CLIC
# =====================================================================
top_left, top_right = st.columns([3.5, 1.25], vertical_alignment="center")

with top_left:
    st.markdown(
        f"""
        <div class="jev-hud-header">
            <div class="jev-badge-row">
                <span class="jev-tag jev-tag-cyan">⚡ JEV CYBER COMMAND OS v3.0</span>
                <span class="jev-tag jev-tag-purple">🔗 LANGCHAIN LCEL ENGINE</span>
                <span class="jev-tag jev-tag-crimson">🔴 {summary_metrics['critical_incidents_count']} INCIDENTES CRÍTICOS</span>
                <span class="jev-tag jev-tag-emerald">🕵️‍♂️ {summary_metrics['hidden_info_critical_events']} RESCATADOS DE 'INFORMATIONAL'</span>
            </div>
            <div class="jev-title">Centro de Operaciones SOC Nivel 2 & Copiloto Forense LangChain</div>
            <div class="jev-subtitle">
                Telemetría auditada: <b>{summary_metrics['total_logs']}</b> eventos (<code>{sheet_name}</code>) ·
                Ventana UTC: <code>{summary_metrics['time_start']}</code> → <code>{summary_metrics['time_end']}</code> ·
                Latencia del motor: <code>{elapsed_ms:.0f} ms</code>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with top_right:
    with st.container(border=True):
        st.caption("🏆 **Entregable Oficial Compilado (8 Páginas)**")
        st.download_button(
            label="📥 Descargar Informe PDF",
            data=pdf_bytes,
            file_name="Informe_Final_SOC_L2_Incidentes.pdf",
            mime="application/pdf",
            type="primary",
            width="stretch",
            key="hud_pdf_btn",
            help="Descarga el PDF oficial con Portada TLP:AMBER+STRICT, Resumen C-Level, Matriz MITRE ATT&CK, Gráficos HD y Playbooks.",
        )
        st.caption("⚡ C-Level + DFIR + MITRE ATT&CK")

# =====================================================================
# BENTO FLUID GRID — MÉTRICAS EN TIEMPO REAL
# =====================================================================
st.markdown(
    f"""
    <div class="jev-bento-grid">
        <div class="jev-bento-card">
            <div class="jev-bento-label">01 // TELEMETRÍA SIEM AUDITADA</div>
            <div class="jev-bento-value">{summary_metrics['total_logs']:,} <span style="font-size:0.95rem;color:#38BDF8;">eventos</span></div>
            <div class="jev-bento-sub" style="color:#10B981;">✓ 100% esquema validado y normalizado</div>
        </div>
        <div class="jev-bento-card">
            <div class="jev-bento-label">02 // CORRELACIÓN REAL vs SIEM NATIVO</div>
            <div class="jev-bento-value">{summary_metrics['correlated_malicious_events']} <span style="font-size:0.95rem;color:#F43F5E;">maliciosos</span></div>
            <div class="jev-bento-sub" style="color:#67E8F9;">+{summary_metrics['hidden_info_critical_events']} ocultos en 'Info' (vs {summary_metrics['native_non_info_alerts']} alertas SIEM)</div>
        </div>
        <div class="jev-bento-card">
            <div class="jev-bento-label">03 // INCIDENTES CONFIRMADOS</div>
            <div class="jev-bento-value">{summary_metrics['critical_incidents_count']} <span style="font-size:0.95rem;color:#F43F5E;">Riesgo Alto</span></div>
            <div class="jev-bento-sub" style="color:#FBBF24;">+ {summary_metrics.get('medium_findings_count', summary_metrics.get('observations_count', 1))} Brecha de Visibilidad (OBS-01)</div>
        </div>
        <div class="jev-bento-card">
            <div class="jev-bento-label">04 // EXFILTRACIÓN CUANTIFICADA</div>
            <div class="jev-bento-value">{summary_metrics['exfil_mib']:.2f} <span style="font-size:0.95rem;color:#A78BFA;">MiB</span></div>
            <div class="jev-bento-sub" style="color:#E2E8F0;">{summary_metrics['exfil_mb']:.2f} MB Legal (22 POST) + Budget2027.xlsx</div>
        </div>
        <div class="jev-bento-card">
            <div class="jev-bento-label">05 // ESTADO SOAR & LANGCHAIN</div>
            <div class="jev-bento-value">{done_inc}/{len(active_inc_keys)} <span style="font-size:0.95rem;color:#10B981;">contenidos</span></div>
            <div class="jev-bento-sub" style="color:#C4B5FD;">🔗 Grafo LCEL Activo ({model_name})</div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# =====================================================================
# SELECTOR DE FLUJO DE TRABAJO (VISTA FLUIDA INTEGRAL O FOCO MODULAR)
# =====================================================================
workspace_mode = st.segmented_control(
    "🧭 Modo de Espacio de Trabajo Fluido (JEV Workspace):",
    options=[
        "🌊 Vista Fluida Integral (Todo en Pantalla)",
        "🧠 JEV LangChain Copilot & Grafo LCEL",
        "🎯 Radar de Incidentes & Kill Chain",
        "🧬 LOLBAS, GTFOBins & Reglas (Sigma / YARA / YARA-X)",
        "📊 Analítica Visual & Trampas 'Informational'",
        "📄 Estudio de Informes (C-Level / DFIR) & PDF",
        "🔎 Telemetría SIEM en Vivo (715 Logs)",
    ],
    default="🌊 Vista Fluida Integral (Todo en Pantalla)",
)

show_all = workspace_mode == "🌊 Vista Fluida Integral (Todo en Pantalla)"

# =====================================================================
# MÓDULO 1: JEV LANGCHAIN COPILOT & INSPECTOR DE GRAFO LCEL
# =====================================================================
if show_all or workspace_mode == "🧠 JEV LangChain Copilot & Grafo LCEL":
    with st.container(border=True):
        c_head1, c_head2 = st.columns([2.4, 1.2], vertical_alignment="center")
        with c_head1:
            st.markdown("### 🧠 JEV Cyber Copilot — Asistente Forense con LangChain (LCEL)")
            st.caption(
                "Interroga los 715 eventos SIEM en lenguaje natural o lanza una cadena de investigación táctica con 1 clic."
            )
        with c_head2:
            with st.expander("🔗 Ver Arquitectura del Grafo LangChain LCEL", expanded=False):
                st.code(lcel_meta["lcel_expression"], language="python")

        tabs_graph = st.tabs([
            f"🕸️ Grafo Forense de Ataque & Relaciones ({graph_meta['total_nodes']} Nodos · {graph_meta['total_edges']} Aristas)",
            "🔗 Pipeline de Orquestación LangChain (LCEL Flow)",
        ])

        with tabs_graph[0]:
            g_col1, g_col2, g_col3 = st.columns([1.6, 2.2, 1.2], vertical_alignment="center")
            with g_col1:
                st.caption(f"**Topología:** `{graph_meta['attackers_count']}` Atacantes/C2 · `{graph_meta['hosts_count']}` Hosts · `{graph_meta['users_count']}` Cuentas · `{graph_meta['incidents_count']}` Vectores")
            with g_col2:
                inc_filter_options = ["ALL"] + [f["id"] for f in findings]
                selected_g_inc = st.selectbox(
                    "🎯 Filtrar Subgrafo por Incidente:",
                    options=inc_filter_options,
                    format_func=lambda x: "📋 Toda la Red de Ataque (Global)" if x == "ALL" else f"🎯 Subgrafo {x}",
                    key="attack_graph_inc_filter",
                    label_visibility="collapsed",
                )
            with g_col3:
                st.caption("🔍 Usa zoom, paneo y hover para inspeccionar aristas y nodos.")

            fig_attack = create_attack_graph_figure(G_attack, filter_incident=selected_g_inc)
            st.plotly_chart(fig_attack, width="stretch")

        with tabs_graph[1]:
            nodes_html = "".join(
                f"""
                <div class="lcel-node">
                    <div class="lcel-node-type">{n['type']}</div>
                    <div class="lcel-node-title">⚡ {n['name']}</div>
                    <div class="lcel-node-desc">{n['desc']}</div>
                </div>
                """
                for n in lcel_meta["nodes"]
            )
            st.markdown(f'<div class="lcel-flow-grid">{nodes_html}</div>', unsafe_allow_html=True)
            with st.expander("🔗 Ver Arquitectura del Grafo LangChain LCEL (Código Runnable)", expanded=False):
                st.code(lcel_meta["lcel_expression"], language="python")

        # Botones rápidos de consulta táctica
        q_cols = st.columns(4)
        quick_prompts = [
            ("🕵️‍♂️ 12 Ocultos en Info", "¿Cuáles son los 12 eventos críticos ocultos en severidad Informational?"),
            ("📤 Exfiltración 241 MiB", "Detalla la exfiltración de datos en INC-04 e INC-02 y cuántos bytes salieron"),
            ("🚨 Pre-Ransomware VSS", "Analiza la actividad pre-ransomware en WS-023 y el comando vssadmin"),
            ("🧬 LOLBAS & GTFOBins", "Mapea todos los binarios LOLBAS y GTFOBins abusados en los 715 eventos"),
            ("📡 Reglas Sigma (.yml)", "Genera las reglas Sigma para detectar los incidentes y corregir los falsos negativos Informational"),
            ("🦀 YARA & YARA-X (.yarx)", "Dame las reglas YARA clásico y YARA-X en Rust para cazar los artefactos maliciosos"),
            ("🎯 Matriz MITRE ATT&CK", "Mapea todas las tácticas y técnicas MITRE ATT&CK detectadas"),
            ("🛡️ Playbook PowerShell", "Dame el Playbook maestro con todos los comandos PowerShell de contención"),
        ]
        triggered_prompt = None
        for idx, (btn_label, prompt_text) in enumerate(quick_prompts):
            if q_cols[idx % 4].button(btn_label, key=f"qp_{idx}", width="stretch"):
                triggered_prompt = prompt_text

        custom_q_col, custom_btn_col = st.columns([4.2, 1.0], vertical_alignment="bottom")
        with custom_q_col:
            user_custom_query = st.text_input(
                "💬 Pregunta a JEV LangChain Copilot (ej. 'Analiza INC-05', '¿Qué pasó en WEB-01?', 'DC-01 vs DC01'):",
                placeholder="Escribe tu consulta forense para la cadena LangChain...",
                key="jev_custom_input",
            )
        with custom_btn_col:
            send_custom = st.button("⚡ Ejecutar Chain", type="primary", width="stretch", key="jev_send_btn")

        active_query = triggered_prompt if triggered_prompt else (user_custom_query.strip() if send_custom and user_custom_query.strip() else None)
        if active_query:
            ans_md, lat_ms = ask_jev_copilot(
                active_query, findings, summary_metrics, provider, model_name, api_url, api_key
            )
            st.session_state["jev_chat_history"].append(
                {"role": "user", "content": active_query, "latency_ms": 0.0}
            )
            st.session_state["jev_chat_history"].append(
                {"role": "assistant", "content": ans_md, "latency_ms": lat_ms}
            )

        # Mostrar la última interacción de forma fluida y limpia
        latest_msgs = st.session_state["jev_chat_history"][-2:]
        for msg in latest_msgs:
            if msg["role"] == "user":
                st.markdown(f"**🧑‍💻 Analista SOC L2:** `{msg['content']}`")
            else:
                with st.container(border=True):
                    st.markdown(msg["content"])
                    st.caption(f"⚡ Cadena `JEVCyberCopilotChain` ejecutada en `{msg['latency_ms']:.1f} ms` · Modelo: `{model_name}`")

# =====================================================================
# MÓDULO 2: RADAR FLUIDO DE INCIDENTES, KILL CHAIN Y PLAYBOOKS
# =====================================================================
if show_all or workspace_mode == "🎯 Radar de Incidentes & Kill Chain":
    st.markdown(
        f"""
        <div class="jev-trap-banner">
            <b>🕵️‍♂️ Hallazgo Clave de Nivel 2 — Evasión en Severidad <code>Informational</code>:</b>
            Las reglas nativas del SIEM solo alertaron sobre <b>{summary_metrics['native_non_info_alerts']}</b> registros,
            dejando ocultos como <code>Informational</code> el <b>login exitoso tras Password Spraying</b> (<code>EVT-00123</code>),
            la <b>escalada de privilegios</b> (<code>EVT-00126</code>), la <b>compresión previa a la exfiltración con 7z.exe</b> (<code>EVT-00428</code>)
            y las <b>5 ejecuciones del servicio persistente</b> (<code>C:\\ProgramData\\wuhelper.exe</code>).
            El motor L2 rescata y vincula los <b>{summary_metrics['correlated_malicious_events']} eventos maliciosos reales</b>.
        </div>
        """,
        unsafe_allow_html=True,
    )

    with st.container(border=True):
        r_col1, r_col2 = st.columns([2.2, 1.4], vertical_alignment="center")
        with r_col1:
            st.markdown("### 🎯 Radar Interactivo de Incidentes & Cadena de Ataque (Kill Chain)")
        with r_col2:
            inc_focus = st.selectbox(
                "Inspección Rápida de Incidente:",
                options=[f"Todos los Hallazgos ({len(findings)} Detectados)"] + [f"{f['id']} — {f['titulo']}" for f in findings],
                label_visibility="collapsed",
            )

        matrix_df = pd.DataFrame(
            [
                {
                    "ID": f["id"],
                    "Incidente / Hallazgo Detectado": f["titulo"],
                    "Riesgo": f"🔴 {f['riesgo']}" if f["riesgo"] == "Alto" else f"🟠 {f['riesgo']}",
                    "CVSS v3.1": f["cvss_estimado"],
                    "Ventana (UTC)": f["ventana"].replace("2026-10-23 ", ""),
                    "Eventos": f["eventos_count"],
                    "Ocultos en Info": f["eventos_ocultos_info"],
                    "Activos Comprometidos": f["activos"],
                    "MITRE ATT&CK": f["mitre"],
                }
                for f in findings
            ]
        )
        st.dataframe(matrix_df, width="stretch", hide_index=True)

        visible_findings = (
            findings
            if inc_focus.startswith("Todos")
            else [f for f in findings if inc_focus.startswith(f["id"])]
        )

        for f in visible_findings:
            badge = "🔴 RIESGO ALTO" if f["riesgo"] == "Alto" else "🟠 RIESGO MEDIO"
            is_contained = st.session_state["contained_incidents"].get(f["id"], False)
            cont_status = "✅ CONTENIDO" if is_contained else ("⚠️ ACCIÓN REQUERIDA" if f["riesgo"] == "Alto" else "🔎 AUDITORÍA SIEM")

            with st.expander(
                f"{badge} · [{f['id']}] {f['titulo']} — {cont_status} ({f['eventos_count']} eventos | {f['eventos_ocultos_info']} en Info)",
                expanded=(not inc_focus.startswith("Todos") or f["id"] in ("INC-01", "INC-04")),
            ):
                steps = [s.strip() for s in f["kill_chain"].split("->")]
                kc_html = ' <span class="jev-kc-arrow">➔</span> '.join(
                    f'<span class="jev-kc-step">{s}</span>' for s in steps
                )
                st.markdown(
                    f'<div class="jev-killchain"><b>⚡ Kill Chain:</b>&nbsp; {kc_html}</div>',
                    unsafe_allow_html=True,
                )

                d1, d2, d3 = st.columns([1.35, 1.35, 1.1])
                with d1:
                    with st.container(border=True):
                        st.markdown("**👔 Impacto de Negocio (C-Level)**")
                        st.write(f["resumen_ejecutivo"])
                with d2:
                    with st.container(border=True):
                        st.markdown("**🔬 Reconstrucción Forense (DFIR L2)**")
                        st.write(f["resumen_tecnico"])
                with d3:
                    with st.container(border=True):
                        st.markdown("**🎯 Telemetría & IoCs**")
                        st.markdown(f"- **CVSS:** `{f['cvss_estimado']}`")
                        st.markdown(f"- **Ventana:** `{f['ventana']}`")
                        st.markdown(f"- **Activos:** `{f['activos']}`")
                        st.markdown(f"- **MITRE:** `{f['mitre']}`")
                        st.markdown(f"- **Log_IDs:** `{f['evidencia_logs']}`")

                st.info(f"**🛡️ Plan de Contención y Remediación:**\n{f['remediacion']}")
                st.code(f["comandos_contencion"], language="powershell")

# =====================================================================
# MÓDULO 2.5: INGENIERÍA DE DETECCIÓN (LOLBAS, GTFOBINS, SIGMA, YARA & YARA-X)
# =====================================================================
if show_all or workspace_mode == "🧬 LOLBAS, GTFOBins & Reglas (Sigma / YARA / YARA-X)":
    with st.container(border=True):
        det_h1, det_h2, det_h3 = st.columns([2.2, 1.0, 1.0], vertical_alignment="center")
        with det_h1:
            st.markdown("### 🧬 Laboratorio de Ingeniería de Detección: LOLBAS · GTFOBins · Sigma · YARA · YARA-X")
            st.caption(
                "Mapeo forense de binarios nativos abusados (Living Off The Land) en los 715 eventos y reglas listas para SIEM/EDR."
            )
        with det_h2:
            st.link_button(
                "🌐 Abrir LOLBAS Project Oficial",
                "https://lolbas-project.github.io/",
                width="stretch",
            )
        with det_h3:
            st.link_button(
                "🌐 Abrir GTFOBins Oficial",
                "https://gtfobins.org/",
                width="stretch",
            )

        lolbas_df = pd.DataFrame(get_lolbas_gtfobins_catalog())
        st.dataframe(
            lolbas_df,
            width="stretch",
            hide_index=True,
            column_config={
                "binario": st.column_config.TextColumn("Binario Abusado"),
                "catalogo": st.column_config.TextColumn("Catálogo"),
                "incidente": st.column_config.TextColumn("Incidente"),
                "log_ids": st.column_config.TextColumn("Evidencia (Log_IDs)"),
                "host": st.column_config.TextColumn("Host / Cuenta"),
                "comando_detectado": st.column_config.TextColumn("Comando Exacto en SIEM"),
                "funcion_abusada": st.column_config.TextColumn("Función Abusada"),
                "mitre": st.column_config.TextColumn("MITRE ATT&CK"),
                "lolbas_url": st.column_config.LinkColumn("Referencia LOLBAS", display_text="LOLBAS ↗"),
                "gtfobins_url": st.column_config.LinkColumn("Referencia GTFOBins", display_text="GTFOBins ↗"),
                "riesgo": st.column_config.TextColumn("Riesgo"),
            },
        )

        rule_view = st.segmented_control(
            "🛡️ Seleccionar Motor de Reglas de Detección:",
            options=[
                "📡 Reglas Sigma (.yml — Correlación SIEM & Trampas Informational)",
                "🧬 Reglas YARA Clásico (.yar — Escaneo Memoria/Disco)",
                "🦀 Reglas YARA-X Next-Gen (.yarx — Motor Rust de VirusTotal)",
            ],
            default="📡 Reglas Sigma (.yml — Correlación SIEM & Trampas Informational)",
        )

        sigma_code = get_sigma_rules_yaml()
        yara_code = get_yara_classic_rules()
        yarax_code = get_yarax_nextgen_rules()

        dl_c1, dl_c2, dl_c3 = st.columns(3)
        with dl_c1:
            st.download_button(
                "📥 Descargar Reglas Sigma (.yml)",
                data=sigma_code.encode("utf-8"),
                file_name="soc_l2_sigma_rules.yml",
                mime="text/yaml",
                width="stretch",
                key="dl_sigma_btn",
            )
        with dl_c2:
            st.download_button(
                "📥 Descargar Reglas YARA (.yar)",
                data=yara_code.encode("utf-8"),
                file_name="soc_l2_yara_classic.yar",
                mime="text/plain",
                width="stretch",
                key="dl_yara_btn",
            )
        with dl_c3:
            st.download_button(
                "📥 Descargar Reglas YARA-X (.yarx)",
                data=yarax_code.encode("utf-8"),
                file_name="soc_l2_yarax_rust.yarx",
                mime="text/plain",
                width="stretch",
                key="dl_yarax_btn",
            )

        if rule_view and rule_view.startswith("📡"):
            st.code(sigma_code, language="yaml")
        elif rule_view and rule_view.startswith("🧬"):
            st.code(yara_code, language="c")
        else:
            st.code(yarax_code, language="rust")

# =====================================================================
# MÓDULO 3: ANALÍTICA VISUAL FLUIDA & AUDITORÍA DE EVASIÓN SIEM
# =====================================================================
if show_all or workspace_mode == "📊 Analítica Visual & Trampas 'Informational'":
    with st.container(border=True):
        st.markdown("### 📊 Telemetría Visual Interactiva & Auditoría de Evasión SIEM")
        st.caption(
            "Gráficos sincronizados con los 124 eventos maliciosos correlacionados y los 12 eventos críticos rescatados de severidad 'Informational'."
        )

        ch_col1, ch_col2 = st.columns(2)
        with ch_col1:
            inc_df = df[df["Incident_ID"] != "NONE"].copy()
            inc_df["Visibilidad SIEM"] = inc_df["Severity"].apply(
                lambda s: "Oculto en 'Informational' (Rescatado L2)" if s == "Informational" else f"Alerta SIEM ({s})"
            )
            inc_grouped = (
                inc_df.groupby(["Incident_Tag", "Visibilidad SIEM"])
                .size()
                .reset_index(name="Eventos")
            )
            fig_inc = px.bar(
                inc_grouped,
                x="Eventos",
                y="Incident_Tag",
                color="Visibilidad SIEM",
                orientation="h",
                title=f"🎯 Eventos por Incidente (Total: {summary_metrics['correlated_malicious_events']})",
                color_discrete_map={
                    "Alerta SIEM (High)": "#FF2A5F",
                    "Alerta SIEM (Medium)": "#F97316",
                    "Alerta SIEM (Warning)": "#FBBF24",
                    "Oculto en 'Informational' (Rescatado L2)": "#00F0FF",
                },
                text="Eventos",
                template="plotly_dark",
            )
            fig_inc.update_layout(
                yaxis={"categoryorder": "total ascending", "title": ""},
                xaxis_title="Eventos Correlacionados",
                legend_title="Visibilidad SIEM",
                height=360,
                margin=dict(l=10, r=10, t=42, b=15),
                paper_bgcolor="rgba(15,23,42,0.92)",
                plot_bgcolor="rgba(15,23,42,0.92)",
            )
            st.plotly_chart(fig_inc, width="stretch")

        with ch_col2:
            timeline_df = (
                df[df["Incident_ID"] != "NONE"]
                .groupby(["Hour_Min_10", "Incident_ID"])
                .size()
                .reset_index(name="Eventos")
            )
            timeline_df["Hora"] = timeline_df["Hour_Min_10"].dt.strftime("%H:%M")
            fig_time = px.bar(
                timeline_df,
                x="Hora",
                y="Eventos",
                color="Incident_ID",
                title="⏱️ Progresión Cronológica de Ataques (Ventanas de 10 min)",
                color_discrete_sequence=["#FF2A5F", "#F97316", "#FBBF24", "#8B5CF6", "#00F0FF", "#10B981"],
                text="Eventos",
                template="plotly_dark",
            )
            fig_time.update_layout(
                xaxis_title="Hora UTC (2026-10-23)",
                yaxis_title="Eventos Maliciosos",
                legend_title="Incidente",
                height=360,
                margin=dict(l=10, r=10, t=42, b=15),
                paper_bgcolor="rgba(15,23,42,0.92)",
                plot_bgcolor="rgba(15,23,42,0.92)",
            )
            st.plotly_chart(fig_time, width="stretch")

        ch_col3, ch_col4 = st.columns(2)
        with ch_col3:
            host_df = (
                df[df["Incident_ID"] != "NONE"]
                .groupby(["Hostname_Norm", "Incident_ID"])
                .size()
                .reset_index(name="Eventos")
            )
            fig_host = px.bar(
                host_df,
                x="Hostname_Norm",
                y="Eventos",
                color="Incident_ID",
                title="🖥️ Activos Comprometidos (Hostnames Normalizados)",
                color_discrete_sequence=["#FF2A5F", "#F97316", "#FBBF24", "#8B5CF6", "#00F0FF", "#10B981"],
                text="Eventos",
                template="plotly_dark",
            )
            fig_host.update_layout(
                xaxis_title="Activo Corporativo",
                height=330,
                margin=dict(l=10, r=10, t=42, b=15),
                paper_bgcolor="rgba(15,23,42,0.92)",
                plot_bgcolor="rgba(15,23,42,0.92)",
            )
            st.plotly_chart(fig_host, width="stretch")

        with ch_col4:
            ip_df = (
                df[df["Incident_ID"] != "NONE"]
                .groupby(["Source_IP", "Incident_ID"])
                .size()
                .reset_index(name="Eventos")
            )
            fig_ip = px.bar(
                ip_df,
                x="Eventos",
                y="Source_IP",
                color="Incident_ID",
                orientation="h",
                title="🌐 IPs de Origen en Incidentes (Externas y Pivotes)",
                color_discrete_sequence=["#FF2A5F", "#F97316", "#FBBF24", "#8B5CF6", "#00F0FF", "#10B981"],
                text="Eventos",
                template="plotly_dark",
            )
            fig_ip.update_layout(
                yaxis={"categoryorder": "total ascending"},
                height=330,
                margin=dict(l=10, r=10, t=42, b=15),
                paper_bgcolor="rgba(15,23,42,0.92)",
                plot_bgcolor="rgba(15,23,42,0.92)",
            )
            st.plotly_chart(fig_ip, width="stretch")

        with st.expander(
            f"🕵️‍♂️ Ver Tabla de los {summary_metrics['hidden_info_critical_events']} Eventos Críticos Ocultos en 'Informational' + Normalización DC-01/DC01",
            expanded=not show_all,
        ):
            hidden_df_view = df[df["Hidden_Critical_Info"]][
                [
                    "Log_ID",
                    "Timestamp",
                    "Incident_ID",
                    "Hostname",
                    "Event_ID",
                    "User",
                    "Source_IP",
                    "Destination",
                    "Event_Description",
                    "Process_CommandLine",
                    "Severity",
                ]
            ]
            st.dataframe(hidden_df_view, width="stretch", hide_index=True)
            n1, n2 = st.columns(2)
            n1.info(
                f"**🖥️ Normalización de Activos (`DC-01` vs `DC01`):** `DC-01` ({summary_metrics['normalization']['dc_hyphen_count']} logs) + "
                f"`DC01` ({summary_metrics['normalization']['dc_no_hyphen_count']} logs) $\\rightarrow$ unificados en `Hostname_Norm = DC-01`."
            )
            n2.info(
                f"**👤 Dualidad de Cuentas (`backupsvc` vs `svc_backup`):** `CORP\\backupsvc` ({summary_metrics['normalization']['backupsvc_count']} logs, "
                f"comprometida en `INC-03`) vs `CORP\\svc_backup` ({summary_metrics['normalization']['svc_backup_count']} logs)."
            )

# =====================================================================
# MÓDULO 4: ESTUDIO DE INFORMES LANGCHAIN (C-LEVEL + DFIR) & PDF
# =====================================================================
if show_all or workspace_mode == "📄 Estudio de Informes (C-Level / DFIR) & PDF":
    with st.container(border=True):
        st.markdown("### 📄 Estudio Dual de Informes LangChain (`RunnableParallel`) & Compilador PDF")
        bar_c1, bar_c2 = st.columns([1.3, 2.5], vertical_alignment="center")
        with bar_c1:
            regen = st.button(
                "🔗 Ejecutar Pipeline LangChain LCEL",
                type="secondary",
                width="stretch",
            )
        with bar_c2:
            st.success(f"🟢 {st.session_state.get('ai_status', 'Pipeline LangChain LCEL sincronizado.')}")

        if regen:
            with st.spinner("Ejecutando RunnableParallel(executive=exec_chain, technical=tech_chain)..."):
                exec_rep, tech_rep, status_msg = generate_ai_reports(
                    findings, summary_metrics, provider, model_name, api_url, api_key
                )
                st.session_state["exec_rep"] = exec_rep
                st.session_state["tech_rep"] = tech_rep
                st.session_state["ai_status"] = status_msg
                st.rerun()

        ed_col1, ed_col2 = st.columns(2)
        with ed_col1:
            st.markdown("#### 👔 1. Informe Ejecutivo (C-Level / Junta Directiva)")
            st.text_area(
                "Editor Ejecutivo:",
                key="exec_rep",
                height=340,
                label_visibility="collapsed",
            )
        with ed_col2:
            st.markdown("#### 🛠️ 2. Informe Técnico Forense (Ingeniería SOC L2 / DFIR)")
            st.text_area(
                "Editor Técnico:",
                key="tech_rep",
                height=340,
                label_visibility="collapsed",
            )

        final_pdf_bytes = cached_compile_pdf(
            st.session_state["exec_rep"],
            st.session_state["tech_rep"],
            findings,
            summary_metrics,
            df,
        )
        st.download_button(
            label="📥 DESCARGAR INFORME OFICIAL EN PDF (EJECUTIVO C-LEVEL + TÉCNICO DFIR + MITRE ATT&CK)",
            data=final_pdf_bytes,
            file_name="Informe_Final_SOC_L2_Incidentes.pdf",
            mime="application/pdf",
            type="primary",
            width="stretch",
            key="studio_pdf_btn",
        )

# =====================================================================
# MÓDULO 5: EXPLORADOR FLUIDO DE TELEMETRÍA SIEM (715 LOGS)
# =====================================================================
if show_all or workspace_mode == "🔎 Telemetría SIEM en Vivo (715 Logs)":
    with st.container(border=True):
        st.markdown("### 🔎 Stream Forense de Telemetría SIEM (715 Eventos)")
        opt_malicious = f"🔴 Maliciosos Correlacionados ({summary_metrics['correlated_malicious_events']})"
        opt_hidden = f"🕵️‍♂️ Críticos Ocultos en 'Info' ({summary_metrics['hidden_info_critical_events']})"
        opt_ext_ip = f"🌐 Tráfico con IPs Externas ({summary_metrics.get('external_ip_events_count', int(df['External_IP'].sum() if 'External_IP' in df.columns else 0))})"
        opt_all = f"📋 Dataset Completo ({summary_metrics['total_logs']})"

        f_top1, f_top2, f_top3 = st.columns([2.3, 1.1, 1.2], vertical_alignment="center")
        with f_top1:
            preset = st.segmented_control(
                "Filtro Rápido:",
                options=[opt_malicious, opt_hidden, opt_ext_ip, opt_all],
                default=opt_malicious,
                label_visibility="collapsed",
            )
        with f_top2:
            sel_inc = st.selectbox(
                "Incidente",
                ["Todos los Incidentes"] + list(df["Incident_Tag"].unique()),
                label_visibility="collapsed",
            )
        with f_top3:
            search_q = st.text_input(
                "Buscar IOC / Comando / Log_ID",
                value="",
                placeholder="🔎 Buscar Log_ID, IP, usuario, comando...",
                label_visibility="collapsed",
            )

        filtered = df.copy()
        if preset == opt_malicious:
            filtered = filtered[filtered["Incident_ID"] != "NONE"]
        elif preset == opt_hidden:
            filtered = filtered[filtered["Hidden_Critical_Info"]]
        elif preset == opt_ext_ip:
            filtered = filtered[filtered["Involves_External_IP"]]

        if sel_inc != "Todos los Incidentes":
            filtered = filtered[filtered["Incident_Tag"] == sel_inc]
        if search_q.strip():
            q = search_q.strip().lower()
            mask_q = (
                filtered["Log_ID"].astype(str).str.lower().str.contains(q)
                | filtered["User"].astype(str).str.lower().str.contains(q)
                | filtered["Source_IP"].astype(str).str.lower().str.contains(q)
                | filtered["Destination"].astype(str).str.lower().str.contains(q)
                | filtered["Event_Description"].astype(str).str.lower().str.contains(q)
                | filtered["Process_CommandLine"].astype(str).str.lower().str.contains(q)
            )
            filtered = filtered[mask_q]

        st.caption(f"Mostrando **{len(filtered):,}** de **{len(df):,}** registros SIEM.")
        display_cols = [
            "Log_ID",
            "Timestamp",
            "Incident_ID",
            "Severity",
            "Hostname",
            "Event_ID",
            "User",
            "Source_IP",
            "Destination",
            "Log_Source",
            "Event_Description",
            "Process_CommandLine",
            "Result",
            "Hidden_Critical_Info",
        ]
        st.dataframe(filtered[display_cols], width="stretch", height=400, hide_index=True)
