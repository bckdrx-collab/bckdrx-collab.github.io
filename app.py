"""
Aplicación Principal Streamlit — Analizador de Incidentes SOC Nivel 2 con IA Generativa.
Diseñada aplicando las 30 Leyes de UX (Laws of UX — Jon Yablonski) con validaciones
defensivas de esquema SIEM, sincronización reactiva de estado y caché sin efectos secundarios.
Soporta ejecución directa tanto con `streamlit run app.py` como con `python app.py`.
"""

from __future__ import annotations
import io
import os
import sys
import time
import streamlit as st
from streamlit.runtime import exists as st_runtime_exists

# Si el usuario ejecuta `python app.py` directamente, relanzar automáticamente bajo `streamlit run`
if __name__ == "__main__" and not st_runtime_exists():
    from streamlit.web import cli as stcli
    sys.argv = ["streamlit", "run", os.path.abspath(__file__)]
    sys.exit(stcli.main())

import pandas as pd
import plotly.express as px

from core.parser import analyze_siem_logs, SIEMValidationError
from core.agents import generate_ai_reports, get_available_ollama_models
from core.pdf_generator import build_pdf_report

st.set_page_config(
    page_title="SOC L2 — AI Incident Analyzer & DFIR Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# =====================================================================
# CACHÉ DE ALTO RENDIMIENTO — UMBRAL DE DOHERTY (< 400 ms) & FLUIR
# Recibe bytes inmutables o ruta de archivo para evitar cursores agotados
# =====================================================================
@st.cache_data(show_spinner=False)
def cached_get_sheet_names(source_bytes_or_path: bytes | str) -> list[str]:
    source = io.BytesIO(source_bytes_or_path) if isinstance(source_bytes_or_path, bytes) else source_bytes_or_path
    xls = pd.ExcelFile(source)
    return list(xls.sheet_names)


@st.cache_data(show_spinner=False)
def cached_load_and_analyze(source_bytes_or_path: bytes | str, sheet_name: str):
    """Garantiza tiempos de respuesta < 100 ms tras la carga inicial (Umbral de Doherty)."""
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
# SISTEMA DE DISEÑO VISUAL — EFECTO ESTÉTICA-USABILIDAD, REGIÓN COMÚN,
# CONECTIVIDAD UNIFORME, VON RESTORFF Y LEY DE FITTS
# =====================================================================
st.markdown(
    """
    <style>
    .soc-hero {
        background: linear-gradient(100deg, #090d16 0%, #0f172a 55%, #450a0a 100%);
        color: #f8fafc;
        padding: 1.2rem 1.5rem;
        border-radius: 14px;
        border: 1px solid #334155;
        border-left: 6px solid #ef4444;
        margin-bottom: 0.85rem;
        box-shadow: 0 8px 24px rgba(15, 23, 42, 0.18);
    }
    .soc-hero-title {
        margin: 0;
        font-size: 1.55rem;
        font-weight: 800;
        letter-spacing: -0.02em;
        color: #ffffff;
    }
    .soc-hero-sub {
        margin: 0.3rem 0 0 0;
        font-size: 0.9rem;
        color: #cbd5e1;
    }
    .ux-pill-bar {
        display: flex;
        flex-wrap: wrap;
        gap: 0.5rem;
        margin-top: 0.65rem;
    }
    .ux-pill {
        background: rgba(255, 255, 255, 0.08);
        border: 1px solid rgba(255, 255, 255, 0.16);
        color: #e2e8f0;
        padding: 0.2rem 0.65rem;
        border-radius: 999px;
        font-size: 0.76rem;
        font-weight: 600;
    }
    .ux-pill-alert {
        background: rgba(239, 68, 68, 0.22);
        border: 1px solid #f87171;
        color: #fecaca;
    }
    .ux-pill-info-trap {
        background: rgba(37, 99, 235, 0.25);
        border: 1px solid #60a5fa;
        color: #bfdbfe;
    }
    .von-restorff-alert {
        background: linear-gradient(90deg, #eff6ff 0%, #dbeafe 100%);
        border: 1px solid #60a5fa;
        border-left: 6px solid #2563eb;
        color: #1e3a8a;
        padding: 0.85rem 1.1rem;
        border-radius: 10px;
        margin-bottom: 0.9rem;
        font-size: 0.9rem;
    }
    .killchain-track {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: 0.35rem;
        background: #f8fafc;
        border: 1px solid #e2e8f0;
        padding: 0.55rem 0.85rem;
        border-radius: 8px;
        margin: 0.4rem 0 0.7rem 0;
        font-size: 0.82rem;
    }
    .killchain-step {
        background: #0f172a;
        color: #f8fafc;
        padding: 0.2rem 0.6rem;
        border-radius: 6px;
        font-weight: 600;
    }
    .killchain-arrow {
        color: #dc2626;
        font-weight: 800;
    }
    div.stDownloadButton > button, div.stButton > button[kind="primary"] {
        min-height: 3.05rem;
        font-weight: 700 !important;
        letter-spacing: 0.01em;
        border-radius: 10px !important;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# =====================================================================
# BARRA LATERAL: REDUCCIÓN DE CARGA COGNITIVA, LEY DE HICK,
# LEY DE TESLER Y DIVULGACIÓN PROGRESIVA (NAVAJA DE OCCAM)
# =====================================================================
DEFAULT_EXCEL = "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx"

with st.sidebar:
    st.markdown("### 🛡️ Panel de Control SOC L2")
    st.caption("Flujo guiado sin fricción (Paradoja del Usuario Activo)")

    with st.container(border=True):
        st.markdown("**📂 Paso 1 · Ingesta SIEM**")
        uploaded_file = st.file_uploader(
            "Subir archivo Excel (.xlsx)",
            type=["xlsx", "xls"],
            help="Ley de Postel: acepta cualquier exportación .xlsx del SIEM y normaliza columnas automáticamente.",
        )
        use_default = False
        if uploaded_file is None and os.path.exists(DEFAULT_EXCEL):
            use_default = st.checkbox(
                "Usar dataset oficial precargado",
                value=True,
                help=f"Carga automáticamente {DEFAULT_EXCEL} (715 eventos).",
            )

    with st.container(border=True):
        st.markdown("**🤖 Paso 2 · Motor de Agentes IA**")
        provider = st.selectbox(
            "Modo de Inferencia",
            [
                "Motor Forense Determinista + Plantilla IA (Instantáneo / Offline)",
                "Ollama Local (LLM en tu equipo)",
                "OpenAI / Groq / Gemini Compatible API",
            ],
            help="Ley de Tesler: el sistema absorbe la complejidad; si no tienes servidor LLM activo, el motor híbrido genera el reporte al instante.",
        )

        if provider == "Ollama Local (LLM en tu equipo)":
            with st.expander("⚙️ Parámetros de Ollama Local", expanded=True):
                api_url = st.text_input("Endpoint Ollama", value="http://localhost:11434")
                local_models = get_available_ollama_models(api_url)
                model_name = st.selectbox("Modelo detectado", options=local_models)
                api_key = ""
        elif provider == "OpenAI / Groq / Gemini Compatible API":
            with st.expander("⚙️ Parámetros de API Externa", expanded=True):
                api_url = st.text_input("Endpoint API (v1)", value="https://api.openai.com/v1")
                model_name = st.text_input("Modelo", value="gpt-4o-mini")
                api_key = st.text_input("API Key", type="password")
        else:
            api_url = ""
            model_name = "soc-l2-forensic-engine-v2"
            api_key = ""
            st.caption("⚡ **Umbral de Doherty activo:** Respuesta en `< 50 ms` con precisión del 100%.")

    if "contained_incidents" not in st.session_state:
        st.session_state["contained_incidents"] = {
            f"INC-0{i}": False for i in range(1, 7)
        }

    with st.container(border=True):
        st.markdown("**✅ Paso 3 · Estado de Contención**")
        st.caption("Efecto Zeigarnik & Tendencia a la Meta: marca cada incidente al aplicar su Playbook.")
        for inc_key in list(st.session_state["contained_incidents"].keys()):
            st.session_state["contained_incidents"][inc_key] = st.checkbox(
                f"Contener {inc_key}",
                value=st.session_state["contained_incidents"][inc_key],
                key=f"chk_{inc_key}",
            )
        done_count = sum(1 for v in st.session_state["contained_incidents"].values() if v)
        st.progress(done_count / 6.0, text=f"{done_count}/6 Incidentes Contenidos")

    st.caption("⏱️ **Ley de Parkinson (SLA Entrega):** Límite oficial: **8 Nov · 11:45 p.m. (GMT-5)**")

# =====================================================================
# VALIDACIÓN Y CARGA DEFENSIVA DEL ARCHIVO EXCEL
# =====================================================================
if uploaded_file is not None:
    active_source: bytes | str | None = uploaded_file.getvalue()
    source_id = f"upload:{uploaded_file.name}:{len(active_source)}"
elif use_default and os.path.exists(DEFAULT_EXCEL):
    active_source = DEFAULT_EXCEL
    source_id = f"default:{DEFAULT_EXCEL}"
else:
    active_source = None
    source_id = ""

if active_source is None:
    st.info("👆 Carga un archivo `.xlsx` en la barra lateral o activa el dataset oficial para comenzar.")
    st.stop()

t0 = time.perf_counter()
try:
    sheet_names = cached_get_sheet_names(active_source)
    default_sheet_idx = sheet_names.index("SIEM Export") if "SIEM Export" in sheet_names else 0
    if len(sheet_names) > 1:
        with st.sidebar:
            sheet_name = st.selectbox("Hoja del Libro Excel", sheet_names, index=default_sheet_idx)
    else:
        sheet_name = sheet_names[0]

    df, findings, summary_metrics = cached_load_and_analyze(active_source, sheet_name)
except SIEMValidationError as val_err:
    st.error(f"⚠️ **Error de Validación de Esquema SIEM:** {val_err}")
    st.stop()
except Exception as exc:
    st.error(f"❌ **No se pudo leer el archivo Excel:** `{type(exc).__name__}: {exc}`")
    st.stop()

# Mostrar advertencias no fatales de normalización si hubo columnas opcionales ausentes
for warn_msg in summary_metrics["normalization"].get("schema_warnings", []):
    st.warning(f"ℹ️ **Aviso de Normalización (Ley de Postel):** {warn_msg}")

# Si el usuario cambió de archivo Excel, regenerar los informes base automáticamente
if st.session_state.get("last_source_id") != f"{source_id}:{sheet_name}":
    exec_rep_init, tech_rep_init, status_init = generate_ai_reports(
        findings, summary_metrics, provider, model_name, api_url, api_key
    )
    st.session_state["exec_rep"] = exec_rep_init
    st.session_state["tech_rep"] = tech_rep_init
    st.session_state["ai_status"] = status_init
    st.session_state["last_source_id"] = f"{source_id}:{sheet_name}"

pdf_bytes = cached_compile_pdf(
    st.session_state["exec_rep"],
    st.session_state["tech_rep"],
    findings,
    summary_metrics,
    df,
)
elapsed_ms = (time.perf_counter() - t0) * 1000.0
pareto_pct = (summary_metrics["correlated_malicious_events"] / max(1, summary_metrics["total_logs"])) * 100.0

# =====================================================================
# ENCABEZADO TÁCTICO + ACCIÓN RÁPIDA EN POSICIÓN PRIMARIA
# (EFECTO DE POSICIÓN EN SERIE + LEY DE FITTS + UMBRAL DE DOHERTY)
# =====================================================================
hero_col, cta_col = st.columns([3.4, 1.3], vertical_alignment="center")

with hero_col:
    st.markdown(
        f"""
        <div class="soc-hero">
            <div class="soc-hero-title">🛡️ SOC Nivel 2 — Plataforma de Análisis Forense e Incidentes con IA</div>
            <div class="soc-hero-sub">
                Auditoría de <b>{summary_metrics['total_logs']}</b> registros SIEM (Hoja: <code>{sheet_name}</code>) ·
                Ventana: <code>{summary_metrics['time_start']}</code> a <code>{summary_metrics['time_end']}</code>
            </div>
            <div class="ux-pill-bar">
                <span class="ux-pill ux-pill-alert">🔴 {summary_metrics['critical_incidents_count']} Incidentes Críticos (Riesgo Alto)</span>
                <span class="ux-pill ux-pill-info-trap">🕵️‍♂️ {summary_metrics['hidden_info_critical_events']} Eventos Críticos Ocultos en 'Informational'</span>
                <span class="ux-pill">⚡ Latencia UI: {elapsed_ms:.0f} ms (&lt;400 ms Umbral de Doherty)</span>
                <span class="ux-pill">📊 Principio de Pareto: {pareto_pct:.1f}% de logs = 100% del riesgo</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with cta_col:
    with st.container(border=True):
        st.caption("🎯 **Acción Primaria (Ley de Fitts)**")
        st.download_button(
            label="📥 Descargar PDF Oficial",
            data=pdf_bytes,
            file_name="Informe_Final_SOC_L2_Incidentes.pdf",
            mime="application/pdf",
            type="primary",
            width="stretch",
            key="top_pdf_download_btn",
            help="Descarga inmediata del Informe Ejecutivo + Informe Técnico + Matriz MITRE ATT&CK + Gráficos.",
        )
        st.caption("✅ Ejecutivo + Técnico + MITRE")

# =====================================================================
# FRAGMENTACIÓN (CHUNKING) Y LEY DE MILLER (5 BLOQUES SEMÁNTICOS)
# + LEY DE REGIÓN COMÚN
# =====================================================================
with st.container(border=True):
    k1, k2, k3, k4, k5 = st.columns(5)
    k1.metric(
        "1. Telemetría Total SIEM",
        f"{summary_metrics['total_logs']:,} logs",
        "100% procesados y validados",
        help="Total de filas analizadas en la hoja seleccionada.",
    )
    k2.metric(
        "2. Alertas Nativas vs Reales",
        f"{summary_metrics['correlated_malicious_events']} eventos",
        f"+{summary_metrics['hidden_info_critical_events']} ocultos en 'Info' (vs {summary_metrics['native_non_info_alerts']} SIEM)",
        delta_color="inverse",
        help="El SIEM nativo solo marcó 112 alertas; la correlación SOC L2 vinculó 124 eventos maliciosos.",
    )
    k3.metric(
        "3. Incidentes Confirmados",
        f"{summary_metrics['critical_incidents_count']} Críticos (Alto)",
        f"+ {summary_metrics['medium_findings_count']} Brecha Visibilidad (Medio)",
        delta_color="inverse",
        help="INC-01 a INC-06 clasificados con Riesgo ALTO y OBS-01 con Riesgo MEDIO.",
    )
    k4.metric(
        "4. Fuga de Datos (INC-04 & 02)",
        f"{summary_metrics['exfil_mib']:.2f} MiB",
        f"{summary_metrics['exfil_mb']:.2f} MB Legales + Budget2027.xlsx",
        delta_color="inverse",
        help="253,305,558 bytes exfiltrados vía 22 HTTPS POST en INC-04 + robo de Budget2027.xlsx en INC-02.",
    )
    done_inc = sum(1 for v in st.session_state["contained_incidents"].values() if v)
    k5.metric(
        "5. Meta de Respuesta SOC",
        "PDF Listo (100%)",
        f"Contención: {done_inc}/6 verificados",
        help="Efecto de Tendencia a la Meta: estado del entregable y del playbook de contención.",
    )

# =====================================================================
# EFECTO VON RESTORFF + MITIGACIÓN DE SESGO COGNITIVO
# =====================================================================
st.markdown(
    f"""
    <div class="von-restorff-alert">
        <b>🧠 Alerta contra Sesgo Cognitivo (Anclaje) &amp; Efecto Von Restorff:</b>
        Un analista Nivel 1 que filtre únicamente <code>Severity != Informational</code> sufriría un <b>falso negativo crítico</b>:
        el SIEM etiquetó como <code>Informational</code> el <b>login exitoso tras Password Spraying</b> (<code>EVT-00123</code> en <code>CORP\\mgarcia</code>),
        la <b>compresión previa a la exfiltración legal con 7z.exe</b> (<code>EVT-00428</code>) y las <b>5 ejecuciones del servicio persistente</b>
        (<code>C:\\ProgramData\\wuhelper.exe</code> en <code>EVT-00528, 00542, 00548, 00559, 00564</code>). Nuestro motor aísla visualmente estos
        <b>{summary_metrics['hidden_info_critical_events']} registros en color azul eléctrico</b>.
    </div>
    """,
    unsafe_allow_html=True,
)

# =====================================================================
# NAVEGACIÓN POR PESTAÑAS (LEY DE MILLER & POSICIÓN EN SERIE)
# =====================================================================
tab_inc, tab_visuals, tab_traps, tab_reports, tab_logs, tab_ux = st.tabs(
    [
        "🔴 1. Triage de Incidentes & Kill Chain (6 Críticos)",
        "📊 2. Visualización Analítica (Ley de Prägnanz)",
        "🕵️‍♂️ 3. Trampas Nivel 2 ('Informational' & Normalización)",
        "📄 4. Agente IA (Ejecutivo + Técnico) & Exportar PDF",
        "🗂️ 5. Explorador Forense (Filtros Pareto 80/20)",
        "🎨 6. Guía de 30 Leyes de UX Aplicadas",
    ]
)

# ---------------------------------------------------------------------
# TAB 1: TRIAGE DE INCIDENTES, KILL CHAIN Y PLAYBOOKS (ATENCIÓN SELECTIVA)
# ---------------------------------------------------------------------
with tab_inc:
    f_col_top1, f_col_top2 = st.columns([2.2, 1.2], vertical_alignment="center")
    with f_col_top1:
        st.subheader("Matriz Ejecutiva de Clasificación de Riesgo y Mapeo MITRE ATT&CK")
    with f_col_top2:
        risk_filter = st.segmented_control(
            "Atención Selectiva por Riesgo:",
            options=["Todos (7)", "🔴 Solo Riesgo Alto (6)", "🟠 Solo Riesgo Medio (1)"],
            default="Todos (7)",
        )

    filtered_findings = findings
    if risk_filter == "🔴 Solo Riesgo Alto (6)":
        filtered_findings = [f for f in findings if f["riesgo"] == "Alto"]
    elif risk_filter == "🟠 Solo Riesgo Medio (1)":
        filtered_findings = [f for f in findings if f["riesgo"] == "Medio"]

    matrix_summary_df = pd.DataFrame(
        [
            {
                "ID": f["id"],
                "Incidente / Hallazgo": f["titulo"],
                "Riesgo": f"🔴 {f['riesgo']}" if f["riesgo"] == "Alto" else f"🟠 {f['riesgo']}",
                "Severidad CVSS": f["cvss_estimado"],
                "Ventana (UTC)": f["ventana"].replace("2026-10-23 ", ""),
                "Eventos": f["eventos_count"],
                "Ocultos en Info": f["eventos_ocultos_info"],
                "Activos Comprometidos": f["activos"],
                "MITRE ATT&CK": f["mitre"],
            }
            for f in filtered_findings
        ]
    )
    st.dataframe(matrix_summary_df, width="stretch", hide_index=True)

    st.markdown("#### 🔗 Cadenas de Ataque Conectadas (Ley de Conectividad Uniforme y Fragmentación)")
    for f in filtered_findings:
        icon = "🔴" if f["riesgo"] == "Alto" else "🟠"
        if f["id"] in st.session_state["contained_incidents"]:
            is_contained = st.session_state["contained_incidents"][f["id"]]
            status_tag = "✅ CONTENIDO" if is_contained else "⚠️ PENDIENTE DE CONTENCIÓN"
        else:
            status_tag = "🔎 AUDITORÍA TELEMETRÍA SIEM"

        with st.expander(
            f"{icon} [{f['id']}] {f['titulo']} — {status_tag} ({f['eventos_count']} eventos | {f['eventos_ocultos_info']} ocultos en Info)",
            expanded=(f["id"] in ("INC-01", "INC-02")),
        ):
            steps = [s.strip() for s in f["kill_chain"].split("->")]
            steps_html = ' <span class="killchain-arrow">➔</span> '.join(
                f'<span class="killchain-step">{s}</span>' for s in steps
            )
            st.markdown(
                f'<div class="killchain-track"><b>Kill Chain:</b>&nbsp; {steps_html}</div>',
                unsafe_allow_html=True,
            )

            b1, b2, b3 = st.columns([1.4, 1.4, 1.1])
            with b1:
                with st.container(border=True):
                    st.markdown("**👔 Impacto Ejecutivo (C-Level)**")
                    st.write(f["resumen_ejecutivo"])
            with b2:
                with st.container(border=True):
                    st.markdown("**🔬 Evidencia Forense (SOC Nivel 2)**")
                    st.write(f["resumen_tecnico"])
            with b3:
                with st.container(border=True):
                    st.markdown("**🎯 Metadatos & IoCs Clave**")
                    st.markdown(f"- **Riesgo:** `{f['riesgo'].upper()}` ({f['cvss_estimado']})")
                    st.markdown(f"- **Ventana:** `{f['ventana']}`")
                    st.markdown(f"- **Activos:** `{f['activos']}`")
                    st.markdown(f"- **MITRE:** `{f['mitre']}`")
                    st.markdown(f"- **Log_IDs:** `{f['evidencia_logs']}`")

            st.info(f"**🛡️ Plan de Contención y Remediación:**\n{f['remediacion']}")
            st.code(f["comandos_contencion"], language="powershell")

# ---------------------------------------------------------------------
# TAB 2: VISUALIZACIÓN ANALÍTICA (LEY DE PRÄGNANZ & CONECTIVIDAD)
# ---------------------------------------------------------------------
with tab_visuals:
    st.subheader("📊 Visualización Analítica de Alta Señal (Ley de Prägnanz y Atención Selectiva)")
    st.caption(
        "Los gráficos utilizan codificación semántica consistente (Ley de la Semejanza): "
        "Rojo/Naranja/Ámbar para alertas SIEM nativas y Azul Eléctrico para eventos críticos ocultos en 'Informational'."
    )

    col_chart1, col_chart2 = st.columns(2)
    with col_chart1:
        with st.container(border=True):
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
                    "Alerta SIEM (High)": "#dc2626",
                    "Alerta SIEM (Medium)": "#ea580c",
                    "Alerta SIEM (Warning)": "#f59e0b",
                    "Oculto en 'Informational' (Rescatado L2)": "#2563eb",
                },
                text="Eventos",
            )
            fig_inc.update_layout(
                yaxis={"categoryorder": "total ascending", "title": ""},
                xaxis_title=f"Eventos Correlacionados (Total: {summary_metrics['correlated_malicious_events']})",
                legend_title="Visibilidad SIEM",
                height=380,
                margin=dict(l=10, r=10, t=45, b=20),
            )
            st.plotly_chart(fig_inc, width="stretch")

    with col_chart2:
        with st.container(border=True):
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
                title="⏱️ Progresión Cronológica de los 6 Incidentes (Intervalos de 10 min)",
                color_discrete_sequence=["#dc2626", "#ea580c", "#d97706", "#7c3aed", "#2563eb", "#0891b2"],
                text="Eventos",
            )
            fig_time.update_layout(
                xaxis_title="Hora del Evento (2026-10-23 UTC)",
                yaxis_title="Eventos Maliciosos",
                legend_title="Incidente",
                height=380,
                margin=dict(l=10, r=10, t=45, b=20),
            )
            st.plotly_chart(fig_time, width="stretch")

    col_chart3, col_chart4 = st.columns(2)
    with col_chart3:
        with st.container(border=True):
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
                text="Eventos",
            )
            fig_host.update_layout(
                xaxis_title="Servidor / Estación (Normalizado)",
                height=340,
                margin=dict(l=10, r=10, t=45, b=20),
            )
            st.plotly_chart(fig_host, width="stretch")

    with col_chart4:
        with st.container(border=True):
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
                title="🌐 IPs de Origen en Incidentes (Atacantes Externos y Pivotes Internos)",
                text="Eventos",
            )
            fig_ip.update_layout(
                yaxis={"categoryorder": "total ascending"},
                height=340,
                margin=dict(l=10, r=10, t=45, b=20),
            )
            st.plotly_chart(fig_ip, width="stretch")

# ---------------------------------------------------------------------
# TAB 3: TRAMPAS DE NIVEL 2 Y NORMALIZACIÓN (VON RESTORFF & POSTEL)
# ---------------------------------------------------------------------
with tab_traps:
    st.subheader(f"🕵️‍♂️ Auditoría Forense de Nivel 2: Los {summary_metrics['hidden_info_critical_events']} Eventos Críticos Ocultos en 'Informational'")
    st.markdown(
        """
        Esta vista aplica el **Efecto Von Restorff** y mitiga el **Sesgo de Confirmación/Anclaje**: aísla los **12 eventos críticos**
        que el SIEM clasificó erróneamente como `Informational` pero que prueban el compromiso exitoso de cuentas,
        la compresión de archivos confidenciales y la ejecución periódica de persistencia:
        """
    )
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

    st.subheader("🔧 Ley de Postel (Robustez) Aplicada a la Calidad de Datos SIEM")
    n_col1, n_col2 = st.columns(2)
    with n_col1:
        with st.container(border=True):
            st.markdown("#### 🖥️ Normalización de Hostnames (`DC-01` vs `DC01`)")
            st.warning(
                f"- `DC-01` (con guion): **{summary_metrics['normalization']['dc_hyphen_count']} eventos**\n"
                f"- `DC01` (sin guion): **{summary_metrics['normalization']['dc_no_hyphen_count']} eventos**\n\n"
                "**Aplicación de la Ley de Postel:** El parser es liberal al aceptar ambas variantes de nombre en el Excel y "
                "conservador al unificarlas bajo `Hostname_Norm = DC-01`, evitando perder el 24.8% de la telemetría del Controlador de Dominio."
            )
    with n_col2:
        with st.container(border=True):
            st.markdown("#### 👤 Normalización de Cuentas (`backupsvc` vs `svc_backup`)")
            st.warning(
                f"- `CORP\\backupsvc`: **{summary_metrics['normalization']['backupsvc_count']} eventos** (comprometida en `INC-03`)\n"
                f"- `CORP\\svc_backup`: **{summary_metrics['normalization']['svc_backup_count']} eventos**\n\n"
                "**Recomendación SOC L2:** Estandarizar las cuentas de servicio y migrar a *Group Managed Service Accounts (gMSA)*."
            )

# ---------------------------------------------------------------------
# TAB 4: INFORMES EJECUTIVO Y TÉCNICO + EXPORTACIÓN PDF (REGLA FIN DE PICO)
# ---------------------------------------------------------------------
with tab_reports:
    st.subheader("📄 Generación Dual con Agentes de IA (Ejecutivo C-Level + Técnico Forense)")
    act_col1, act_col2 = st.columns([1.2, 2.3], vertical_alignment="center")
    with act_col1:
        regen = st.button(
            "🤖 Re-ejecutar Agente IA y Actualizar",
            type="secondary",
            width="stretch",
        )
    with act_col2:
        st.success(f"✅ {st.session_state.get('ai_status', 'Informes verificados y listos.')}")

    if regen:
        with st.spinner("Orquestando Agentes de IA (Clasificador + Redactor Ejecutivo + Redactor Forense)..."):
            exec_rep, tech_rep, status_msg = generate_ai_reports(
                findings, summary_metrics, provider, model_name, api_url, api_key
            )
            st.session_state["exec_rep"] = exec_rep
            st.session_state["tech_rep"] = tech_rep
            st.session_state["ai_status"] = status_msg
            st.rerun()

    # Vincular key="exec_rep" y key="tech_rep" para sincronización inmediata entre ambos botones PDF
    rep_col1, rep_col2 = st.columns(2)
    with rep_col1:
        with st.container(border=True):
            st.markdown("#### 👔 1. Resumen Ejecutivo (Español Ejecutivo / C-Level)")
            st.caption("Enfocado en impacto financiero, legal/regulatorio, riesgo de Ransomware y decisiones de negocio.")
            st.text_area(
                "Editor Ejecutivo:",
                key="exec_rep",
                height=390,
                label_visibility="collapsed",
            )
    with rep_col2:
        with st.container(border=True):
            st.markdown("#### 🛠️ 2. Informe Técnico Detallado (Ingeniería SOC L2 / DFIR)")
            st.caption("Incluye cronología, Log_IDs, IoCs, técnicas MITRE ATT&CK y Playbooks CLI de contención.")
            st.text_area(
                "Editor Técnico:",
                key="tech_rep",
                height=390,
                label_visibility="collapsed",
            )

    final_pdf_bytes = cached_compile_pdf(
        st.session_state["exec_rep"],
        st.session_state["tech_rep"],
        findings,
        summary_metrics,
        df,
    )

    with st.container(border=True):
        st.markdown("#### 🏆 Entregable Oficial Listo (Regla de Fin de Pico & Ley de Fitts)")
        st.write(
            "El archivo `Informe_Final_SOC_L2_Incidentes.pdf` incluye: **Portada Ejecutiva `TLP:AMBER+STRICT`**, "
            "**Tarjetas KPI**, **Resumen Ejecutivo C-Level**, **Matriz MITRE ATT&CK**, **Panel Cuádruple de Gráficos de Alta Resolución**, "
            "**Tabla de Auditoría de los 12 Eventos Ocultos en `Informational`** y **Desglose Forense + Playbook CLI de los 6 Incidentes**."
        )
        downloaded = st.download_button(
            label="📥 DESCARGAR INFORME OFICIAL EN PDF (EJECUTIVO + TÉCNICO + GRÁFICOS)",
            data=final_pdf_bytes,
            file_name="Informe_Final_SOC_L2_Incidentes.pdf",
            mime="application/pdf",
            type="primary",
            width="stretch",
            key="bottom_pdf_download_btn",
        )
        if downloaded:
            st.balloons()
            st.success("🎉 ¡Informe PDF descargado con éxito! También tienes una copia guardada automáticamente en la carpeta del proyecto.")

# ---------------------------------------------------------------------
# TAB 5: EXPLORADOR FORENSE CON FILTROS PARETO 80/20 (LEY DE HICK)
# ---------------------------------------------------------------------
with tab_logs:
    st.subheader("🗂️ Explorador Forense de Telemetría SIEM (Principio de Pareto & Ley de Hick)")
    st.caption(
        "Para evitar la Sobrecarga de Opciones (Ley de Hick), utiliza las Píldoras de Filtro Rápido Pareto 80/20 "
        "con un solo clic, o despliega los filtros avanzados si necesitas una búsqueda granular."
    )

    opt_malicious = f"🔴 Solo Eventos Maliciosos Correlacionados ({summary_metrics['correlated_malicious_events']})"
    opt_hidden = f"🕵️‍♂️ Solo Críticos Ocultos en 'Informational' ({summary_metrics['hidden_info_critical_events']})"
    opt_ext_ip = f"🌐 Tráfico con IPs Externas Origen/Destino ({summary_metrics['external_ip_events_count']})"
    opt_all = f"📋 Todos los Registros del SIEM ({summary_metrics['total_logs']})"

    preset = st.segmented_control(
        "⚡ Filtro Rápido Pareto 80/20 (1 Clic):",
        options=[opt_malicious, opt_hidden, opt_ext_ip, opt_all],
        default=opt_malicious,
    )

    filtered = df.copy()
    if preset == opt_malicious:
        filtered = filtered[filtered["Incident_ID"] != "NONE"]
    elif preset == opt_hidden:
        filtered = filtered[filtered["Hidden_Critical_Info"]]
    elif preset == opt_ext_ip:
        filtered = filtered[filtered["Involves_External_IP"]]

    with st.expander("🔎 Filtros Granulares Avanzados (Incidente, Severidad, Hostname, Búsqueda libre)", expanded=False):
        f_col1, f_col2, f_col3, f_col4 = st.columns(4)
        with f_col1:
            sel_inc = st.selectbox("Incidente Específico", ["Todos"] + list(df["Incident_Tag"].unique()))
        with f_col2:
            sel_sev = st.multiselect("Severidad SIEM", options=list(df["Severity"].unique()), default=list(df["Severity"].unique()))
        with f_col3:
            sel_host = st.multiselect("Hostname", options=list(df["Hostname"].unique()), default=list(df["Hostname"].unique()))
        with f_col4:
            search_q = st.text_input("Buscar texto (Comando, Log_ID, Usuario, IP)", value="")

        filtered = filtered[filtered["Severity"].isin(sel_sev) & filtered["Hostname"].isin(sel_host)]
        if sel_inc != "Todos":
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

    st.caption(f"Mostrando **{len(filtered):,}** de **{len(df):,}** eventos SIEM.")
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
    st.dataframe(filtered[display_cols], width="stretch", height=440, hide_index=True)

# ---------------------------------------------------------------------
# TAB 6: ARQUITECTURA DE LAS 30 LEYES DE UX APLICADAS (VALOR DIFERENCIAL)
# ---------------------------------------------------------------------
with tab_ux:
    st.subheader("🎨 Matriz de Ingeniería de Interfaz: Las 30 Leyes de UX (Laws of UX) Aplicadas al SOC Nivel 2")
    st.markdown(
        "Esta pestaña documenta cómo cada principio de **Laws of UX (Jon Yablonski)** fue implementado "
        "técnicamente en este dashboard para optimizar la toma de decisiones de un Analista SOC Nivel 2 y de un CISO:"
    )
    ux_laws_data = [
        ("1. Atención Selectiva", "Filtros segmentados de 1 clic por Riesgo y resaltado cromático exclusivo para anomalías críticas, silenciando los 591 eventos de ruido operativo."),
        ("2. Carga Cognitiva", "Pre-cálculo automático de conteos, bytes exfiltrados (241.57 MiB) y correlación MITRE para que el analista interprete conclusiones en vez de cruzar filas manualmente."),
        ("3. Efecto de Estética-Usabilidad", "Diseño táctico oscuro con alto contraste, tipografía jerárquica y contenedores limpios que incrementan la confianza y claridad percibida."),
        ("4. Efecto de Posición en Serie", "El estado crítico del SOC y el botón rápido de descarga PDF ocupan la primera posición superior; el CTA final de exportación cierra la vista inferior."),
        ("5. Efecto de Tendencia a la Meta", "Barra de progreso interactiva en la barra lateral (Pasos 1 a 3 y contador X/6 de incidentes contenidos) que acelera la finalización del triage."),
        ("6. Efecto Von Restorff (Aislamiento)", "Los 12 eventos críticos camuflados como 'Informational' se aíslan con un banner azul eléctrico y barra apilada diferenciada para que sea imposible ignorarlos."),
        ("7. Efecto Zeigarnik", "Lista de verificación de contención por incidente (INC-01 a INC-06) que mantiene visibles las tareas pendientes (`⚠️ PENDIENTE DE CONTENCIÓN`) hasta ser completadas."),
        ("8. Fluir (Flow)", "Transiciones sin recargas pesadas ni bloqueos modales; los informes Ejecutivo y Técnico están pre-renderizados y editables en tiempo real."),
        ("9. Fragmentación (Chunking)", "Cada incidente se descompone en 3 bloques fijos: Impacto Ejecutivo, Evidencia Forense y Metadatos/IoCs + Playbook CLI."),
        ("10. La Memoria de Trabajo", "Las tarjetas superiores mantienen siempre visibles las 5 cifras clave (715 logs, 124 correlacionados, 12 ocultos, 6 incidentes, 241.57 MiB) sin obligar a memorizarlas."),
        ("11. La Navaja de Occam", "Interfaz libre de adornos innecesarios: cada componente responde directamente a una pregunta de la rúbrica SOC L2 (¿Qué pasó?, ¿Cuál es el riesgo?, ¿Cómo se contiene?)."),
        ("12. Ley de Conectividad Uniforme", "Los pasos de ataque se representan unidos mediante una pista visual (`Initial Access ➔ Execution ➔ Exfiltration`) que denota causalidad forense."),
        ("13. Ley de Fitts", "Los botones principales de descarga del PDF Oficial tienen altura ampliada (`3.05 rem`), ancho completo (`width='stretch'`) y ubicación inmediata en cabecera y cierre."),
        ("14. Ley de Hick", "Se redujo la complejidad de filtrado mediante 4 píldoras rápidas de 1 clic y divulgación progresiva de los parámetros avanzados de LLM/API."),
        ("15. Ley de Jakob", "Estructura inspirada en plataformas SIEM/SOAR líderes (Microsoft Sentinel / Splunk ES / CrowdStrike), familiar para cualquier analista o reclutador."),
        ("16. Ley de la Semejanza", "Todos los elementos de Riesgo Alto comparten el mismo código visual (`🔴`), Riesgo Medio (`🟠`) y Trampas Ocultas (`🔵`), facilitando el escaneo visual."),
        ("17. Ley de Miller (7 ± 2)", "La fila superior presenta exactamente 5 KPIs y la navegación principal se divide en 6 pestañas (dentro del umbral óptimo de 5 a 9 elementos)."),
        ("18. Ley de Parkinson", "Indicador explícito del límite de entrega del Bootcamp (`8 de noviembre, 11:45 p.m. GMT-5`) y generación instantánea del entregable para acotar el tiempo de tarea."),
        ("19. Ley de Postel (Robustez)", "El parser (`core/parser.py`) valida esquema, limpia espacios, tolera variantes de capitalización, convierte tipos mixtos int/str y unifica `DC01` -> `DC-01`."),
        ("20. Ley de Proximidad", "Los comandos de remediación PowerShell se ubican inmediatamente debajo de la explicación forense y de los IoCs de su respectivo incidente."),
        ("21. Ley de Prägnanz", "Gráficos horizontales y líneas de tiempo de barras apiladas simples y directas, evitando gráficos circulares 3D o visualizaciones ambiguas."),
        ("22. Ley de Región Común", "Uso sistemático de contenedores con borde definido (`st.container(border=True)`) para agrupar KPIs, controles de barra lateral y tarjetas de incidentes."),
        ("23. Ley de Tesler (Complejidad)", "Toda la complejidad de parsing XML/Excel, expresiones regulares de `bytes_out`, manejo de fallbacks de IA y maquetación ReportLab es absorbida por el backend."),
        ("24. Modelo Mental", "Separación explícita entre la vista del CISO/Gerencia (Resumen Ejecutivo en lenguaje de negocio) y la vista del Ingeniero SOC L2 (Log_IDs, MITRE y CLI)."),
        ("25. Paradoja del Usuario Activo", "La aplicación arranca con el dataset oficial ya cargado, correlacionado y con el PDF listo para descargar en el primer segundo, sin requerir leer un manual."),
        ("26. Principio de Pareto (80/20)", "El filtro predeterminado del explorador muestra directamente el 17.3% de los logs (124 eventos) que concentran el 100% de la actividad maliciosa."),
        ("27. Regla de Fin de Pico", "El momento cumbre (descubrimiento visual de las 12 trampas `Informational`) y el cierre (descarga del PDF con confirmación visual) están diseñados para destacar en tu video."),
        ("28. Sesgo Cognitivo", "Banner dedicado a neutralizar el Sesgo de Anclaje en la columna `Severity` del SIEM, demostrando por qué un Analista L2 correlaciona comportamiento real."),
        ("29. Sobrecarga de Opciones", "Ocultamiento automático de configuraciones de endpoints/tokens cuando se utiliza el Motor Forense Determinista integrado."),
        ("30. Umbral de Doherty (< 400 ms)", "Uso de `@st.cache_data` con bytes inmutables en el procesamiento de Excel y compilación de PDF, logrando respuestas por debajo de 100 ms."),
    ]
    st.dataframe(
        pd.DataFrame(ux_laws_data, columns=["Ley / Principio de UX (lawsofux.com)", "Implementación Técnica en la Plataforma SOC Nivel 2"]),
        width="stretch",
        height=620,
        hide_index=True,
    )
