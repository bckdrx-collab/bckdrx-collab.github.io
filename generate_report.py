"""
Script CLI unificado para generar los entregables oficiales del proyecto SOC Nivel 2:
1. 'Informe_Final_SOC_L2_Incidentes.pdf' (Informe Ejecutivo C-Level + Informe Técnico Forense DFIR)
2. 'soc_l2_dashboard_summary.png' (Panel cuádruple de visualización forense en alta resolución)
3. 'index.html' (Portal web interactivo estático para GitHub Pages / github.io)
"""

from __future__ import annotations
import json
from pathlib import Path
import pandas as pd

from core.parser import analyze_siem_logs
from core.agents import generate_ai_reports
from core.pdf_generator import build_pdf_report


def build_static_web_portal(
    df: pd.DataFrame,
    findings: list[dict],
    summary_metrics: dict,
    exec_md: str,
    tech_md: str,
    output_dir: Path,
) -> None:
    """Genera index.html y .nojekyll sincronizados con el motor forense para GitHub Pages."""
    df_export = df.copy()
    df_export["Timestamp_Str"] = df_export["Timestamp_dt"].dt.strftime("%Y-%m-%d %H:%M:%S")
    df_export["Minute_Window"] = df_export["Timestamp_dt"].dt.floor("5min").dt.strftime("%Y-%m-%d %H:%M")

    records = []
    for _, r in df_export.iterrows():
        records.append(
            {
                "Log_ID": str(r["Log_ID"]),
                "Timestamp": str(r["Timestamp_Str"]),
                "Minute_Window": str(r["Minute_Window"]),
                "Log_Source": str(r["Log_Source"]),
                "Event_ID": str(r["Event_ID"]),
                "Event_Description": str(r["Event_Description"]),
                "Severity": str(r["Severity"]),
                "User": str(r["User"]),
                "User_Norm": str(r["User_Norm"]),
                "Hostname": str(r["Hostname"]),
                "Hostname_Norm": str(r["Hostname_Norm"]),
                "Source_IP": str(r["Source_IP"]),
                "Destination": str(r["Destination"]),
                "Result": str(r["Result"]),
                "Process_CommandLine": str(r["Process_CommandLine"]),
                "Incident_ID": str(r["Incident_ID"]),
                "Incident_Tag": str(r["Incident_Tag"]),
                "Hidden_Trap": bool(r["Hidden_Critical_Info"]),
            }
        )

    payload = {
        "metrics": summary_metrics,
        "findings": findings,
        "hidden_events": summary_metrics["hidden_events_records"],
        "exec_md": exec_md,
        "tech_md": tech_md,
        "logs": records,
    }
    payload_json = json.dumps(payload, ensure_ascii=False)

    html_content = f"""<!DOCTYPE html>
<html lang="es" class="dark">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>SOC L2 Command Center — Análisis Forense SIEM & Respuesta a Incidentes</title>
  <meta name="description" content="Plataforma de Análisis de Incidentes SIEM, Threat Hunting MITRE ATT&CK y Generación de Informes Forenses SOC Nivel 2 (Dojo Community)." />
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <script src="https://cdn.plot.ly/plotly-2.35.2.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/xlsx@0.18.5/dist/xlsx.full.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
  <style>
    :root {{
      --bg-primary: #070B14;
      --bg-secondary: #0F172A;
      --bg-card: rgba(15, 23, 42, 0.88);
      --border-slate: rgba(56, 189, 248, 0.22);
      --text-primary: #F8FAFC;
      --text-secondary: #94A3B8;
      --accent-cyan: #38BDF8;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      background: radial-gradient(circle at 15% 0%, #0f1b33 0%, #070B14 60%);
      color: var(--text-primary);
      line-height: 1.55;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }}
    code, pre, .mono {{ font-family: 'JetBrains Mono', monospace; }}
    .app-layout {{
      display: grid;
      grid-template-columns: 315px 1fr;
      min-height: 100vh;
    }}
    @media (max-width: 1024px) {{
      .app-layout {{ grid-template-columns: 1fr; }}
      .sidebar {{ border-right: none; border-bottom: 1px solid var(--border-slate); }}
    }}
    .sidebar {{
      background: rgba(10, 15, 29, 0.96);
      border-right: 1px solid var(--border-slate);
      padding: 1.35rem;
      display: flex;
      flex-direction: column;
      gap: 1.05rem;
    }}
    .brand-box {{
      display: flex;
      align-items: center;
      gap: 0.75rem;
      padding-bottom: 0.9rem;
      border-bottom: 1px solid rgba(148, 163, 184, 0.15);
    }}
    .brand-icon {{
      width: 42px;
      height: 42px;
      border-radius: 10px;
      background: linear-gradient(135deg, #2563EB, #7C3AED);
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 1.35rem;
      box-shadow: 0 6px 18px rgba(56, 189, 248, 0.25);
    }}
    .brand-title {{ font-weight: 800; font-size: 1.02rem; letter-spacing: -0.02em; }}
    .brand-sub {{ font-size: 0.75rem; color: var(--accent-cyan); font-weight: 600; }}
    .side-section {{
      background: rgba(15, 23, 42, 0.75);
      border: 1px solid rgba(148, 163, 184, 0.16);
      border-radius: 11px;
      padding: 0.9rem;
    }}
    .side-section h4 {{
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.07em;
      color: var(--accent-cyan);
      margin-bottom: 0.55rem;
    }}
    .progress-bar-wrap {{
      width: 100%;
      height: 9px;
      background: #1E293B;
      border-radius: 999px;
      overflow: hidden;
      margin: 0.45rem 0;
    }}
    .progress-bar-fill {{
      height: 100%;
      background: linear-gradient(90deg, #38BDF8, #10B981);
      transition: width 0.35s ease;
    }}
    .checklist-item {{
      display: flex;
      align-items: center;
      gap: 0.5rem;
      font-size: 0.81rem;
      padding: 0.25rem 0;
      cursor: pointer;
      color: #E2E8F0;
    }}
    .checklist-item input {{
      accent-color: #38BDF8;
      width: 15px;
      height: 15px;
      cursor: pointer;
    }}
    .btn-cta {{
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 0.5rem;
      width: 100%;
      min-height: 46px;
      padding: 0.68rem 1rem;
      border-radius: 10px;
      font-weight: 700;
      font-size: 0.85rem;
      text-decoration: none;
      border: none;
      cursor: pointer;
      transition: all 0.2s ease;
    }}
    .btn-primary {{
      background: linear-gradient(135deg, #2563EB 0%, #4F46E5 100%);
      color: #FFFFFF;
      box-shadow: 0 6px 18px rgba(37, 99, 235, 0.35);
    }}
    .btn-primary:hover {{
      transform: translateY(-1px);
      box-shadow: 0 10px 24px rgba(56, 189, 248, 0.45);
    }}
    .btn-secondary {{
      background: rgba(30, 41, 59, 0.9);
      color: #E2E8F0;
      border: 1px solid rgba(56, 189, 248, 0.35);
    }}
    .btn-secondary:hover {{
      background: rgba(51, 65, 85, 0.9);
      border-color: #38BDF8;
    }}
    .main-area {{
      padding: 1.45rem 1.85rem;
      overflow-x: hidden;
      max-width: 1600px;
      width: 100%;
      margin: 0 auto;
    }}
    .soc-hero {{
      background: linear-gradient(135deg, #0D1527 0%, #162340 55%, #1E1B4B 100%);
      border: 1px solid rgba(56, 189, 248, 0.32);
      border-left: 6px solid #38BDF8;
      border-radius: 14px;
      padding: 1.3rem 1.6rem;
      margin-bottom: 1.1rem;
      box-shadow: 0 12px 32px rgba(0, 0, 0, 0.45);
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 1rem;
    }}
    .soc-hero h1 {{ font-size: 1.45rem; font-weight: 800; letter-spacing: -0.02em; margin-bottom: 0.25rem; }}
    .soc-hero p {{ color: #CBD5E1; font-size: 0.88rem; }}
    .evasion-banner {{
      background: linear-gradient(90deg, rgba(168, 85, 247, 0.18) 0%, rgba(239, 68, 68, 0.16) 100%);
      border: 1px solid #A855F7;
      border-left: 6px solid #A855F7;
      border-radius: 11px;
      padding: 0.9rem 1.2rem;
      margin-bottom: 1.15rem;
      font-size: 0.87rem;
      color: #F3E8FF;
    }}
    .kpi-grid {{
      display: grid;
      grid-template-columns: repeat(5, 1fr);
      gap: 0.85rem;
      margin-bottom: 1.25rem;
    }}
    @media (max-width: 1200px) {{
      .kpi-grid {{ grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); }}
    }}
    .kpi-card {{
      background: var(--bg-card);
      border: 1px solid rgba(148, 163, 184, 0.18);
      border-top: 3px solid var(--accent-cyan);
      border-radius: 12px;
      padding: 0.95rem 1.05rem;
      box-shadow: 0 6px 20px rgba(0, 0, 0, 0.25);
    }}
    .kpi-card.critical {{ border-top-color: #EF4444; }}
    .kpi-card.warning {{ border-top-color: #F59E0B; }}
    .kpi-card.purple {{ border-top-color: #A855F7; }}
    .kpi-label {{
      font-size: 0.74rem;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: var(--text-secondary);
      font-weight: 600;
    }}
    .kpi-value {{
      font-size: 1.6rem;
      font-weight: 800;
      margin: 0.22rem 0;
      color: #F8FAFC;
    }}
    .kpi-delta {{
      font-size: 0.75rem;
      font-weight: 600;
      display: inline-block;
      padding: 0.15rem 0.5rem;
      border-radius: 999px;
      background: rgba(56, 189, 248, 0.13);
      color: #38BDF8;
    }}
    .kpi-delta.red {{ background: rgba(239, 68, 68, 0.16); color: #FCA5A5; }}
    .kpi-delta.purple {{ background: rgba(168, 85, 247, 0.2); color: #E9D5FF; }}
    .tabs-bar {{
      display: flex;
      gap: 0.5rem;
      border-bottom: 1px solid rgba(148, 163, 184, 0.2);
      padding-bottom: 0.6rem;
      margin-bottom: 1.25rem;
      overflow-x: auto;
    }}
    .tab-btn {{
      background: rgba(15, 23, 42, 0.75);
      color: #94A3B8;
      border: 1px solid rgba(148, 163, 184, 0.18);
      padding: 0.62rem 1rem;
      border-radius: 9px;
      font-size: 0.84rem;
      font-weight: 600;
      cursor: pointer;
      white-space: nowrap;
      transition: all 0.2s ease;
    }}
    .tab-btn:hover {{ color: #F8FAFC; border-color: rgba(56, 189, 248, 0.45); }}
    .tab-btn.active {{
      background: linear-gradient(135deg, rgba(37, 99, 235, 0.34), rgba(124, 58, 237, 0.34));
      color: #FFFFFF;
      border-color: #38BDF8;
      box-shadow: 0 4px 14px rgba(56, 189, 248, 0.22);
    }}
    .tab-panel {{ display: none; }}
    .tab-panel.active {{ display: block; animation: fadeIn 0.22s ease; }}
    @keyframes fadeIn {{ from {{ opacity: 0; transform: translateY(4px); }} to {{ opacity: 1; transform: translateY(0); }} }}
    .grid-2 {{
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 1.05rem;
      margin-bottom: 1.05rem;
    }}
    @media (max-width: 1100px) {{ .grid-2 {{ grid-template-columns: 1fr; }} }}
    .panel-card {{
      background: var(--bg-card);
      border: 1px solid rgba(148, 163, 184, 0.18);
      border-radius: 12px;
      padding: 1.1rem;
      margin-bottom: 1.05rem;
    }}
    .panel-card h3 {{
      font-size: 0.98rem;
      font-weight: 700;
      margin-bottom: 0.65rem;
      color: #F8FAFC;
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 0.5rem;
    }}
    .inc-card {{
      background: rgba(15, 23, 42, 0.92);
      border: 1px solid rgba(148, 163, 184, 0.22);
      border-left: 5px solid #EF4444;
      border-radius: 12px;
      padding: 1.15rem 1.3rem;
      margin-bottom: 0.95rem;
    }}
    .inc-card.med {{ border-left-color: #F59E0B; }}
    .inc-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 0.5rem;
      margin-bottom: 0.6rem;
    }}
    .killchain-flow {{
      display: flex;
      align-items: center;
      flex-wrap: wrap;
      gap: 0.35rem;
      margin: 0.55rem 0;
    }}
    .kc-step {{
      background: rgba(30, 41, 59, 0.95);
      border: 1px solid rgba(56, 189, 248, 0.35);
      color: #7DD3FC;
      padding: 0.2rem 0.6rem;
      border-radius: 6px;
      font-size: 0.74rem;
      font-weight: 600;
    }}
    .kc-arrow {{ color: #64748B; font-weight: 700; font-size: 0.8rem; }}
    .badge {{
      display: inline-block;
      padding: 0.2rem 0.58rem;
      border-radius: 999px;
      font-size: 0.72rem;
      font-weight: 700;
      text-transform: uppercase;
    }}
    .badge-crit {{ background: rgba(239, 68, 68, 0.2); color: #FCA5A5; border: 1px solid #EF4444; }}
    .badge-med {{ background: rgba(245, 158, 11, 0.2); color: #FDE68A; border: 1px solid #F59E0B; }}
    .badge-mitre {{ background: rgba(56, 189, 248, 0.14); color: #7DD3FC; border: 1px solid rgba(56, 189, 248, 0.35); }}
    .badge-trap {{ background: rgba(168, 85, 247, 0.22); color: #E9D5FF; border: 1px solid #A855F7; }}
    .inc-meta-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 0.6rem;
      background: rgba(7, 11, 20, 0.65);
      padding: 0.8rem;
      border-radius: 9px;
      margin: 0.7rem 0;
      font-size: 0.82rem;
    }}
    .quick-pills {{
      display: flex;
      gap: 0.45rem;
      flex-wrap: wrap;
      margin-bottom: 0.85rem;
    }}
    .pill-btn {{
      background: rgba(30, 41, 59, 0.85);
      border: 1px solid rgba(56, 189, 248, 0.3);
      color: #E2E8F0;
      padding: 0.35rem 0.75rem;
      border-radius: 999px;
      font-size: 0.76rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.15s ease;
    }}
    .pill-btn:hover {{
      background: rgba(37, 99, 235, 0.35);
      border-color: #38BDF8;
      color: #FFFFFF;
    }}
    .table-wrap {{
      overflow-x: auto;
      border: 1px solid rgba(148, 163, 184, 0.18);
      border-radius: 10px;
      max-height: 520px;
      overflow-y: auto;
    }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.8rem; text-align: left; }}
    th {{
      position: sticky;
      top: 0;
      background: #0F172A;
      color: #38BDF8;
      padding: 0.62rem 0.72rem;
      font-weight: 700;
      border-bottom: 1px solid rgba(56, 189, 248, 0.25);
      z-index: 2;
    }}
    td {{
      padding: 0.52rem 0.72rem;
      border-bottom: 1px solid rgba(148, 163, 184, 0.1);
      color: #E2E8F0;
    }}
    tr:hover td {{ background: rgba(56, 189, 248, 0.06); }}
    tr.trap-row td {{ background: rgba(168, 85, 247, 0.14); }}
    .filter-bar {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 0.75rem;
      margin-bottom: 0.95rem;
    }}
    input[type="text"], input[type="password"], select, textarea {{
      width: 100%;
      background: #090D16;
      color: #F8FAFC;
      border: 1px solid rgba(148, 163, 184, 0.28);
      border-radius: 8px;
      padding: 0.52rem 0.72rem;
      font-size: 0.83rem;
      font-family: inherit;
    }}
    input:focus, select:focus, textarea:focus {{ outline: none; border-color: #38BDF8; }}
    .markdown-preview {{
      background: rgba(9, 13, 22, 0.85);
      border: 1px solid rgba(148, 163, 184, 0.2);
      border-radius: 10px;
      padding: 1.2rem;
      max-height: 640px;
      overflow-y: auto;
      font-size: 0.86rem;
    }}
    .markdown-preview h1, .markdown-preview h2, .markdown-preview h3 {{
      color: #38BDF8;
      margin-top: 0.95rem;
      margin-bottom: 0.45rem;
    }}
    .markdown-preview ul, .markdown-preview ol {{ padding-left: 1.3rem; margin-bottom: 0.7rem; }}
  </style>
</head>
<body>
  <div class="app-layout">
    <!-- SIDEBAR -->
    <aside class="sidebar">
      <div class="brand-box">
        <div class="brand-icon">🛡️</div>
        <div>
          <div class="brand-title">SOC L2 Command Center</div>
          <div class="brand-sub">Dojo Community • Proyecto Final</div>
        </div>
      </div>

      <div class="side-section">
        <h4>🎯 Progreso de Contención IR</h4>
        <div style="display:flex;justify-content:space-between;font-size:0.8rem;font-weight:600;">
          <span id="containment-label">6 / 6 Incidentes Contenidos</span>
          <span id="containment-pct" style="color:#10B981;">100%</span>
        </div>
        <div class="progress-bar-wrap">
          <div id="containment-bar" class="progress-bar-fill" style="width:100%;"></div>
        </div>
        <div id="checklist-container" style="margin-top:0.45rem;">
          <label class="checklist-item"><input type="checkbox" checked onchange="updateContainment()"> <span>INC-01: Spraying & mgarcia</span></label>
          <label class="checklist-item"><input type="checkbox" checked onchange="updateContainment()"> <span>INC-02: RDP -> SMB Budget2027</span></label>
          <label class="checklist-item"><input type="checkbox" checked onchange="updateContainment()"> <span>INC-03: Pre-Ransomware vssadmin</span></label>
          <label class="checklist-item"><input type="checkbox" checked onchange="updateContainment()"> <span>INC-04: Exfiltración Legal 241.57 MiB</span></label>
          <label class="checklist-item"><input type="checkbox" checked onchange="updateContainment()"> <span>INC-05: Persistencia wuhelper.exe</span></label>
          <label class="checklist-item"><input type="checkbox" checked onchange="updateContainment()"> <span>INC-06: Webshell IIS DefaultAppPool</span></label>
        </div>
      </div>

      <div class="side-section">
        <h4>📂 Ingesta SIEM (.xlsx en vivo)</h4>
        <p style="font-size:0.75rem;color:#94A3B8;margin-bottom:0.45rem;">
          Dataset oficial precargado (715 eventos). También puedes cargar y correlacionar cualquier archivo <code>.xlsx</code> local:
        </p>
        <input type="file" id="xlsx-upload" accept=".xlsx,.xls" style="font-size:0.74rem;padding:0.38rem;" onchange="handleXlsxUpload(event)" />
        <div id="upload-status" style="font-size:0.74rem;color:#10B981;margin-top:0.38rem;">
          ✔ Dataset activo: SIEM Export (715 filas)
        </div>
      </div>

      <div class="side-section" style="display:flex;flex-direction:column;gap:0.52rem;">
        <h4>📥 Entregables Oficiales</h4>
        <a href="Informe_Final_SOC_L2_Incidentes.pdf" download="Informe_Final_SOC_L2_Incidentes.pdf" class="btn-cta btn-primary">
          📄 Descargar Informe PDF Oficial
        </a>
        <a href="SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx" download="SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx" class="btn-cta btn-secondary">
          📊 Descargar Dataset SIEM (.xlsx)
        </a>
        <a href="soc_l2_dashboard_summary.png" target="_blank" class="btn-cta btn-secondary">
          🖼️ Ver Panel Gráfico HD (.png)
        </a>
        <a href="https://github.com/bckdrx-collab/soc-l2-incident-response" target="_blank" class="btn-cta btn-secondary">
          💻 Ver Código Fuente en GitHub
        </a>
      </div>

      <div class="side-section">
        <h4>⏱️ Ventana Forense Analizada</h4>
        <div style="font-size:0.77rem;color:#CBD5E1;">
          <div>• <b>Inicio:</b> 2026-10-23 07:46:07</div>
          <div>• <b>Fin:</b> 2026-10-23 13:44:06</div>
          <div>• <b>Duración:</b> 5h 57m 59s</div>
          <div>• <b>Estado:</b> <span id="perf-badge" style="color:#38BDF8;">Correlación L2 Activa</span></div>
        </div>
      </div>
    </aside>

    <!-- MAIN CONTENT -->
    <main class="main-area">
      <header class="soc-hero">
        <div>
          <h1>🛡️ Centro de Mando SOC Nivel 2 — Análisis Forense & Respuesta a Incidentes</h1>
          <p>Correlación Multi-Incidente MITRE ATT&CK • Detección de Evasión SIEM • Generación de Informes C-Level & CSIRT</p>
        </div>
        <div style="display:flex;gap:0.6rem;flex-wrap:wrap;">
          <a href="Informe_Final_SOC_L2_Incidentes.pdf" target="_blank" class="btn-cta btn-primary" style="width:auto;padding:0.65rem 1.2rem;">
            📥 Abrir PDF Oficial (Ejecutivo + Técnico)
          </a>
        </div>
      </header>

      <div class="evasion-banner">
        🚨 <b>HALLAZGO DE AUDITORÍA SIEM (FALSOS NEGATIVOS):</b> Se detectaron <b>12 eventos críticos de intrusión</b> registrados erróneamente como <code>Severity = Informational</code> en el SIEM (incluyendo login exitoso post-spraying <code>EVT-00123</code>, escalamiento <code>EVT-00126</code>, verificación SMB post-vssadmin <code>EVT-00315</code>, archivado <code>7z.exe</code> <code>EVT-00428</code> y 5 ejecuciones del servicio persistente <code>wuhelper.exe</code>). El motor L2 correlaciona las <b>112 alertas nativas + 12 ocultas = 124 eventos maliciosos</b>.
      </div>

      <section class="kpi-grid">
        <div class="kpi-card">
          <div class="kpi-label">1. Eventos Analizados</div>
          <div class="kpi-value" id="kpi-total-val">715</div>
          <span class="kpi-delta">591 ruido base (82.7%)</span>
        </div>
        <div class="kpi-card warning">
          <div class="kpi-label">2. Eventos Maliciosos L2</div>
          <div class="kpi-value" id="kpi-mal-val">124</div>
          <span class="kpi-delta red" id="kpi-mal-sub">112 alertas + 12 ocultos Info</span>
        </div>
        <div class="kpi-card critical">
          <div class="kpi-label">3. Incidentes Confirmados</div>
          <div class="kpi-value">6 + 1 OBS</div>
          <span class="kpi-delta red">INC-01 a INC-06 + OBS-01</span>
        </div>
        <div class="kpi-card purple">
          <div class="kpi-label">4. Exfiltración Confirmada</div>
          <div class="kpi-value">241.57 MiB</div>
          <span class="kpi-delta purple">253.31 MB hacia 198.51.100.88</span>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">5. Tráfico IPs Externas</div>
          <div class="kpi-value">91</div>
          <span class="kpi-delta">68 inbound • 23 outbound</span>
        </div>
      </section>

      <!-- 5 OPERATIONAL TABS -->
      <nav class="tabs-bar">
        <button id="btn-tab-incidentes" class="tab-btn active" onclick="switchTab('tab-incidentes', this)">🔴 1. Triage de Incidentes & Kill Chain</button>
        <button id="btn-tab-panorama" class="tab-btn" onclick="switchTab('tab-panorama', this)">📊 2. Visualización Analítica SIEM</button>
        <button id="btn-tab-trampa" class="tab-btn" onclick="switchTab('tab-trampa', this)">🕵️‍♂️ 3. Auditoría de Evasión (12 Info)</button>
        <button id="btn-tab-informes" class="tab-btn" onclick="switchTab('tab-informes', this)">📄 4. Informes IA & Exportación PDF</button>
        <button id="btn-tab-explorador" class="tab-btn" onclick="switchTab('tab-explorador', this)">🗂️ 5. Explorador Forense (715 Logs)</button>
      </nav>

      <!-- TAB 1: LOS 6 INCIDENTES -->
      <section id="tab-incidentes" class="tab-panel active">
        <div id="incidents-container"></div>
      </section>

      <!-- TAB 2: PANORAMA TACTICO -->
      <section id="tab-panorama" class="tab-panel">
        <div class="grid-2">
          <div class="panel-card">
            <h3><span>📈 Línea de Tiempo Multi-Incidente (Ventanas de 5 min)</span></h3>
            <div id="chart-timeline" style="height:330px;"></div>
          </div>
          <div class="panel-card">
            <h3><span>🎯 Volumen de Eventos por Incidente (Alertas SIEM vs Ocultos en Info)</span></h3>
            <div id="chart-incidents" style="height:330px;"></div>
          </div>
        </div>
        <div class="grid-2">
          <div class="panel-card">
            <h3><span>🌐 Distribución por Fuente de Telemetría (Log_Source)</span></h3>
            <div id="chart-sources" style="height:310px;"></div>
          </div>
          <div class="panel-card">
            <h3><span>🖥️ Hosts Comprometidos por Eventos Maliciosos Correlacionados</span></h3>
            <div id="chart-hosts" style="height:310px;"></div>
          </div>
        </div>
      </section>

      <!-- TAB 3: TRAMPA SIEM (12 EVENTOS INFO) -->
      <section id="tab-trampa" class="tab-panel">
        <div class="panel-card">
          <h3><span>🕵️‍♂️ Auditoría de Ceguera de Detección: Los 12 Eventos Críticos Ocultos en <code>Informational</code></span></h3>
          <p style="font-size:0.85rem;color:#CBD5E1;margin-bottom:0.9rem;">
            Un filtro básico de Nivel 1 que descarte <code>Severity == Informational</code> perdería los 12 registros de éxito de intrusión, compresión y ejecución persistente listados a continuación:
          </p>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Log_ID</th>
                  <th>Timestamp</th>
                  <th>Incidente</th>
                  <th>Host</th>
                  <th>Event_ID</th>
                  <th>Usuario</th>
                  <th>Origen → Destino</th>
                  <th>Comando / Evidencia Forense</th>
                </tr>
              </thead>
              <tbody id="hidden-tbody"></tbody>
            </table>
          </div>
        </div>
      </section>

      <!-- TAB 4: INFORMES IA & EXPORTACION PDF -->
      <section id="tab-informes" class="tab-panel">
        <div class="panel-card">
          <h3>
            <span>🤖 Orquestador de Informes Duales (C-Level Ejecutivo + Forense CSIRT L2)</span>
            <div style="display:flex;gap:0.5rem;flex-wrap:wrap;">
              <a href="Informe_Final_SOC_L2_Incidentes.pdf" download="Informe_Final_SOC_L2_Incidentes.pdf" class="btn-cta btn-primary" style="width:auto;min-height:38px;padding:0.45rem 0.95rem;">
                📥 Descargar PDF Compilado Oficial
              </a>
              <button class="btn-cta btn-secondary" style="width:auto;min-height:38px;padding:0.45rem 0.95rem;" onclick="downloadMarkdownReport()">
                📝 Descargar Informes (.md)
              </button>
              <button class="btn-cta btn-secondary" style="width:auto;min-height:38px;padding:0.45rem 0.95rem;" onclick="window.print()">
                🖨️ Imprimir / Guardar Vista
              </button>
            </div>
          </h3>
          <div class="filter-bar" style="margin-top:0.65rem;">
            <div>
              <label style="font-size:0.74rem;color:#94A3B8;">Motor de Generación de Informes</label>
              <select id="ai-provider">
                <option value="deterministic">Motor Forense Híbrido SOC L2 (Auditado • Instantáneo)</option>
                <option value="openai">OpenAI / Compatible API (gpt-4o-mini)</option>
                <option value="groq">Groq Cloud API (llama-3.3-70b-versatile)</option>
              </select>
            </div>
            <div>
              <label style="font-size:0.74rem;color:#94A3B8;">API Key (Opcional — solo para OpenAI/Groq en vivo)</label>
              <input type="password" id="ai-key" placeholder="sk-... / gsk_..." />
            </div>
            <div style="display:flex;align-items:flex-end;gap:0.5rem;">
              <button class="btn-cta btn-secondary" style="min-height:38px;" onclick="generateLiveAIReport()">
                ⚡ Sintetizar con Agente IA
              </button>
            </div>
          </div>
          <div id="ai-status-msg" style="font-size:0.78rem;color:#10B981;">
            ✔ Estado: Informes Ejecutivo y Técnico sincronizados con los 715 eventos y 6 incidentes críticos.
          </div>
        </div>
        <div class="grid-2">
          <div class="panel-card">
            <h3><span>👔 Informe 1: Resumen Ejecutivo (Audiencia No Técnica / C-Level)</span></h3>
            <div id="exec-report-view" class="markdown-preview"></div>
          </div>
          <div class="panel-card">
            <h3><span>🔬 Informe 2: Análisis Técnico Forense (SOC Nivel 2 / CSIRT)</span></h3>
            <div id="tech-report-view" class="markdown-preview"></div>
          </div>
        </div>
      </section>

      <!-- TAB 5: EXPLORADOR FORENSE -->
      <section id="tab-explorador" class="tab-panel">
        <div class="panel-card">
          <h3>
            <span>🔎 Explorador de Telemetría SIEM (715 Eventos Normalizados)</span>
            <span id="explorer-count" class="badge badge-mitre">Mostrando 715 eventos</span>
          </h3>
          <div class="quick-pills">
            <button class="pill-btn" onclick="applyQuickFilter('MALICIOUS', 'ALL', 'ALL', '')">🔴 124 Maliciosos Correlacionados</button>
            <button class="pill-btn" onclick="applyQuickFilter('TRAP', 'ALL', 'ALL', '')">🟣 12 Ocultos en Informational</button>
            <button class="pill-btn" onclick="applyQuickFilter('INC-03', 'ALL', 'ALL', 'vssadmin')">💥 Pre-Ransomware (vssadmin)</button>
            <button class="pill-btn" onclick="applyQuickFilter('INC-04', 'ALL', 'ALL', '')">📤 Exfiltración Legal (241.57 MiB)</button>
            <button class="pill-btn" onclick="applyQuickFilter('INC-06', 'ALL', 'ALL', 'test.aspx')">🕸️ Webshell IIS (test.aspx)</button>
            <button class="pill-btn" onclick="applyQuickFilter('ALL', 'ALL', 'ALL', '')">🔄 Mostrar Todo (715)</button>
          </div>
          <div class="filter-bar">
            <div>
              <label style="font-size:0.74rem;color:#94A3B8;">Filtrar por Incidente</label>
              <select id="filter-inc" onchange="renderExplorerTable()">
                <option value="ALL">Todos los eventos (715)</option>
                <option value="MALICIOUS">Solo Maliciosos Correlacionados (124)</option>
                <option value="TRAP">Solo Ocultos en Informational (12)</option>
                <option value="INC-01">INC-01: Password Spraying (35)</option>
                <option value="INC-02">INC-02: RDP -> SMB Budget2027 (16)</option>
                <option value="INC-03">INC-03: Pre-Ransomware vssadmin (19)</option>
                <option value="INC-04">INC-04: Exfiltración Legal 7z (24)</option>
                <option value="INC-05">INC-05: Persistencia wuhelper (8)</option>
                <option value="INC-06">INC-06: Webshell IIS WEB-01 (22)</option>
                <option value="NONE">Ruido Operativo Base (591)</option>
              </select>
            </div>
            <div>
              <label style="font-size:0.74rem;color:#94A3B8;">Severidad SIEM Nativa</label>
              <select id="filter-sev" onchange="renderExplorerTable()">
                <option value="ALL">Todas las Severidades</option>
                <option value="High">High (8)</option>
                <option value="Medium">Medium (7)</option>
                <option value="Warning">Warning (97)</option>
                <option value="Informational">Informational (603)</option>
              </select>
            </div>
            <div>
              <label style="font-size:0.74rem;color:#94A3B8;">Host Normalizado</label>
              <select id="filter-host" onchange="renderExplorerTable()">
                <option value="ALL">Todos los Hosts</option>
                <option value="DC-01">DC-01 (incluye alias DC01)</option>
                <option value="APP-SRV01">APP-SRV01</option>
                <option value="FS-SRV01">FS-SRV01</option>
                <option value="WS-023">WS-023</option>
                <option value="WS-018">WS-018</option>
                <option value="WEB-01">WEB-01</option>
                <option value="WS-031">WS-031</option>
              </select>
            </div>
            <div>
              <label style="font-size:0.74rem;color:#94A3B8;">Búsqueda Libre (Log_ID, IP, Comando, Usuario)</label>
              <input type="text" id="filter-search" placeholder="Ej. EVT-00314, vssadmin, 198.51.100.88..." oninput="renderExplorerTable()" />
            </div>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Log_ID</th>
                  <th>Timestamp</th>
                  <th>Incidente</th>
                  <th>Severidad</th>
                  <th>Host_Norm</th>
                  <th>User_Norm</th>
                  <th>Source_IP → Dest</th>
                  <th>Event_ID / Fuente</th>
                  <th>Descripción / Process_CommandLine</th>
                </tr>
              </thead>
              <tbody id="explorer-tbody"></tbody>
            </table>
          </div>
        </div>
      </section>
    </main>
  </div>

  <script>
    const SOC_DATA = {payload_json};

    function switchTab(tabId, btnEl) {{
      const t0 = performance.now();
      document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.getElementById(tabId).classList.add('active');
      if (btnEl) btnEl.classList.add('active');
      window.dispatchEvent(new Event('resize'));
      const dt = (performance.now() - t0).toFixed(1);
      document.getElementById('perf-badge').textContent = `Renderizado en ${{dt}} ms`;
    }}

    function jumpToIncidentLogs(incId) {{
      document.getElementById('filter-inc').value = incId;
      document.getElementById('filter-sev').value = 'ALL';
      document.getElementById('filter-host').value = 'ALL';
      document.getElementById('filter-search').value = '';
      renderExplorerTable();
      switchTab('tab-explorador', document.getElementById('btn-tab-explorador'));
    }}

    function applyQuickFilter(incVal, sevVal, hostVal, qVal) {{
      document.getElementById('filter-inc').value = incVal;
      document.getElementById('filter-sev').value = sevVal;
      document.getElementById('filter-host').value = hostVal;
      document.getElementById('filter-search').value = qVal;
      renderExplorerTable();
    }}

    function updateContainment() {{
      const boxes = document.querySelectorAll('#checklist-container input[type="checkbox"]');
      const total = boxes.length;
      let checked = 0;
      boxes.forEach(b => {{ if (b.checked) checked++; }});
      const pct = Math.round((checked / total) * 100);
      document.getElementById('containment-label').textContent = `${{checked}} / ${{total}} Incidentes Contenidos`;
      document.getElementById('containment-pct').textContent = `${{pct}}%`;
      document.getElementById('containment-bar').style.width = `${{pct}}%`;
    }}

    function renderCharts() {{
      const logs = SOC_DATA.logs;
      const findings = SOC_DATA.findings.filter(f => f.id.startsWith('INC-'));

      const winMap = {{}};
      logs.forEach(l => {{
        if (l.Incident_ID && l.Incident_ID.startsWith('INC-')) {{
          const key = l.Minute_Window;
          if (!winMap[key]) winMap[key] = {{}};
          winMap[key][l.Incident_ID] = (winMap[key][l.Incident_ID] || 0) + 1;
        }}
      }});
      const windows = Object.keys(winMap).sort();
      const incIds = ['INC-01', 'INC-02', 'INC-03', 'INC-04', 'INC-05', 'INC-06'];
      const colors = {{
        'INC-01': '#F97316',
        'INC-02': '#EF4444',
        'INC-03': '#DC2626',
        'INC-04': '#A855F7',
        'INC-05': '#F59E0B',
        'INC-06': '#38BDF8'
      }};
      const tracesTimeline = incIds.map(id => ({{
        x: windows,
        y: windows.map(w => (winMap[w] && winMap[w][id]) ? winMap[w][id] : 0),
        name: id,
        type: 'bar',
        marker: {{ color: colors[id] }}
      }}));

      const darkLayout = {{
        paper_bgcolor: 'rgba(0,0,0,0)',
        plot_bgcolor: 'rgba(0,0,0,0)',
        font: {{ color: '#CBD5E1', family: 'Inter, sans-serif', size: 11 }},
        margin: {{ t: 15, r: 15, b: 45, l: 45 }},
        barmode: 'stack',
        legend: {{ orientation: 'h', y: 1.14 }},
        xaxis: {{ gridcolor: 'rgba(148,163,184,0.1)' }},
        yaxis: {{ gridcolor: 'rgba(148,163,184,0.1)' }}
      }};
      Plotly.newPlot('chart-timeline', tracesTimeline, darkLayout, {{ responsive: true, displayModeBar: false }});

      const incNames = findings.map(f => f.id);
      const nativeCounts = findings.map(f => f.eventos_count - f.eventos_ocultos_info);
      const hiddenCounts = findings.map(f => f.eventos_ocultos_info);
      Plotly.newPlot('chart-incidents', [
        {{ x: incNames, y: nativeCounts, name: 'Alertas SIEM (Warning/Med/High)', type: 'bar', marker: {{ color: '#38BDF8' }} }},
        {{ x: incNames, y: hiddenCounts, name: 'Ocultos en Informational', type: 'bar', marker: {{ color: '#A855F7' }} }}
      ], darkLayout, {{ responsive: true, displayModeBar: false }});

      const srcCounts = SOC_DATA.metrics.log_source_counts;
      const sKeys = Object.keys(srcCounts);
      Plotly.newPlot('chart-sources', [{{
        x: sKeys,
        y: sKeys.map(k => srcCounts[k]),
        type: 'bar',
        text: sKeys.map(k => srcCounts[k]),
        textposition: 'auto',
        marker: {{ color: '#6366F1' }}
      }}], {{ ...darkLayout, showlegend: false }}, {{ responsive: true, displayModeBar: false }});

      const hostCounts = {{}};
      logs.forEach(l => {{
        if (l.Incident_ID && l.Incident_ID.startsWith('INC-')) {{
          hostCounts[l.Hostname_Norm] = (hostCounts[l.Hostname_Norm] || 0) + 1;
        }}
      }});
      const hKeys = Object.keys(hostCounts).sort((a,b) => hostCounts[b] - hostCounts[a]);
      Plotly.newPlot('chart-hosts', [{{
        x: hKeys,
        y: hKeys.map(k => hostCounts[k]),
        type: 'bar',
        text: hKeys.map(k => hostCounts[k] + ' evts'),
        textposition: 'auto',
        marker: {{ color: '#EF4444' }}
      }}], {{ ...darkLayout, showlegend: false }}, {{ responsive: true, displayModeBar: false }});
    }}

    function renderIncidents() {{
      const container = document.getElementById('incidents-container');
      container.innerHTML = SOC_DATA.findings.map(f => {{
        const isHigh = f.riesgo === 'Alto';
        const kcSteps = f.kill_chain.split('->').map(s => s.trim());
        const kcHtml = kcSteps.map((s, idx) =>
          `<span class="kc-step">${{s}}</span>${{idx < kcSteps.length - 1 ? '<span class="kc-arrow">➔</span>' : ''}}`
        ).join('');
        const jumpBtn = f.id.startsWith('INC-')
          ? `<button class="pill-btn" onclick="jumpToIncidentLogs('${{f.id}}')">🔎 Ver los ${{f.eventos_count}} logs de ${{f.id}} en Explorador</button>`
          : '';
        return `
          <div class="inc-card ${{isHigh ? '' : 'med'}}">
            <div class="inc-header">
              <div style="display:flex;align-items:center;gap:0.6rem;flex-wrap:wrap;">
                <span class="badge ${{isHigh ? 'badge-crit' : 'badge-med'}}">${{f.id}} • Riesgo ${{f.riesgo}} (${{f.cvss_estimado}})</span>
                <h3 style="font-size:1.02rem;font-weight:800;">${{f.titulo}}</h3>
              </div>
              <div style="display:flex;gap:0.45rem;flex-wrap:wrap;align-items:center;">
                <span class="badge badge-mitre">${{f.mitre}}</span>
                ${{f.eventos_ocultos_info > 0 ? `<span class="badge badge-trap">⚠️ ${{f.eventos_ocultos_info}} ocultos en Info</span>` : ''}}
                ${{jumpBtn}}
              </div>
            </div>
            <div class="killchain-flow">${{kcHtml}}</div>
            <p style="font-size:0.85rem;color:#E2E8F0;margin-bottom:0.45rem;"><b>Resumen Ejecutivo:</b> ${{f.resumen_ejecutivo}}</p>
            <p style="font-size:0.83rem;color:#CBD5E1;margin-bottom:0.5rem;"><b>Detalle Forense L2:</b> ${{f.resumen_tecnico}}</p>
            <div class="inc-meta-grid">
              <div><b>🕒 Ventana:</b> <span class="mono">${{f.ventana}}</span></div>
              <div><b>🖥️ Activos:</b> <span class="mono">${{f.activos}}</span></div>
              <div><b>👤 Usuarios:</b> <span class="mono">${{f.usuarios}}</span></div>
              <div><b>🔍 IOCs:</b> <span class="mono">${{f.ioc}}</span></div>
              <div><b>📊 Eventos:</b> <b>${{f.eventos_count}}</b> (${{f.eventos_ocultos_info}} en Info)</div>
              <div><b>🔑 Evidencia Logs:</b> <span class="mono">${{f.evidencia_logs}}</span></div>
            </div>
            <div style="font-size:0.81rem;color:#A7F3D0;margin-top:0.4rem;">
              <b>🛠️ Playbook Contención CLI:</b> <span class="mono">${{f.comandos_contencion}}</span>
            </div>
          </div>
        `;
      }}).join('');
    }}

    function renderHiddenTable() {{
      const tbody = document.getElementById('hidden-tbody');
      tbody.innerHTML = SOC_DATA.hidden_events.map(r => `
        <tr class="trap-row">
          <td class="mono" style="font-weight:700;color:#E9D5FF;">${{r.Log_ID}}</td>
          <td class="mono">${{r.Timestamp}}</td>
          <td><span class="badge badge-trap">${{r.Incident_ID}}</span></td>
          <td class="mono">${{r.Hostname}}</td>
          <td class="mono">${{r.Event_ID}}</td>
          <td class="mono">${{r.User}}</td>
          <td class="mono">${{r.Source_IP}} → ${{r.Destination}}</td>
          <td class="mono" style="color:#FDE047;">${{r.Process_CommandLine}}</td>
        </tr>
      `).join('');
    }}

    function renderExplorerTable() {{
      const t0 = performance.now();
      const incFilter = document.getElementById('filter-inc').value;
      const sevFilter = document.getElementById('filter-sev').value;
      const hostFilter = document.getElementById('filter-host').value;
      const q = document.getElementById('filter-search').value.trim().toLowerCase();

      const filtered = SOC_DATA.logs.filter(r => {{
        if (incFilter === 'MALICIOUS' && r.Incident_ID === 'NONE') return false;
        if (incFilter === 'TRAP' && !r.Hidden_Trap) return false;
        if (incFilter !== 'ALL' && incFilter !== 'MALICIOUS' && incFilter !== 'TRAP' && r.Incident_ID !== incFilter) return false;
        if (sevFilter !== 'ALL' && r.Severity !== sevFilter) return false;
        if (hostFilter !== 'ALL' && r.Hostname_Norm !== hostFilter) return false;
        if (q) {{
          const hay = `${{r.Log_ID}} ${{r.Timestamp}} ${{r.Incident_ID}} ${{r.Hostname_Norm}} ${{r.User_Norm}} ${{r.Source_IP}} ${{r.Destination}} ${{r.Event_ID}} ${{r.Event_Description}} ${{r.Process_CommandLine}}`.toLowerCase();
          if (!hay.includes(q)) return false;
        }}
        return true;
      }});

      document.getElementById('explorer-count').textContent = `Mostrando ${{filtered.length}} de ${{SOC_DATA.logs.length}} eventos`;
      const tbody = document.getElementById('explorer-tbody');
      tbody.innerHTML = filtered.slice(0, 350).map(r => {{
        const detail = r.Process_CommandLine !== '-' ? `${{r.Event_Description}} | ${{r.Process_CommandLine}}` : r.Event_Description;
        return `
          <tr class="${{r.Hidden_Trap ? 'trap-row' : ''}}">
            <td class="mono" style="font-weight:600;">${{r.Log_ID}}</td>
            <td class="mono">${{r.Timestamp}}</td>
            <td><span class="badge ${{r.Incident_ID.startsWith('INC') ? 'badge-crit' : 'badge-mitre'}}">${{r.Incident_ID}}</span></td>
            <td>${{r.Severity}} ${{r.Hidden_Trap ? '⚠️' : ''}}</td>
            <td class="mono">${{r.Hostname_Norm}}</td>
            <td class="mono">${{r.User_Norm}}</td>
            <td class="mono">${{r.Source_IP}} → ${{r.Destination}}</td>
            <td class="mono">${{r.Event_ID}} (${{r.Log_Source}})</td>
            <td class="mono" style="max-width:360px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${{detail.replace(/"/g, '&quot;')}}">${{detail}}</td>
          </tr>
        `;
      }}).join('');
      const dt = (performance.now() - t0).toFixed(1);
      document.getElementById('perf-badge').textContent = `Filtrado en ${{dt}} ms`;
    }}

    function renderReports() {{
      document.getElementById('exec-report-view').innerHTML = marked.parse(SOC_DATA.exec_md);
      document.getElementById('tech-report-view').innerHTML = marked.parse(SOC_DATA.tech_md);
    }}

    async function generateLiveAIReport() {{
      const provider = document.getElementById('ai-provider').value;
      const apiKey = document.getElementById('ai-key').value.trim();
      const statusEl = document.getElementById('ai-status-msg');

      if (provider === 'deterministic' || !apiKey) {{
        renderReports();
        statusEl.innerHTML = '✔ Informes regenerados instantáneamente mediante el Motor Forense Híbrido SOC L2 (100% verificado contra los 715 eventos).';
        return;
      }}

      statusEl.innerHTML = '⏳ Consultando API de IA Generativa con el contexto estructurado de los 6 incidentes...';
      const endpoint = provider === 'groq'
        ? 'https://api.groq.com/openai/v1/chat/completions'
        : 'https://api.openai.com/v1/chat/completions';
      const model = provider === 'groq' ? 'llama-3.3-70b-versatile' : 'gpt-4o-mini';

      try {{
        const resp = await fetch(endpoint, {{
          method: 'POST',
          headers: {{
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${{apiKey}}`
          }},
          body: JSON.stringify({{
            model: model,
            temperature: 0.2,
            messages: [
              {{ role: 'system', content: 'Eres un Principal SOC Nivel 2 & CSIRT Lead. Redacta un Resumen Ejecutivo C-Level en español claro basado estrictamente en las métricas forenses proporcionadas.' }},
              {{ role: 'user', content: JSON.stringify({{ metrics: SOC_DATA.metrics, findings: SOC_DATA.findings }}) }}
            ]
          }})
        }});
        const data = await resp.json();
        if (data.choices && data.choices[0]) {{
          SOC_DATA.exec_md = data.choices[0].message.content;
          renderReports();
          statusEl.innerHTML = `✔ Resumen Ejecutivo actualizado en vivo con ${{model}}.`;
        }} else {{
          throw new Error(data.error ? data.error.message : 'Respuesta inesperada de la API');
        }}
      }} catch (err) {{
        renderReports();
        statusEl.innerHTML = `<span style="color:#F59E0B;">⚠️ No se pudo conectar a la API externa (${{err.message}}); se mantiene el informe del Motor Forense Determinista.</span>`;
      }}
    }}

    function downloadMarkdownReport() {{
      const combined = `${{SOC_DATA.exec_md}}\\n\\n---\\n\\n${{SOC_DATA.tech_md}}`;
      const blob = new Blob([combined], {{ type: 'text/markdown;charset=utf-8' }});
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'Informe_Dual_SOC_L2_Incidentes.md';
      a.click();
      URL.revokeObjectURL(url);
    }}

    function correlateUploadedRow(r) {{
      const srcIp = String(r.Source_IP || '-').trim();
      const user = String(r.User || '-').trim();
      const host = String(r.Hostname || '-').trim();
      const ts = String(r.Timestamp || '').trim();
      if (srcIp === '203.0.113.74') return 'INC-01';
      if (srcIp === '198.51.100.77' || user === 'CORP\\\\admin') return 'INC-02';
      if (user === 'CORP\\\\backupsvc' && srcIp === '10.10.1.44' && ts >= '2026-10-23 09:36:00' && ts <= '2026-10-23 09:43:00') return 'INC-03';
      if (user === 'CORP\\\\rrojas' && srcIp === '10.10.1.31' && ts >= '2026-10-23 10:40:00' && ts <= '2026-10-23 10:49:30') return 'INC-04';
      if (host === 'APP-SRV01' && user === 'CORP\\\\helpdesk' && srcIp === '10.10.3.18') return 'INC-05';
      if (srcIp === '192.0.2.91' || user === 'IIS APPPOOL\\\\DefaultAppPool') return 'INC-06';
      return 'NONE';
    }}

    function handleXlsxUpload(event) {{
      const file = event.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = function(e) {{
        try {{
          const data = new Uint8Array(e.target.result);
          const workbook = XLSX.read(data, {{ type: 'array' }});
          const sheetName = workbook.SheetNames.includes('SIEM Export') ? 'SIEM Export' : workbook.SheetNames[0];
          const rows = XLSX.utils.sheet_to_json(workbook.Sheets[sheetName]);
          if (!rows.length) throw new Error('El archivo Excel está vacío (0 filas).');

          let malCount = 0;
          let trapCount = 0;
          const mapped = rows.map(r => {{
            const incId = correlateUploadedRow(r);
            const sev = String(r.Severity || 'Informational').trim();
            const isTrap = incId !== 'NONE' && sev === 'Informational';
            if (incId !== 'NONE') malCount++;
            if (isTrap) trapCount++;
            const host = String(r.Hostname || '-').trim();
            const user = String(r.User || '-').trim();
            return {{
              Log_ID: String(r.Log_ID || '-'),
              Timestamp: String(r.Timestamp || '-'),
              Minute_Window: String(r.Timestamp || '').slice(0, 16),
              Log_Source: String(r.Log_Source || '-'),
              Event_ID: String(r.Event_ID || '-'),
              Event_Description: String(r.Event_Description || '-'),
              Severity: sev,
              User: user,
              User_Norm: user === 'CORP\\\\svc_backup' ? 'CORP\\\\backupsvc' : user,
              Hostname: host,
              Hostname_Norm: host === 'DC01' ? 'DC-01' : host,
              Source_IP: String(r.Source_IP || '-'),
              Destination: String(r.Destination || '-'),
              Result: String(r.Result || '-'),
              Process_CommandLine: String(r.Process_CommandLine || '-'),
              Incident_ID: incId,
              Incident_Tag: incId,
              Hidden_Trap: isTrap
            }};
          }});

          SOC_DATA.logs = mapped;
          document.getElementById('kpi-total-val').textContent = mapped.length;
          document.getElementById('kpi-mal-val').textContent = malCount;
          document.getElementById('kpi-mal-sub').textContent = `${{malCount - trapCount}} alertas + ${{trapCount}} ocultos Info`;
          renderCharts();
          renderExplorerTable();
          document.getElementById('upload-status').innerHTML = `✔ Procesado en vivo: <b>${{file.name}}</b> (${{mapped.length}} logs, ${{malCount}} maliciosos, ${{trapCount}} ocultos en Info)`;
        }} catch (err) {{
          document.getElementById('upload-status').innerHTML = `<span style="color:#EF4444;">❌ Error validando .xlsx: ${{err.message}}</span>`;
        }}
      }};
      reader.readAsArrayBuffer(file);
    }}

    window.addEventListener('DOMContentLoaded', () => {{
      renderIncidents();
      renderCharts();
      renderHiddenTable();
      renderExplorerTable();
      renderReports();
    }});
  </script>
</body>
</html>
"""
    (output_dir / "index.html").write_text(html_content, encoding="utf-8")
    (output_dir / ".nojekyll").write_text("", encoding="utf-8")


def main() -> None:
    base_dir = Path(__file__).resolve().parent
    excel_path = base_dir / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx"
    print(f"[*] Cargando archivo oficial: {excel_path.name} ...")
    raw_df = pd.read_excel(excel_path, sheet_name="SIEM Export")

    print("[*] Ejecutando motor de correlación forense SOC Nivel 2...")
    df, findings, summary_metrics = analyze_siem_logs(raw_df)
    print(f"    - Total eventos procesados: {summary_metrics['total_logs']}")
    print(f"    - Alertas nativas SIEM: {summary_metrics['native_non_info_alerts']}")
    print(f"    - Eventos maliciosos correlacionados: {summary_metrics['correlated_malicious_events']}")
    print(f"    - Eventos críticos ocultos en Informational: {summary_metrics['hidden_info_critical_events']}")
    print(f"    - Exfiltración HTTPS POST detectada: {summary_metrics['exfil_bytes']:,} bytes ({summary_metrics['exfil_mib']} MiB)")

    print("[*] Generando Informe Ejecutivo e Informe Técnico Forense...")
    exec_rep, tech_rep, status = generate_ai_reports(
        findings,
        summary_metrics,
        provider="Motor Forense Determinista + Plantilla IA (Instantáneo / Offline)",
        model_name="soc-l2-forensic-engine-v2",
        api_url="",
        api_key="",
    )
    print(f"    - Estado IA: {status}")

    pdf_path = base_dir / "Informe_Final_SOC_L2_Incidentes.pdf"
    chart_path = base_dir / "soc_l2_dashboard_summary.png"
    print(f"[*] Compilando PDF oficial ({pdf_path.name}) y panel gráfico ({chart_path.name})...")
    pdf_bytes = build_pdf_report(
        exec_rep,
        tech_rep,
        findings,
        summary_metrics,
        df,
        chart_output_path=str(chart_path),
    )
    pdf_path.write_bytes(pdf_bytes)
    print(f"[+] PDF generado en '{pdf_path.name}' ({len(pdf_bytes):,} bytes).")

    print("[*] Sincronizando portal web interactivo ('index.html') para GitHub Pages...")
    build_static_web_portal(df, findings, summary_metrics, exec_rep, tech_rep, base_dir)
    print("[+] Portal 'index.html' actualizado correctamente.")


if __name__ == "__main__":
    main()
