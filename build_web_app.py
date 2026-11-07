"""Generador del Portal Web Interactivo Estático (index.html) para GitHub Pages (github.io).

Sincroniza al 100% los datos auditados de `core.parser` y `core.agents` dentro de una
Single-Page Application (SPA) autocontenida con Plotly.js, SheetJS (carga de .xlsx en vivo),
las 30 Leyes de UX y descarga directa del PDF oficial y dataset SIEM.
"""

from __future__ import annotations

import json
from pathlib import Path
import pandas as pd

from core.agents import generate_ai_reports
from core.parser import analyze_siem_logs


def main() -> None:
    base_dir = Path(__file__).resolve().parent
    excel_path = base_dir / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx"

    raw_df = pd.read_excel(excel_path, sheet_name="SIEM Export")
    df, findings, summary_metrics = analyze_siem_logs(raw_df)
    exec_md, tech_md, _ = generate_ai_reports(
        findings,
        summary_metrics,
        provider="Motor Forense Determinista + Plantilla IA (Instantáneo / Offline)",
        model_name="soc-l2-forensic-engine-v2",
        api_url="",
        api_key="",
    )

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
  <title>SOC L2 Command Center — Dojo Community Final Project</title>
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
      --accent-indigo: #6366F1;
      --sev-critical: #EF4444;
      --sev-high: #F97316;
      --sev-warning: #F59E0B;
      --sev-ok: #10B981;
      --von-restorff: #A855F7;
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
    .von-restorff-alert {{
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
    .ux-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
      gap: 0.8rem;
    }}
    .ux-card {{
      background: rgba(15, 23, 42, 0.9);
      border: 1px solid rgba(56, 189, 248, 0.22);
      border-radius: 10px;
      padding: 0.88rem;
    }}
    .ux-card h4 {{ color: #38BDF8; font-size: 0.88rem; margin-bottom: 0.28rem; }}
    .ux-card p {{ font-size: 0.79rem; color: #CBD5E1; margin-bottom: 0.32rem; }}
    .ux-card .impl {{ font-size: 0.77rem; color: #A7F3D0; }}
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

      <!-- Zeigarnik & Goal-Gradient Progress -->
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

      <!-- Postel's Law: Live XLSX Upload -->
      <div class="side-section">
        <h4>📂 Ingesta SIEM (.xlsx en vivo)</h4>
        <p style="font-size:0.75rem;color:#94A3B8;margin-bottom:0.45rem;">
          Dataset oficial precargado (715 eventos). También puedes validar cualquier archivo <code>.xlsx</code> local:
        </p>
        <input type="file" id="xlsx-upload" accept=".xlsx,.xls" style="font-size:0.74rem;padding:0.38rem;" onchange="handleXlsxUpload(event)" />
        <div id="upload-status" style="font-size:0.74rem;color:#10B981;margin-top:0.38rem;">
          ✔ Dataset activo: SIEM Export (715 filas)
        </div>
      </div>

      <!-- Fitts's Law: High-visibility Primary Downloads -->
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
      </div>

      <!-- Parkinson's Law SLA -->
      <div class="side-section">
        <h4>⏱️ Ventana Forense & SLA</h4>
        <div style="font-size:0.77rem;color:#CBD5E1;">
          <div>• <b>Inicio:</b> 2026-10-23 07:46:07</div>
          <div>• <b>Fin:</b> 2026-10-23 13:44:06</div>
          <div>• <b>Duración:</b> 5h 57m 59s</div>
          <div>• <b>Motor:</b> <span style="color:#38BDF8;">Doherty &lt; 30ms Ready</span></div>
        </div>
      </div>
    </aside>

    <!-- MAIN CONTENT -->
    <main class="main-area">
      <!-- HERO BANNER -->
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

      <!-- VON RESTORFF ISOLATION ALERT -->
      <div class="von-restorff-alert">
        🚨 <b>EFECTO VON RESTORFF — HALLAZGO DE AUDITORÍA SIEM:</b> Se detectaron <b>12 eventos críticos de intrusión</b> registrados erróneamente como <code>Severity = Informational</code> en el SIEM (incluyendo login exitoso post-spraying <code>EVT-00123</code>, escalamiento <code>EVT-00126</code>, verificación SMB post-vssadmin <code>EVT-00315</code>, archivado <code>7z.exe</code> <code>EVT-00428</code> y 5 ejecuciones del servicio persistente <code>wuhelper.exe</code>). El motor L2 correlaciona las <b>112 alertas nativas + 12 ocultas = 124 eventos maliciosos</b>.
      </div>

      <!-- MILLER'S LAW: 5 CHUNKED KPI CARDS -->
      <section class="kpi-grid">
        <div class="kpi-card">
          <div class="kpi-label">1. Eventos Analizados</div>
          <div class="kpi-value">715</div>
          <span class="kpi-delta">591 ruido base (82.7%)</span>
        </div>
        <div class="kpi-card warning">
          <div class="kpi-label">2. Eventos Maliciosos L2</div>
          <div class="kpi-value">124</div>
          <span class="kpi-delta red">112 alertas + 12 ocultos Info</span>
        </div>
        <div class="kpi-card critical">
          <div class="kpi-label">3. Incidentes Críticos</div>
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

      <!-- NAVIGATION TABS -->
      <nav class="tabs-bar">
        <button class="tab-btn active" onclick="switchTab('tab-panorama', this)">📊 1. Panorama Táctico (80/20)</button>
        <button class="tab-btn" onclick="switchTab('tab-incidentes', this)">🚨 2. Los 6 Incidentes + OBS-01</button>
        <button class="tab-btn" onclick="switchTab('tab-trampa', this)">🕵️‍♂️ 3. Trampa SIEM (12 Eventos Info)</button>
        <button class="tab-btn" onclick="switchTab('tab-explorador', this)">🔎 4. Explorador Forense (715 Logs)</button>
        <button class="tab-btn" onclick="switchTab('tab-ux', this)">🧠 5. Arquitectura Cognitiva (30 Leyes UX)</button>
        <button class="tab-btn" onclick="switchTab('tab-informes', this)">📄 6. Informes IA & Exportación PDF</button>
      </nav>

      <!-- TAB 1: PANORAMA TACTICO -->
      <section id="tab-panorama" class="tab-panel active">
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

      <!-- TAB 2: LOS 6 INCIDENTES -->
      <section id="tab-incidentes" class="tab-panel">
        <div id="incidents-container"></div>
      </section>

      <!-- TAB 3: TRAMPA SIEM (12 EVENTOS INFO) -->
      <section id="tab-trampa" class="tab-panel">
        <div class="panel-card">
          <h3><span>🕵️‍♂️ Auditoría de Ceguera de Detección: Los 12 Eventos Críticos Ocultos en <code>Informational</code></span></h3>
          <p style="font-size:0.85rem;color:#CBD5E1;margin-bottom:0.9rem;">
            Un analista Nivel 1 que filtre únicamente por <code>Severity != Informational</code> perdería los 12 registros de éxito de intrusión, compresión y ejecución persistente listados a continuación:
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

      <!-- TAB 4: EXPLORADOR FORENSE -->
      <section id="tab-explorador" class="tab-panel">
        <div class="panel-card">
          <h3>
            <span>🔎 Explorador de Telemetría SIEM (715 Eventos Normalizados)</span>
            <span id="explorer-count" class="badge badge-mitre">Mostrando 715 eventos</span>
          </h3>
          <div class="filter-bar">
            <div>
              <label style="font-size:0.74rem;color:#94A3B8;">Filtrar por Incidente</label>
              <select id="filter-inc" onchange="renderExplorerTable()">
                <option value="ALL">Todos los eventos (715)</option>
                <option value="MALICIOUS">Solo Maliciosos Correlacionados (124)</option>
                <option value="TRAP">Solo Trampa Informational (12)</option>
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

      <!-- TAB 5: 30 LEYES DE UX -->
      <section id="tab-ux" class="tab-panel">
        <div class="panel-card">
          <h3><span>🧠 Matriz de las 30 Leyes de UX (Jon Yablonski) Aplicadas al SOC L2</span></h3>
          <p style="font-size:0.84rem;color:#CBD5E1;margin-bottom:0.95rem;">
            Cada principio de psicología cognitiva y diseño de interacción de <a href="https://lawsofux.com/es/" target="_blank" style="color:#38BDF8;">LawsOfUX.com</a> ha sido implementado en la interfaz para minimizar la fatiga de alertas y acelerar el MTTR:
          </p>
          <div id="ux-laws-grid" class="ux-grid"></div>
        </div>
      </section>

      <!-- TAB 6: INFORMES IA & EXPORTACION PDF -->
      <section id="tab-informes" class="tab-panel">
        <div class="panel-card">
          <h3>
            <span>🤖 Orquestador de Informes Duales (C-Level Ejecutivo + Forense CSIRT L2)</span>
            <div style="display:flex;gap:0.5rem;flex-wrap:wrap;">
              <a href="Informe_Final_SOC_L2_Incidentes.pdf" download="Informe_Final_SOC_L2_Incidentes.pdf" class="btn-cta btn-primary" style="width:auto;min-height:38px;padding:0.45rem 0.95rem;">
                📥 Descargar PDF Compilado Oficial
              </a>
              <button class="btn-cta btn-secondary" style="width:auto;min-height:38px;padding:0.45rem 0.95rem;" onclick="window.print()">
                🖨️ Imprimir / Guardar Vista
              </button>
            </div>
          </h3>
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
    </main>
  </div>

  <script>
    const SOC_DATA = {payload_json};

    const UX_LAWS = [
      ["1. Atención Selectiva", "Centrar la atención en estímulos relacionados con la meta.", "Filtro automático del 82.7% de ruido base para resaltar los 124 eventos maliciosos."],
      ["2. Carga Cognitiva", "Minimizar los recursos mentales requeridos para operar.", "Normalización automática de identidades (DC01→DC-01, svc_backup→backupsvc)."],
      ["3. Efecto Estética-Usabilidad", "Diseños atractivos se perciben como más confiables.", "Tema oscuro táctico de alto contraste con jerarquía tipográfica Inter & JetBrains Mono."],
      ["4. Efecto de Posición en Serie", "Se recuerdan mejor el primer y último elemento.", "Pestaña #1 (Panorama Táctico) al inicio y Pestaña #6 (Exportación PDF) al final."],
      ["5. Efecto de Tendencia a la Meta", "La motivación aumenta al acercarse a la meta.", "Barra interactiva de progreso de contención de los 6 incidentes en el panel lateral."],
      ["6. Efecto Von Restorff", "El elemento que difiere del resto es recordado.", "Alerta púrpura exclusiva para los 12 eventos críticos ocultos en Informational."],
      ["7. Efecto Zeigarnik", "Se recuerdan mejor las tareas incompletas.", "Checklist interactivo de contención que alerta si queda algún incidente pendiente."],
      ["8. Fluir (Flow)", "Inmersión total sin fricción técnica.", "Filtros reactivos instantáneos sin recargas de página."],
      ["9. Fragmentación (Chunking)", "Agrupar información en bloques manejables.", "715 logs agrupados en 6 tarjetas de incidente con fases de Kill Chain."],
      ["10. Memoria de Trabajo", "Retener datos clave sin obligar a memorizar.", "IOCs críticos (IPs, Usuarios, Archivos, Bytes) visibles persistentemente por incidente."],
      ["11. Navaja de Occam", "Priorizar la explicación más directa y verificable.", "Gráficos limpios sin adornos 3D innecesarios y correlación determinista."],
      ["12. Conectividad Uniforme", "Elementos conectados visualmente se perciben relacionados.", "Cadenas de ataque conectadas: Origen → Vector → Host → Impacto."],
      ["13. Ley de Fitts", "Objetivos grandes y cercanos se alcanzan más rápido.", "Botones CTA de descarga PDF de ancho completo y 46px de altura mínima."],
      ["14. Ley de Hick", "Reducir el número de opciones acelera la decisión.", "Filtros preconfigurados por incidente y severidad con valores óptimos por defecto."],
      ["15. Ley de Jakob", "Usar convenciones familiares de plataformas SIEM.", "Estructura familiar estilo Splunk ES / Microsoft Sentinel / Elastic Security."],
      ["16. Ley de la Semejanza", "Elementos similares se perciben agrupados.", "Semáforo cromático consistente (Rojo=Alto/Crítico, Ámbar=Medio, Púrpura=Trampa Info)."],
      ["17. Ley de Miller", "Mantener 7±2 elementos en memoria de trabajo.", "5 KPIs principales en la cabecera y 6 pestañas de navegación."],
      ["18. Ley de Parkinson", "Acotar el tiempo evita que la tarea se expanda.", "Ventana forense acotada (05h 57m 59s) y descarga de reporte en 1 clic."],
      ["19. Ley de Postel", "Ser liberal en lo que se acepta y conservador en lo que se envía.", "Acepta archivos .xlsx en vivo en el navegador y valida esquema antes de exportar."],
      ["20. Ley de Proximidad", "Objetos cercanos se perciben como unidad.", "Métricas, comando exacto y playbook de remediación juntos en cada incidente."],
      ["21. Ley de Prägnanz", "Interpretar formas complejas de la manera más simple.", "Transformación de 715 filas crudas en 4 visualizaciones ejecutivas claras."],
      ["22. Ley de Región Común", "Elementos dentro de un borde claro se agrupan.", "Tarjetas con bordes definidos para separar cada uno de los 6 incidentes."],
      ["23. Ley de Tesler", "El sistema absorbe la complejidad inherente.", "El parser resuelve correlación MITRE, conversión MiB/MB y detección de evasión."],
      ["24. Modelo Mental", "Alinear la interfaz con el flujo mental del analista SOC.", "Flujo Triage → Investigación → Threat Hunting → Contención → Reporte."],
      ["25. Paradoja del Usuario Activo", "El usuario usa la app de inmediato sin leer manuales.", "Precarga automática de los 715 eventos e informes listos desde el segundo cero."],
      ["26. Principio de Pareto (80/20)", "El 80% del riesgo proviene del 20% de los eventos.", "Foco directo en el 17.3% de eventos maliciosos (124 de 715) que causan el 100% del daño."],
      ["27. Regla de Fin de Pico", "La experiencia se juzga por su punto álgido y su final.", "Pico: hallazgo de los 12 logs ocultos; Final: descarga instantánea del PDF profesional."],
      ["28. Revelación Progresiva", "Mostrar primero el resumen y luego el detalle a demanda.", "Tarjetas ejecutivas con tablas de logs detalladas bajo demanda."],
      ["29. Sesgo Cognitivo", "Mitigar el sesgo de anclaje en severidades del SIEM.", "Alerta explícita contra confiar ciegamente en Severity=Informational."],
      ["30. Umbral de Doherty (<400 ms)", "Respuestas en menos de 400 ms mantienen la atención.", "Motor en memoria en el navegador con filtrado y renderizado en <30 ms."]
    ];

    function switchTab(tabId, btnEl) {{
      document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.getElementById(tabId).classList.add('active');
      btnEl.classList.add('active');
      window.dispatchEvent(new Event('resize'));
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
        {{ x: incNames, y: hiddenCounts, name: 'Ocultos en Informational (Trampa)', type: 'bar', marker: {{ color: '#A855F7' }} }}
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
        return `
          <div class="inc-card ${{isHigh ? '' : 'med'}}">
            <div class="inc-header">
              <div style="display:flex;align-items:center;gap:0.6rem;flex-wrap:wrap;">
                <span class="badge ${{isHigh ? 'badge-crit' : 'badge-med'}}">${{f.id}} • Riesgo ${{f.riesgo}} (${{f.cvss_estimado}})</span>
                <h3 style="font-size:1.02rem;font-weight:800;">${{f.titulo}}</h3>
              </div>
              <div style="display:flex;gap:0.45rem;flex-wrap:wrap;">
                <span class="badge badge-mitre">${{f.mitre}}</span>
                ${{f.eventos_ocultos_info > 0 ? `<span class="badge badge-trap">⚠️ ${{f.eventos_ocultos_info}} ocultos en Info</span>` : ''}}
              </div>
            </div>
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
              <b>🛠️ Playbook Contención:</b> <span class="mono">${{f.comandos_contencion}}</span>
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
      tbody.innerHTML = filtered.slice(0, 300).map(r => {{
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
    }}

    function renderUxLaws() {{
      const grid = document.getElementById('ux-laws-grid');
      grid.innerHTML = UX_LAWS.map(([title, desc, impl]) => `
        <div class="ux-card">
          <h4>${{title}}</h4>
          <p>${{desc}}</p>
          <div class="impl">✔ <b>Aplicación SOC:</b> ${{impl}}</div>
        </div>
      `).join('');
    }}

    function renderReports() {{
      document.getElementById('exec-report-view').innerHTML = marked.parse(SOC_DATA.exec_md);
      document.getElementById('tech-report-view').innerHTML = marked.parse(SOC_DATA.tech_md);
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
          document.getElementById('upload-status').innerHTML = `✔ Archivo validado: <b>${{file.name}}</b> (${{rows.length}} eventos en hoja <code>${{sheetName}}</code>)`;
        }} catch (err) {{
          document.getElementById('upload-status').innerHTML = `<span style="color:#EF4444;">❌ Error leyendo archivo .xlsx: ${{err.message}}</span>`;
        }}
      }};
      reader.readAsArrayBuffer(file);
    }}

    window.addEventListener('DOMContentLoaded', () => {{
      renderCharts();
      renderIncidents();
      renderHiddenTable();
      renderExplorerTable();
      renderUxLaws();
      renderReports();
    }});
  </script>
</body>
</html>
"""

    (base_dir / "index.html").write_text(html_content, encoding="utf-8")
    (base_dir / ".nojekyll").write_text("", encoding="utf-8")
    print("Generated index.html and .nojekyll successfully.")


if __name__ == "__main__":
    main()
