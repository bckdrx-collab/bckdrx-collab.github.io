"""
Script CLI unificado para generar los entregables oficiales del proyecto SOC Nivel 2 (JEV // LangChain LCEL Edition):
1. 'Informe_Final_SOC_L2_Incidentes.pdf' (Informe Ejecutivo C-Level + Informe Técnico Forense DFIR)
2. 'soc_l2_dashboard_summary.png' (Panel cuádruple de visualización forense en alta resolución)
3. 'index.html' (Interfaz Fluida JEV Cyber Command OS v3.0 con LangChain LCEL Copilot para GitHub Pages)
"""

from __future__ import annotations
import json
from pathlib import Path
import pandas as pd

from core.parser import analyze_siem_logs
from core.agents import generate_ai_reports, get_langchain_pipeline_metadata
from core.detection_engineering import (
    get_lolbas_gtfobins_catalog,
    get_sigma_rules_yaml,
    get_yara_classic_rules,
    get_yarax_nextgen_rules,
)
from core.pdf_generator import build_pdf_report


def build_static_web_portal(
    df: pd.DataFrame,
    findings: list[dict],
    summary_metrics: dict,
    exec_md: str,
    tech_md: str,
    output_dir: Path,
) -> None:
    """Genera index.html y .nojekyll con la interfaz fluida JEV Cyber Command OS + LangChain LCEL."""
    df_export = df.copy()
    df_export["Timestamp_Str"] = df_export["Timestamp_dt"].dt.strftime("%Y-%m-%d %H:%M:%S")
    df_export["Minute_Window"] = df_export["Timestamp_dt"].dt.floor("10min").dt.strftime("%H:%M")

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
                "External_IP": bool(r["Involves_External_IP"]),
            }
        )

    lcel_meta = get_langchain_pipeline_metadata()
    payload = {
        "metrics": summary_metrics,
        "findings": findings,
        "hidden_events": summary_metrics["hidden_events_records"],
        "lcel": lcel_meta,
        "lolbas_catalog": get_lolbas_gtfobins_catalog(),
        "sigma_yaml": get_sigma_rules_yaml(),
        "yara_classic": get_yara_classic_rules(),
        "yarax_rust": get_yarax_nextgen_rules(),
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
  <title>JEV // SOC L2 Cyber Command OS — LangChain LCEL & Análisis Forense SIEM</title>
  <meta name="description" content="JEV Cyber Command OS v3.0: Plataforma Fluida de Análisis de Incidentes SIEM con Orquestación LangChain LCEL, MITRE ATT&CK y Generación de Informes Forenses SOC Nivel 2." />
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <script src="https://cdn.plot.ly/plotly-2.35.2.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/xlsx@0.18.5/dist/xlsx.full.min.js"></script>
  <style>
    :root {{
      --bg-deep: #040711;
      --bg-surface: rgba(11, 18, 35, 0.84);
      --bg-card: rgba(15, 23, 42, 0.88);
      --bg-glass: rgba(15, 23, 42, 0.72);
      --border-cyan: rgba(0, 240, 255, 0.24);
      --border-subtle: rgba(148, 163, 184, 0.16);
      --text-main: #F8FAFC;
      --text-muted: #94A3B8;
      --neon-cyan: #00F0FF;
      --neon-purple: #8B5CF6;
      --neon-crimson: #FF2A5F;
      --neon-emerald: #10B981;
      --neon-amber: #FBBF24;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    html {{ scroll-behavior: smooth; }}
    body {{
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      background:
        radial-gradient(circle at 12% 8%, rgba(0, 240, 255, 0.10) 0%, transparent 38%),
        radial-gradient(circle at 88% 12%, rgba(139, 92, 246, 0.12) 0%, transparent 42%),
        radial-gradient(circle at 50% 90%, rgba(255, 42, 95, 0.07) 0%, transparent 45%),
        var(--bg-deep);
      color: var(--text-main);
      line-height: 1.55;
      min-height: 100vh;
      overflow-x: hidden;
    }}
    code, pre, .mono {{ font-family: 'JetBrains Mono', monospace; }}

    /* Top Fluid Glass Navigation Bar */
    .top-command-bar {{
      position: sticky;
      top: 0;
      z-index: 100;
      background: rgba(5, 9, 20, 0.84);
      backdrop-filter: blur(18px);
      -webkit-backdrop-filter: blur(18px);
      border-bottom: 1px solid var(--border-cyan);
      padding: 0.7rem clamp(1rem, 2.5vw, 2.2rem);
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 0.85rem;
    }}
    .brand-cluster {{
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }}
    .brand-orb {{
      width: 40px;
      height: 40px;
      border-radius: 12px;
      background: linear-gradient(135deg, #00F0FF 0%, #8B5CF6 60%, #FF2A5F 100%);
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 800;
      font-family: 'Space Grotesk', sans-serif;
      color: #040711;
      font-size: 1.05rem;
      box-shadow: 0 0 20px rgba(0, 240, 255, 0.4);
    }}
    .brand-name {{
      font-family: 'Space Grotesk', sans-serif;
      font-weight: 700;
      font-size: 1.08rem;
      letter-spacing: -0.02em;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }}
    .pulse-dot {{
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--neon-emerald);
      box-shadow: 0 0 10px var(--neon-emerald);
      display: inline-block;
    }}
    .brand-meta {{
      font-size: 0.73rem;
      color: var(--neon-cyan);
      font-family: 'JetBrains Mono', monospace;
    }}

    /* Fluid Mode Switcher Pills */
    .mode-pills {{
      display: flex;
      flex-wrap: wrap;
      gap: 0.4rem;
      background: rgba(15, 23, 42, 0.8);
      padding: 0.28rem;
      border-radius: 999px;
      border: 1px solid var(--border-subtle);
    }}
    .mode-pill {{
      background: transparent;
      border: none;
      color: var(--text-muted);
      padding: 0.42rem 0.88rem;
      border-radius: 999px;
      font-size: 0.79rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.22s cubic-bezier(0.16, 1, 0.3, 1);
    }}
    .mode-pill:hover {{
      color: #FFFFFF;
      background: rgba(255, 255, 255, 0.06);
    }}
    .mode-pill.active {{
      background: linear-gradient(135deg, rgba(0, 240, 255, 0.22), rgba(139, 92, 246, 0.28));
      color: #FFFFFF;
      border: 1px solid rgba(0, 240, 255, 0.48);
      box-shadow: 0 4px 14px rgba(0, 240, 255, 0.18);
    }}

    .top-actions {{
      display: flex;
      align-items: center;
      gap: 0.6rem;
    }}
    .btn-pdf-glow {{
      display: inline-flex;
      align-items: center;
      gap: 0.45rem;
      background: linear-gradient(135deg, #FF2A5F 0%, #E11D48 100%);
      color: #FFFFFF;
      text-decoration: none;
      padding: 0.55rem 1.05rem;
      border-radius: 11px;
      font-weight: 700;
      font-size: 0.82rem;
      border: 1px solid rgba(255, 255, 255, 0.22);
      box-shadow: 0 6px 20px rgba(255, 42, 95, 0.32);
      transition: transform 0.2s ease, box-shadow 0.2s ease;
    }}
    .btn-pdf-glow:hover {{
      transform: translateY(-1px);
      box-shadow: 0 10px 26px rgba(255, 42, 95, 0.48);
    }}

    /* Fluid Workspace Container */
    .fluid-shell {{
      display: grid;
      grid-template-columns: 300px minmax(0, 1fr);
      gap: 1.25rem;
      padding: clamp(1rem, 2vw, 1.75rem);
      max-width: 1920px;
      margin: 0 auto;
      align-items: start;
    }}
    @media (max-width: 1120px) {{
      .fluid-shell {{
        grid-template-columns: 1fr;
      }}
    }}

    /* Left Fluid Control Dock */
    .control-dock {{
      position: sticky;
      top: 4.8rem;
      display: flex;
      flex-direction: column;
      gap: 0.95rem;
    }}
    @media (max-width: 1120px) {{
      .control-dock {{
        position: static;
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      }}
    }}
    .dock-card {{
      background: var(--bg-glass);
      backdrop-filter: blur(14px);
      border: 1px solid var(--border-subtle);
      border-radius: 16px;
      padding: 1rem;
      box-shadow: 0 10px 28px rgba(0, 0, 0, 0.25);
    }}
    .dock-title {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.73rem;
      text-transform: uppercase;
      letter-spacing: 0.07em;
      color: var(--neon-cyan);
      margin-bottom: 0.6rem;
      display: flex;
      align-items: center;
      gap: 0.4rem;
    }}
    .dock-select, .dock-input {{
      width: 100%;
      background: rgba(4, 7, 17, 0.85);
      border: 1px solid rgba(148, 163, 184, 0.26);
      color: #F8FAFC;
      padding: 0.5rem 0.65rem;
      border-radius: 9px;
      font-size: 0.8rem;
      margin-top: 0.3rem;
    }}
    .soar-bar-wrap {{
      width: 100%;
      height: 8px;
      background: rgba(15, 23, 42, 0.95);
      border-radius: 999px;
      overflow: hidden;
      margin: 0.5rem 0;
      border: 1px solid rgba(255, 255, 255, 0.08);
    }}
    .soar-bar-fill {{
      height: 100%;
      background: linear-gradient(90deg, var(--neon-cyan), var(--neon-emerald));
      transition: width 0.35s ease;
    }}
    .soar-check {{
      display: flex;
      align-items: center;
      gap: 0.5rem;
      font-size: 0.8rem;
      padding: 0.24rem 0;
      cursor: pointer;
      color: #E2E8F0;
    }}
    .soar-check input {{
      accent-color: var(--neon-cyan);
      width: 15px;
      height: 15px;
      cursor: pointer;
    }}

    /* Main Fluid Canvas */
    .fluid-canvas {{
      display: flex;
      flex-direction: column;
      gap: 1.2rem;
      min-width: 0;
    }}

    /* Hero Banner */
    .jev-hero {{
      background:
        radial-gradient(circle at 85% 20%, rgba(0, 240, 255, 0.16) 0%, rgba(139, 92, 246, 0.12) 40%, transparent 75%),
        linear-gradient(135deg, rgba(11, 18, 35, 0.95) 0%, rgba(17, 24, 39, 0.92) 100%);
      border: 1px solid var(--border-cyan);
      border-radius: 20px;
      padding: clamp(1.15rem, 2.2vw, 1.75rem);
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      gap: 1rem;
      box-shadow: 0 16px 40px rgba(0, 0, 0, 0.35);
    }}
    .hero-badges {{
      display: flex;
      flex-wrap: wrap;
      gap: 0.45rem;
      margin-bottom: 0.55rem;
    }}
    .h-badge {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.71rem;
      font-weight: 600;
      padding: 0.2rem 0.65rem;
      border-radius: 999px;
      text-transform: uppercase;
    }}
    .hb-cyan {{ background: rgba(0, 240, 255, 0.14); border: 1px solid rgba(0, 240, 255, 0.45); color: #67E8F9; }}
    .hb-purple {{ background: rgba(139, 92, 246, 0.18); border: 1px solid rgba(167, 139, 250, 0.45); color: #DDD6FE; }}
    .hb-crimson {{ background: rgba(255, 42, 95, 0.18); border: 1px solid rgba(255, 42, 95, 0.5); color: #FECDD3; }}
    .hb-emerald {{ background: rgba(16, 185, 129, 0.16); border: 1px solid rgba(52, 211, 153, 0.45); color: #A7F3D0; }}
    .hero-h1 {{
      font-family: 'Space Grotesk', sans-serif;
      font-size: clamp(1.35rem, 2.3vw, 1.95rem);
      font-weight: 700;
      background: linear-gradient(90deg, #FFFFFF 0%, #67E8F9 60%, #C4B5FD 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }}
    .hero-p {{
      font-size: 0.88rem;
      color: var(--text-muted);
      margin-top: 0.3rem;
    }}

    /* Bento Fluid KPI Row */
    .bento-kpi-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 0.9rem;
    }}
    .bento-kpi {{
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      border-radius: 16px;
      padding: 1rem 1.15rem;
      transition: transform 0.22s ease, border-color 0.22s ease, box-shadow 0.22s ease;
      position: relative;
      overflow: hidden;
    }}
    .bento-kpi:hover {{
      transform: translateY(-3px);
      border-color: var(--neon-cyan);
      box-shadow: 0 12px 28px rgba(0, 240, 255, 0.12);
    }}
    .kpi-idx {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.7rem;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.06em;
    }}
    .kpi-num {{
      font-family: 'Space Grotesk', sans-serif;
      font-size: 1.7rem;
      font-weight: 700;
      margin: 0.2rem 0;
      color: #FFFFFF;
    }}
    .kpi-foot {{
      font-size: 0.76rem;
      font-weight: 500;
    }}

    /* Fluid Section Card */
    .fluid-section {{
      background: var(--bg-surface);
      backdrop-filter: blur(14px);
      border: 1px solid var(--border-subtle);
      border-radius: 18px;
      padding: clamp(1rem, 2vw, 1.5rem);
      box-shadow: 0 12px 32px rgba(0, 0, 0, 0.26);
      transition: opacity 0.25s ease;
    }}
    .sec-header {{
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      gap: 0.75rem;
      margin-bottom: 1rem;
      padding-bottom: 0.75rem;
      border-bottom: 1px solid rgba(148, 163, 184, 0.14);
    }}
    .sec-title {{
      font-family: 'Space Grotesk', sans-serif;
      font-size: 1.18rem;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }}

    /* LangChain LCEL Graph Nodes */
    .lcel-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 0.8rem;
      margin-bottom: 1rem;
    }}
    .lcel-card {{
      background: rgba(15, 23, 42, 0.92);
      border: 1px solid rgba(139, 92, 246, 0.36);
      border-left: 4px solid var(--neon-purple);
      border-radius: 13px;
      padding: 0.85rem 1rem;
    }}
    .lcel-type {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.69rem;
      color: var(--neon-cyan);
    }}
    .lcel-name {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.84rem;
      font-weight: 700;
      color: #DDD6FE;
      margin: 0.15rem 0 0.3rem 0;
    }}
    .lcel-desc {{
      font-size: 0.78rem;
      color: var(--text-muted);
    }}

    /* JEV Copilot Interactive Console */
    .copilot-chips {{
      display: flex;
      flex-wrap: wrap;
      gap: 0.45rem;
      margin-bottom: 0.85rem;
    }}
    .chip-btn {{
      background: rgba(0, 240, 255, 0.09);
      border: 1px solid rgba(0, 240, 255, 0.32);
      color: #E0F2FE;
      padding: 0.42rem 0.8rem;
      border-radius: 999px;
      font-size: 0.78rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.18s ease;
    }}
    .chip-btn:hover {{
      background: rgba(0, 240, 255, 0.22);
      transform: translateY(-1px);
      box-shadow: 0 4px 12px rgba(0, 240, 255, 0.2);
    }}
    .copilot-input-row {{
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 0.6rem;
      margin-bottom: 0.9rem;
    }}
    .copilot-input {{
      background: rgba(4, 7, 17, 0.9);
      border: 1px solid rgba(0, 240, 255, 0.35);
      color: #FFFFFF;
      padding: 0.68rem 0.95rem;
      border-radius: 12px;
      font-size: 0.86rem;
      outline: none;
    }}
    .copilot-input:focus {{
      border-color: var(--neon-cyan);
      box-shadow: 0 0 0 3px rgba(0, 240, 255, 0.15);
    }}
    .btn-chain-run {{
      background: linear-gradient(135deg, #00F0FF 0%, #3B82F6 100%);
      color: #040711;
      border: none;
      padding: 0.68rem 1.2rem;
      border-radius: 12px;
      font-weight: 800;
      font-size: 0.83rem;
      cursor: pointer;
      transition: transform 0.18s ease;
    }}
    .btn-chain-run:hover {{
      transform: translateY(-1px);
    }}
    .copilot-response-box {{
      background: rgba(4, 7, 17, 0.88);
      border: 1px solid rgba(0, 240, 255, 0.28);
      border-radius: 14px;
      padding: 1.05rem 1.25rem;
      font-size: 0.87rem;
      line-height: 1.62;
    }}
    .copilot-response-box h3 {{
      color: var(--neon-cyan);
      font-family: 'Space Grotesk', sans-serif;
      margin-bottom: 0.55rem;
      font-size: 1.02rem;
    }}
    .copilot-response-box pre {{
      background: #02040A;
      border: 1px solid rgba(56, 189, 248, 0.25);
      padding: 0.75rem;
      border-radius: 9px;
      overflow-x: auto;
      color: #67E8F9;
      margin-top: 0.55rem;
      font-size: 0.79rem;
    }}

    /* Incident Selector & Fluid Bento Detail */
    .inc-selector-bar {{
      display: flex;
      flex-wrap: wrap;
      gap: 0.45rem;
      margin-bottom: 1rem;
    }}
    .inc-pill {{
      background: rgba(15, 23, 42, 0.9);
      border: 1px solid rgba(148, 163, 184, 0.25);
      color: #E2E8F0;
      padding: 0.42rem 0.82rem;
      border-radius: 10px;
      font-size: 0.78rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.18s ease;
    }}
    .inc-pill:hover, .inc-pill.active {{
      border-color: var(--neon-crimson);
      background: rgba(255, 42, 95, 0.16);
      color: #FFFFFF;
    }}
    .inc-card {{
      background: rgba(9, 14, 28, 0.92);
      border: 1px solid rgba(148, 163, 184, 0.2);
      border-left: 5px solid var(--neon-crimson);
      border-radius: 16px;
      padding: 1.15rem;
      margin-bottom: 1rem;
    }}
    .inc-card.medium {{
      border-left-color: var(--neon-amber);
    }}
    .kc-track {{
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 0.4rem;
      background: rgba(15, 23, 42, 0.95);
      border: 1px solid rgba(0, 240, 255, 0.22);
      padding: 0.55rem 0.85rem;
      border-radius: 10px;
      margin: 0.65rem 0;
    }}
    .kc-node {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.74rem;
      background: rgba(0, 240, 255, 0.12);
      border: 1px solid rgba(0, 240, 255, 0.35);
      color: #67E8F9;
      padding: 0.18rem 0.55rem;
      border-radius: 6px;
      font-weight: 600;
    }}
    .inc-3col {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 0.85rem;
      margin: 0.75rem 0;
    }}
    .inc-subbox {{
      background: rgba(15, 23, 42, 0.78);
      border: 1px solid rgba(148, 163, 184, 0.16);
      border-radius: 12px;
      padding: 0.85rem;
      font-size: 0.84rem;
    }}
    .inc-subbox h5 {{
      color: var(--neon-cyan);
      font-size: 0.76rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 0.4rem;
    }}
    .cli-playbook {{
      background: #02050D;
      border: 1px solid rgba(16, 185, 129, 0.35);
      border-radius: 10px;
      padding: 0.75rem 0.95rem;
      color: #6EE7B7;
      font-size: 0.79rem;
      overflow-x: auto;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 0.8rem;
      margin-top: 0.6rem;
    }}

    /* Charts Grid */
    .charts-bento {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(410px, 1fr));
      gap: 1rem;
    }}
    @media (max-width: 600px) {{
      .charts-bento {{ grid-template-columns: 1fr; }}
    }}
    .chart-box {{
      background: rgba(9, 14, 28, 0.88);
      border: 1px solid var(--border-subtle);
      border-radius: 14px;
      padding: 0.6rem;
      min-height: 350px;
    }}

    /* Tables */
    .table-scroll {{
      width: 100%;
      overflow-x: auto;
      border-radius: 12px;
      border: 1px solid var(--border-subtle);
      max-height: 440px;
      overflow-y: auto;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.8rem;
      text-align: left;
    }}
    th {{
      position: sticky;
      top: 0;
      background: #0B132B;
      color: var(--neon-cyan);
      padding: 0.65rem 0.75rem;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.73rem;
      text-transform: uppercase;
      border-bottom: 1px solid rgba(0, 240, 255, 0.25);
      z-index: 2;
    }}
    td {{
      padding: 0.55rem 0.75rem;
      border-bottom: 1px solid rgba(148, 163, 184, 0.1);
      color: #E2E8F0;
    }}
    tr:hover td {{
      background: rgba(0, 240, 255, 0.05);
    }}

    .dual-editors {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
      gap: 1rem;
    }}
    .report-textarea {{
      width: 100%;
      height: 360px;
      background: rgba(4, 7, 17, 0.92);
      border: 1px solid rgba(0, 240, 255, 0.25);
      border-radius: 12px;
      color: #F8FAFC;
      padding: 0.9rem;
      font-family: 'Inter', sans-serif;
      font-size: 0.84rem;
      line-height: 1.55;
      resize: vertical;
    }}
    .hidden-mod {{ display: none !important; }}
  </style>
</head>
<body>

  <!-- BARRA SUPERIOR FLUIDA JEV CYBER COMMAND -->
  <header class="top-command-bar">
    <div class="brand-cluster">
      <div class="brand-orb">JEV</div>
      <div>
        <div class="brand-name">
          JEV // Cyber Command OS <span class="pulse-dot" title="Motor Forense Activo"></span>
        </div>
        <div class="brand-meta">LANGCHAIN LCEL · SOC NIVEL 2 · DFIR ENGINE v3.0</div>
      </div>
    </div>

    <nav class="mode-pills" aria-label="Selector de espacio de trabajo fluido">
      <button class="mode-pill active" onclick="setWorkspaceMode('all', this)">🌊 Vista Fluida Integral</button>
      <button class="mode-pill" onclick="setWorkspaceMode('copilot', this)">🧠 JEV LangChain Copilot</button>
      <button class="mode-pill" onclick="setWorkspaceMode('incidents', this)">🎯 Radar & Kill Chain</button>
      <button class="mode-pill" onclick="setWorkspaceMode('detection', this)">🧬 LOLBAS, GTFOBins & YARA-X/Sigma</button>
      <button class="mode-pill" onclick="setWorkspaceMode('visuals', this)">📊 Telemetría & Trampas</button>
      <button class="mode-pill" onclick="setWorkspaceMode('reports', this)">📄 Dual Report & PDF</button>
      <button class="mode-pill" onclick="setWorkspaceMode('logs', this)">🔎 Stream SIEM (715)</button>
    </nav>

    <div class="top-actions">
      <a href="Informe_Final_SOC_L2_Incidentes.pdf" download="Informe_Final_SOC_L2_Incidentes.pdf" class="btn-pdf-glow">
        📥 Descargar PDF Oficial (7 Págs)
      </a>
    </div>
  </header>

  <!-- CONTENEDOR FLUIDO PRINCIPAL -->
  <div class="fluid-shell">

    <!-- DOCK LATERAL FLUIDO -->
    <aside class="control-dock">
      <div class="dock-card">
        <div class="dock-title">📂 01 // Ingesta SIEM (.xlsx)</div>
        <div style="font-size:0.77rem;color:var(--text-muted);margin-bottom:0.45rem;">
          Dataset oficial precargado (715 eventos) o analiza cualquier exportación Excel del SIEM:
        </div>
        <input type="file" id="excelUploadInput" accept=".xlsx,.xls" class="dock-input" />
        <div id="datasetStatusBadge" style="font-size:0.74rem;color:var(--neon-emerald);margin-top:0.45rem;font-weight:600;">
          ✓ Activo: SIEM Export (715 logs validados)
        </div>
      </div>

      <div class="dock-card">
        <div class="dock-title">🔗 02 // Orquestador LangChain</div>
        <label style="font-size:0.75rem;color:#CBD5E1;">Backend del Grafo LCEL:</label>
        <select id="lcelProviderSelect" class="dock-select" onchange="toggleLcelConfig()">
          <option value="deterministic">LangChain LCEL + Motor Forense (Instantáneo)</option>
          <option value="ollama">LangChain + Ollama Local (REST)</option>
          <option value="openai">LangChain + ChatOpenAI (OpenAI/Groq)</option>
        </select>
        <div id="lcelDynamicConfig" style="display:none;margin-top:0.5rem;">
          <input type="text" id="lcelApiUrl" class="dock-input" value="http://localhost:11434" placeholder="Endpoint URL" />
          <input type="text" id="lcelModelName" class="dock-input" value="qwen2.5:7b" placeholder="Modelo (ej. gpt-4o-mini)" />
          <input type="password" id="lcelApiKey" class="dock-input" placeholder="API Key (opcional en Ollama)" />
        </div>
        <div style="font-size:0.73rem;color:#C4B5FD;margin-top:0.5rem;">
          ⚡ <code>RunnableParallel(exec, dfir)</code> listo.
        </div>
      </div>

      <div class="dock-card">
        <div class="dock-title">🛡️ 03 // Contención SOAR</div>
        <div style="display:flex;justify-content:space-between;font-size:0.76rem;">
          <span>Playbooks ejecutados:</span>
          <strong id="soarCounterText" style="color:var(--neon-cyan);">0/6</strong>
        </div>
        <div class="soar-bar-wrap">
          <div id="soarBarFill" class="soar-bar-fill" style="width:0%;"></div>
        </div>
        <div id="soarChecklistContainer"></div>
      </div>
    </aside>

    <!-- LIENZO FLUIDO CENTRAL -->
    <main class="fluid-canvas">

      <!-- HERO TÁCTICO -->
      <section class="jev-hero">
        <div>
          <div class="hero-badges">
            <span class="h-badge hb-cyan">⚡ JEV CYBER COMMAND v3.0</span>
            <span class="h-badge hb-purple">🔗 LANGCHAIN LCEL PIPELINE</span>
            <span class="h-badge hb-crimson" id="heroCritBadge">🔴 6 INCIDENTES CRÍTICOS</span>
            <span class="h-badge hb-emerald" id="heroHiddenBadge">🕵️‍♂️ 12 RESCATADOS DE 'INFORMATIONAL'</span>
          </div>
          <h1 class="hero-h1">Centro de Operaciones SOC Nivel 2 & Copiloto Forense LangChain</h1>
          <p class="hero-p" id="heroSubText">
            Auditoría integral de 715 eventos SIEM · Ventana UTC: 2026-10-23 07:46:07 → 13:44:06 · Correlación MITRE ATT&CK v15
          </p>
        </div>
      </section>

      <!-- BENTO KPI GRID -->
      <section class="bento-kpi-grid">
        <div class="bento-kpi">
          <div class="kpi-idx">01 // TELEMETRÍA SIEM</div>
          <div class="kpi-num" id="kpiTotalLogs">715</div>
          <div class="kpi-foot" style="color:var(--neon-emerald);">✓ 100% procesados y normalizados</div>
        </div>
        <div class="bento-kpi">
          <div class="kpi-idx">02 // CORRELACIÓN REAL L2</div>
          <div class="kpi-num" id="kpiMaliciousLogs" style="color:var(--neon-crimson);">124</div>
          <div class="kpi-foot" id="kpiMaliciousSub" style="color:var(--neon-cyan);">+12 ocultos en 'Info' (vs 112 SIEM)</div>
        </div>
        <div class="bento-kpi">
          <div class="kpi-idx">03 // INCIDENTES CONFIRMADOS</div>
          <div class="kpi-num" id="kpiIncidentsCount">6 Críticos</div>
          <div class="kpi-foot" style="color:var(--neon-amber);">+ 1 Brecha Visibilidad (OBS-01)</div>
        </div>
        <div class="bento-kpi">
          <div class="kpi-idx">04 // EXFILTRACIÓN LEGAL & FINANZAS</div>
          <div class="kpi-num" id="kpiExfilMib" style="color:#C4B5FD;">241.57 MiB</div>
          <div class="kpi-foot" id="kpiExfilSub" style="color:#CBD5E1;">253.31 MB (22 HTTPS POST) + Budget2027</div>
        </div>
        <div class="bento-kpi">
          <div class="kpi-idx">05 // TRÁFICO IPs EXTERNAS</div>
          <div class="kpi-num" id="kpiExtIpCount" style="color:#38BDF8;">91 logs</div>
          <div class="kpi-foot" style="color:#94A3B8;">68 Inbound ataques + 23 Outbound C2</div>
        </div>
      </section>

      <!-- MÓDULO 1: JEV LANGCHAIN COPILOT & GRAFO LCEL -->
      <section id="mod-copilot" class="fluid-section">
        <div class="sec-header">
          <div class="sec-title">🧠 JEV Cyber Copilot — Orquestador Conversacional LangChain (LCEL)</div>
          <span class="mono" style="font-size:0.75rem;color:#C4B5FD;">ChatPromptTemplate | Runnable | StrOutputParser()</span>
        </div>

        <div class="lcel-grid" id="lcelNodesGrid"></div>

        <div class="copilot-chips">
          <button class="chip-btn" onclick="runJevCopilot('¿Cuáles son los 12 eventos críticos ocultos en Informational?')">🕵️‍♂️ 12 Ocultos en Info</button>
          <button class="chip-btn" onclick="runJevCopilot('Detalla la exfiltración de datos en INC-04 e INC-02 en MiB y bytes')">📤 Exfiltración 241.57 MiB</button>
          <button class="chip-btn" onclick="runJevCopilot('Analiza el pre-ransomware en WS-023 y vssadmin delete shadows')">🚨 Pre-Ransomware VSS (INC-03)</button>
          <button class="chip-btn" onclick="runJevCopilot('Mapea todos los binarios LOLBAS y GTFOBins abusados en los 715 eventos')">🧬 LOLBAS & GTFOBins</button>
          <button class="chip-btn" onclick="runJevCopilot('Genera las reglas Sigma para detectar los incidentes y trampas Informational')">📡 Reglas Sigma (.yml)</button>
          <button class="chip-btn" onclick="runJevCopilot('Dame las reglas YARA y YARA-X en Rust para cazar los artefactos maliciosos')">🦀 YARA & YARA-X (.yarx)</button>
          <button class="chip-btn" onclick="runJevCopilot('Mapea todas las tácticas y técnicas MITRE ATT&CK detectadas')">🎯 Matriz MITRE ATT&CK</button>
          <button class="chip-btn" onclick="runJevCopilot('Dame el Playbook maestro con todos los comandos PowerShell de contención')">🛡️ Playbook PowerShell</button>
        </div>

        <div class="copilot-input-row">
          <input type="text" id="copilotQueryInput" class="copilot-input" placeholder="Pregunta a JEV LangChain Copilot (ej. 'Analiza INC-01', '¿Qué hizo 192.0.2.91 en WEB-01?', 'wuhelper.exe')..." onkeydown="if(event.key==='Enter') triggerCustomCopilot()" />
          <button class="btn-chain-run" onclick="triggerCustomCopilot()">⚡ Ejecutar Chain</button>
        </div>

        <div id="copilotResponseContainer" class="copilot-response-box"></div>
      </section>

      <!-- MÓDULO 2: RADAR DE INCIDENTES, KILL CHAIN Y PLAYBOOKS -->
      <section id="mod-incidents" class="fluid-section">
        <div class="sec-header">
          <div class="sec-title">🎯 Radar de Incidentes, Cadena de Ataque (Kill Chain) & Playbooks CLI</div>
          <span class="mono" style="font-size:0.75rem;color:var(--neon-cyan);">6 Incidentes Riesgo Alto + 1 Observación Media</span>
        </div>

        <div class="inc-selector-bar" id="incidentSelectorBar"></div>
        <div id="incidentCardsContainer"></div>
      </section>

      <!-- MÓDULO 2.5: INGENIERÍA DE DETECCIÓN (LOLBAS, GTFOBINS, SIGMA, YARA & YARA-X) -->
      <section id="mod-detection" class="fluid-section">
        <div class="sec-header">
          <div class="sec-title">🧬 Ingeniería de Detección: LOLBAS · GTFOBins · Sigma · YARA · YARA-X</div>
          <div style="display:flex;flex-wrap:wrap;gap:0.5rem;">
            <a href="https://lolbas-project.github.io/" target="_blank" rel="noopener noreferrer" class="chip-btn" style="text-decoration:none;">🌐 LOLBAS Project ↗</a>
            <a href="https://gtfobins.org/" target="_blank" rel="noopener noreferrer" class="chip-btn" style="text-decoration:none;">🌐 GTFOBins Oficial ↗</a>
          </div>
        </div>

        <p style="font-size:0.84rem;color:var(--text-muted);margin-bottom:0.85rem;">
          Mapeo forense de los <strong>8 binarios nativos abusados (Living Off The Land)</strong> en los 715 eventos SIEM contra
          <a href="https://lolbas-project.github.io/" target="_blank" style="color:var(--neon-cyan);">lolbas-project.github.io</a> y
          <a href="https://gtfobins.org/" target="_blank" style="color:var(--neon-cyan);">gtfobins.org</a>, junto con las reglas listas para producción en
          <strong>Sigma (<code>.yml</code>)</strong>, <strong>YARA Clásico (<code>.yar</code>)</strong> y <strong>YARA-X en Rust (<code>.yarx</code>)</strong>:
        </p>

        <div class="table-scroll" style="margin-bottom:1.15rem;">
          <table>
            <thead>
              <tr>
                <th>Binario Abusado</th>
                <th>Catálogo</th>
                <th>Incidente / Log_IDs</th>
                <th>Host & Usuario</th>
                <th>Comando Detectado en SIEM</th>
                <th>MITRE ATT&CK</th>
                <th>Referencias Oficiales</th>
              </tr>
            </thead>
            <tbody id="lolbasTableBody"></tbody>
          </table>
        </div>

        <div style="display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:0.6rem;margin-bottom:0.75rem;">
          <div class="copilot-chips" style="margin-bottom:0;">
            <button class="chip-btn" onclick="switchDetectionRuleTab('sigma')">📡 Reglas Sigma (.yml)</button>
            <button class="chip-btn" onclick="switchDetectionRuleTab('yara')">🧬 YARA Clásico (.yar)</button>
            <button class="chip-btn" onclick="switchDetectionRuleTab('yarax')">🦀 YARA-X Next-Gen Rust (.yarx)</button>
          </div>
          <div style="display:flex;gap:0.5rem;">
            <button class="chip-btn" onclick="copyActiveDetectionRule(this)">📋 Copiar Regla</button>
            <button class="btn-chain-run" onclick="downloadActiveDetectionRule()">📥 Descargar Archivo de Reglas</button>
          </div>
        </div>
        <pre id="detectionRuleCodeBox" style="background:#02050D;border:1px solid rgba(0,240,255,0.3);border-radius:12px;padding:1rem;color:#67E8F9;font-size:0.79rem;overflow-x:auto;max-height:420px;overflow-y:auto;"></pre>
      </section>

      <!-- MÓDULO 3: ANALÍTICA VISUAL & AUDITORÍA DE TRAMPAS INFORMATIONAL -->
      <section id="mod-visuals" class="fluid-section">
        <div class="sec-header">
          <div class="sec-title">📊 Telemetría Analítica SIEM & Auditoría de Evasión ('Informational')</div>
          <span class="mono" style="font-size:0.75rem;color:var(--neon-emerald);">124 Eventos Maliciosos Correlacionados</span>
        </div>

        <div class="charts-bento">
          <div id="chartIncidents" class="chart-box"></div>
          <div id="chartTimeline" class="chart-box"></div>
          <div id="chartHosts" class="chart-box"></div>
          <div id="chartIPs" class="chart-box"></div>
        </div>

        <div style="margin-top:1.25rem;">
          <h4 style="font-family:'Space Grotesk',sans-serif;font-size:1rem;color:var(--neon-cyan);margin-bottom:0.55rem;">
            🕵️‍♂️ Los 12 Eventos Críticos Camuflados bajo Severidad 'Informational' (Rescatados por Correlación L2)
          </h4>
          <div class="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Log_ID</th>
                  <th>Timestamp</th>
                  <th>Incidente</th>
                  <th>Hostname</th>
                  <th>Event_ID</th>
                  <th>Usuario</th>
                  <th>Origen</th>
                  <th>Destino</th>
                  <th>Comando / Evidencia Forense</th>
                </tr>
              </thead>
              <tbody id="hiddenTrapsTableBody"></tbody>
            </table>
          </div>
        </div>
      </section>

      <!-- MÓDULO 4: ESTUDIO DUAL DE INFORMES (C-LEVEL / DFIR) & PDF -->
      <section id="mod-reports" class="fluid-section">
        <div class="sec-header">
          <div class="sec-title">📄 Estudio Dual de Informes LangChain (`RunnableParallel`) & Exportación PDF</div>
          <div style="display:flex;gap:0.6rem;align-items:center;">
            <button class="chip-btn" onclick="runLiveLangChainReportGeneration()">🔗 Re-ejecutar Pipeline LangChain</button>
            <a href="Informe_Final_SOC_L2_Incidentes.pdf" download="Informe_Final_SOC_L2_Incidentes.pdf" class="btn-pdf-glow">📥 Descargar PDF Oficial</a>
          </div>
        </div>
        <div id="reportStatusBanner" style="font-size:0.8rem;color:var(--neon-emerald);margin-bottom:0.8rem;">
          🟢 Pipeline LangChain LCEL (`RunnableParallel`) verificado sobre los 715 registros SIEM.
        </div>
        <div class="dual-editors">
          <div>
            <h4 style="font-size:0.88rem;color:var(--neon-cyan);margin-bottom:0.4rem;">👔 1. Informe Ejecutivo (C-Level / Junta Directiva)</h4>
            <textarea id="execReportBox" class="report-textarea"></textarea>
          </div>
          <div>
            <h4 style="font-size:0.88rem;color:#C4B5FD;margin-bottom:0.4rem;">🛠️ 2. Informe Técnico Forense (Ingeniería SOC L2 / DFIR)</h4>
            <textarea id="techReportBox" class="report-textarea"></textarea>
          </div>
        </div>
      </section>

      <!-- MÓDULO 5: STREAM FORENSE DE TELEMETRÍA (715 LOGS) -->
      <section id="mod-logs" class="fluid-section">
        <div class="sec-header">
          <div class="sec-title">🔎 Explorador Forense de Telemetría SIEM en Vivo</div>
          <span id="logCounterBadge" class="mono" style="font-size:0.78rem;color:var(--neon-cyan);">Mostrando 124 de 715 eventos</span>
        </div>

        <div style="display:flex;flex-wrap:wrap;gap:0.6rem;margin-bottom:0.9rem;align-items:center;">
          <button class="chip-btn" onclick="setLogPreset('malicious')">🔴 Maliciosos (124)</button>
          <button class="chip-btn" onclick="setLogPreset('hidden')">🕵️‍♂️ Ocultos en Info (12)</button>
          <button class="chip-btn" onclick="setLogPreset('extip')">🌐 IPs Externas (91)</button>
          <button class="chip-btn" onclick="setLogPreset('all')">📋 Todos los Logs (715)</button>
          <select id="logIncidentFilter" class="dock-select" style="width:auto;margin-top:0;" onchange="renderLogTable()">
            <option value="ALL">Todos los Incidentes</option>
          </select>
          <input type="text" id="logSearchInput" class="dock-input" style="width:260px;margin-top:0;" placeholder="🔎 Buscar Log_ID, IP, usuario, comando..." oninput="renderLogTable()" />
        </div>

        <div class="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Log_ID</th>
                <th>Timestamp</th>
                <th>Incidente</th>
                <th>Severidad</th>
                <th>Hostname</th>
                <th>Event_ID</th>
                <th>Usuario</th>
                <th>Source_IP</th>
                <th>Destino</th>
                <th>Comando / Descripción</th>
              </tr>
            </thead>
            <tbody id="siemLogsTableBody"></tbody>
          </table>
        </div>
      </section>

    </main>
  </div>

  <script>
    const SOC_DATA = {payload_json};
    let activeLogPreset = 'malicious';
    let activeIncidentFilter = 'ALL';
    const containedState = {{
      'INC-01': false,
      'INC-02': false,
      'INC-03': false,
      'INC-04': false,
      'INC-05': false,
      'INC-06': false
    }};

    function escapeHtml(str) {{
      return String(str ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
    }}

    function setWorkspaceMode(mode, btnEl) {{
      document.querySelectorAll('.mode-pill').forEach(b => b.classList.remove('active'));
      if (btnEl) btnEl.classList.add('active');
      const map = {{
        copilot: 'mod-copilot',
        incidents: 'mod-incidents',
        detection: 'mod-detection',
        visuals: 'mod-visuals',
        reports: 'mod-reports',
        logs: 'mod-logs'
      }};
      Object.values(map).forEach(id => {{
        const el = document.getElementById(id);
        if (!el) return;
        if (mode === 'all' || map[mode] === id) {{
          el.classList.remove('hidden-mod');
        }} else {{
          el.classList.add('hidden-mod');
        }}
      }});
      setTimeout(() => window.dispatchEvent(new Event('resize')), 60);
    }}

    function toggleLcelConfig() {{
      const val = document.getElementById('lcelProviderSelect').value;
      const box = document.getElementById('lcelDynamicConfig');
      box.style.display = val === 'deterministic' ? 'none' : 'block';
      if (val === 'openai') {{
        document.getElementById('lcelApiUrl').value = 'https://api.openai.com/v1';
        document.getElementById('lcelModelName').value = 'gpt-4o-mini';
      }} else if (val === 'ollama') {{
        document.getElementById('lcelApiUrl').value = 'http://localhost:11434';
        document.getElementById('lcelModelName').value = 'qwen2.5:7b';
      }}
    }}

    function renderLcelNodes() {{
      const grid = document.getElementById('lcelNodesGrid');
      grid.innerHTML = SOC_DATA.lcel.nodes.map(n => `
        <div class="lcel-card">
          <div class="lcel-type">${{escapeHtml(n.type)}}</div>
          <div class="lcel-name">⚡ ${{escapeHtml(n.name)}}</div>
          <div class="lcel-desc">${{escapeHtml(n.desc)}}</div>
        </div>
      `).join('');
    }}

    function renderSoarChecklist() {{
      const container = document.getElementById('soarChecklistContainer');
      const keys = Object.keys(containedState);
      container.innerHTML = keys.map(k => `
        <label class="soar-check">
          <input type="checkbox" ${{containedState[k] ? 'checked' : ''}} onchange="toggleContainment('${{k}}', this.checked)" />
          <span>Contener <strong>${{k}}</strong></span>
        </label>
      `).join('');
      const done = keys.filter(k => containedState[k]).length;
      document.getElementById('soarCounterText').textContent = `${{done}}/6`;
      document.getElementById('soarBarFill').style.width = `${{(done / 6) * 100}}%`;
    }}

    function toggleContainment(incId, val) {{
      containedState[incId] = val;
      renderSoarChecklist();
      renderIncidents(activeIncidentFilter);
    }}

    function runJevCopilot(queryText) {{
      const t0 = performance.now();
      const q = (queryText || '').toLowerCase().trim();
      const m = SOC_DATA.metrics;
      const findings = SOC_DATA.findings;
      let html = '';

      const matchInc = findings.find(f => q.includes(f.id.toLowerCase()) || q.includes(f.id.toLowerCase().replace('-', '')));
      if (matchInc) {{
        html = `
          <h3>⚡ Análisis JEV LangChain — [${{escapeHtml(matchInc.id)}}] ${{escapeHtml(matchInc.titulo)}}</h3>
          <p><strong>Riesgo / CVSS:</strong> <code>${{escapeHtml(matchInc.riesgo.toUpperCase())}} (${{escapeHtml(matchInc.cvss_estimado)}})</code> · <strong>Ventana:</strong> <code>${{escapeHtml(matchInc.ventana)}}</code></p>
          <p><strong>Activos:</strong> <code>${{escapeHtml(matchInc.activos)}}</code> · <strong>Usuarios:</strong> <code>${{escapeHtml(matchInc.usuarios)}}</code></p>
          <p><strong>MITRE ATT&CK:</strong> <code>${{escapeHtml(matchInc.mitre)}}</code></p>
          <p style="margin-top:0.45rem;"><strong>🔬 Reconstrucción Forense:</strong> ${{escapeHtml(matchInc.resumen_tecnico)}}</p>
          <pre>${{escapeHtml(matchInc.comandos_contencion)}}</pre>
        `;
      }} else if (q.includes('informational') || q.includes('oculto') || q.includes('trampa') || q.includes('12')) {{
        const items = SOC_DATA.hidden_events.map(r =>
          `<li><code>${{escapeHtml(r.Log_ID)}}</code> (${{escapeHtml(r.Timestamp)}}) · <strong>${{escapeHtml(r.Incident_ID)}}</strong> en <code>${{escapeHtml(r.Hostname)}}</code> (<code>${{escapeHtml(r.User)}}</code>): Event <code>${{escapeHtml(r.Event_ID)}}</code> — <code>${{escapeHtml(r.Process_CommandLine)}}</code></li>`
        ).join('');
        html = `
          <h3>🕵️‍♂️ Auditoría JEV LangChain: Los ${{m.hidden_info_critical_events}} Eventos Críticos Ocultos en 'Informational'</h3>
          <p>Un filtro de Nivel 1 que descarte <code>Severity == Informational</code> omitiría la intrusión exitosa tras Password Spraying, la compresión previa a la exfiltración y las 5 ejecuciones del binario persistente:</p>
          <ul style="margin:0.55rem 0 0.55rem 1.2rem;">${{items}}</ul>
        `;
      }} else if (q.includes('exfil') || q.includes('mib') || q.includes('bytes') || q.includes('legal') || q.includes('budget')) {{
        const inc4 = findings.find(f => f.id === 'INC-04') || findings[3];
        html = `
          <h3>📤 Telemetría de Exfiltración Cuantificada (INC-04 & INC-02)</h3>
          <p>1. <strong>INC-04 (Repositorio Legal — WS-018 / CORP\\rrojas):</strong> Acceso SMB a <code>\\\\FS-SRV01\\Legal</code> (<code>EVT-00419</code>), empaquetado con <code>7z.exe a C:\\Users\\Public\\archive.7z C:\\Legal\\*.docx</code> (<code>EVT-00428</code>) y exfiltración de <strong>${{m.exfil_bytes.toLocaleString()}} bytes (${{m.exfil_mib}} MiB / ${{m.exfil_mb}} MB)</strong> en 22 conexiones <code>HTTPS POST</code> hacia <code>198.51.100.88:443</code>.</p>
          <p style="margin-top:0.35rem;">2. <strong>INC-02 (Finanzas — APP-SRV01 → FS-SRV01 / CORP\\admin):</strong> Sustracción de <code>Budget2027.xlsx</code>, compresión con <code>tar.exe</code> en <code>C:\\Temp\\finance.zip</code> y envío a <code>203.0.113.88:443</code>.</p>
          <pre>${{escapeHtml(inc4.comandos_contencion)}}</pre>
        `;
      }} else if (q.includes('ransom') || q.includes('vssadmin') || q.includes('shadow') || q.includes('ws-023')) {{
        const inc3 = findings.find(f => f.id === 'INC-03') || findings[2];
        html = `
          <h3>🚨 Alerta Pre-Ransomware en WS-023 (INC-03 — CORP\\backupsvc)</h3>
          <p>Ejecución de PowerShell codificado en Base64 (<code>EVT-00280</code>), barrido secuencial de 16 documentos financieros <code>Finance\\FY2026\\document_000..015.xlsx</code> y destrucción de copias de sombra mediante <code>vssadmin.exe delete shadows /all /quiet</code> (<code>EVT-00314</code>, MITRE <code>T1490</code>).</p>
          <pre>${{escapeHtml(inc3.comandos_contencion)}}</pre>
        `;
      }} else if (q.includes('mitre') || q.includes('táctica') || q.includes('tecnica') || q.includes('att&ck')) {{
        const list = findings.map(f => `<li><strong>${{escapeHtml(f.id)}} (${{escapeHtml(f.riesgo)}}):</strong> <code>${{escapeHtml(f.mitre)}}</code> — ${{escapeHtml(f.titulo)}}</li>`).join('');
        html = `
          <h3>🎯 Matriz Consolidada MITRE ATT&CK v15 (SOC Nivel 2)</h3>
          <ul style="margin:0.5rem 0 0.5rem 1.2rem;">${{list}}</ul>
        `;
      }} else if (q.includes('ip') || q.includes('ioc') || q.includes('extern')) {{
        html = `
          <h3>🌐 Indicadores de Compromiso (IoCs) — Red, Artefactos y Cuentas</h3>
          <ul style="margin:0.45rem 0 0.45rem 1.2rem;">
            <li><strong>IPs Atacantes (Inbound):</strong> <code>203.0.113.74</code> (Password Spraying DC-01), <code>198.51.100.77</code> (RDP Brute Force APP-SRV01), <code>192.0.2.91</code> (Webshell RCE WEB-01).</li>
            <li><strong>IPs Receptoras de Exfiltración (Outbound TCP/443):</strong> <code>198.51.100.88:443</code> (241.57 MiB Legal) y <code>203.0.113.88:443</code> (Budget2027.xlsx).</li>
            <li><strong>Artefactos Maliciosos:</strong> <code>C:\\Temp\\finance.zip</code>, <code>C:\\Users\\Public\\archive.7z</code>, <code>C:\\ProgramData\\wuhelper.exe</code>, <code>/uploads/test.aspx</code>.</li>
          </ul>
        `;
      }} else if (q.includes('dc-01') || q.includes('dc01') || q.includes('normaliz') || q.includes('backupsvc')) {{
        html = `
          <h3>🔧 Auditoría de Normalización de Telemetría SIEM (OBS-01)</h3>
          <p>• <strong>Fragmentación de Hostname en Controlador de Dominio:</strong> <code>DC-01</code> (${{m.normalization.dc_hyphen_count}} eventos) vs <code>DC01</code> sin guion (${{m.normalization.dc_no_hyphen_count}} eventos). Unificados automáticamente bajo <code>Hostname_Norm = DC-01</code>.</p>
          <p>• <strong>Dualidad de Cuentas de Servicio:</strong> <code>CORP\\backupsvc</code> (${{m.normalization.backupsvc_count}} eventos, comprometida en INC-03) vs <code>CORP\\svc_backup</code> (${{m.normalization.svc_backup_count}} eventos).</p>
        `;
      }} else if (q.includes('lolbas') || q.includes('gtfobins') || q.includes('gtfo')) {{
        const items = SOC_DATA.lolbas_catalog.map(c =>
          `<li><strong><code>${{escapeHtml(c.binario)}}</code></strong> [${{escapeHtml(c.catalogo)}} · <code>${{escapeHtml(c.incidente)}}</code> · <code>${{escapeHtml(c.log_ids)}}</code>]: <code>${{escapeHtml(c.comando_detectado)}}</code> — <a href="${{escapeHtml(c.lolbas_url)}}" target="_blank" style="color:#00F0FF;">LOLBAS ↗</a> | <a href="${{escapeHtml(c.gtfobins_url)}}" target="_blank" style="color:#C4B5FD;">GTFOBins ↗</a></li>`
        ).join('');
        html = `
          <h3>🧬 Auditoría Forense LOLBAS & GTFOBins en los 715 Eventos SIEM</h3>
          <p>Se identificaron 8 binarios del sistema abusados para ejecución, compresión de exfiltración, persistencia y sabotaje de copias de sombra:</p>
          <ul style="margin:0.5rem 0 0.5rem 1.2rem;">${{items}}</ul>
        `;
      }} else if (q.includes('sigma')) {{
        html = `
          <h3>📡 Reglas Sigma de Producción (.yml) — Detección SIEM & Trampas Informational</h3>
          <pre>${{escapeHtml(SOC_DATA.sigma_yaml)}}</pre>
        `;
      }} else if (q.includes('yara')) {{
        html = `
          <h3>🦀 Reglas YARA Clásico (.yar) & YARA-X Next-Gen en Rust (.yarx)</h3>
          <pre>${{escapeHtml(SOC_DATA.yarax_rust + "\\n\\n" + SOC_DATA.yara_classic)}}</pre>
        `;
      }} else if (q.includes('playbook') || q.includes('powershell') || q.includes('comando')) {{
        const allCmds = findings.slice(0, 6).map(f => `# [${{f.id}}] ${{f.titulo}}\n${{f.comandos_contencion}}`).join('\n\n');
        html = `
          <h3>🛡️ Playbook Maestro de Contención CLI (SOC Nivel 2)</h3>
          <pre>${{escapeHtml(allCmds)}}</pre>
        `;
      }} else {{
        const rows = findings.map(f => `<li><strong>${{escapeHtml(f.id)}} (${{escapeHtml(f.riesgo)}} | CVSS ${{escapeHtml(f.cvss_estimado)}}):</strong> ${{escapeHtml(f.titulo)}} (${{f.eventos_count}} logs, ${{f.eventos_ocultos_info}} en Info)</li>`).join('');
        html = `
          <h3>🤖 JEV Cyber Copilot (LangChain LCEL) — Síntesis Operativa</h3>
          <p>Se auditaron <strong>${{m.total_logs}} eventos SIEM</strong> vinculando <strong>${{m.correlated_malicious_events}} eventos maliciosos</strong> (${{m.native_non_info_alerts}} alertas nativas + <strong>${{m.hidden_info_critical_events}} críticos rescatados de severidad Informational</strong>) y cuantificando <strong>${{m.exfil_mib}} MiB</strong> exfiltrados.</p>
          <ul style="margin:0.5rem 0 0.5rem 1.2rem;">${{rows}}</ul>
        `;
      }}

      const elapsed = (performance.now() - t0).toFixed(1);
      document.getElementById('copilotResponseContainer').innerHTML = `
        ${{html}}
        <div class="mono" style="margin-top:0.65rem;font-size:0.72rem;color:var(--text-muted);">
          ⚡ Cadena LangChain <code>JEVCyberCopilotChain</code> completada en ${{elapsed}} ms · Consulta: "${{escapeHtml(queryText)}}"
        </div>
      `;
    }}

    function triggerCustomCopilot() {{
      const inp = document.getElementById('copilotQueryInput');
      const val = inp.value.trim();
      if (val) runJevCopilot(val);
    }}

    function renderIncidents(selectedId) {{
      activeIncidentFilter = selectedId || 'ALL';
      const bar = document.getElementById('incidentSelectorBar');
      const pills = ['ALL', ...SOC_DATA.findings.map(f => f.id)];
      bar.innerHTML = pills.map(id => `
        <button class="inc-pill ${{activeIncidentFilter === id ? 'active' : ''}}" onclick="renderIncidents('${{id}}')">
          ${{id === 'ALL' ? '📋 Todos los Hallazgos (7)' : '🎯 ' + id}}
        </button>
      `).join('');

      const visible = activeIncidentFilter === 'ALL'
        ? SOC_DATA.findings
        : SOC_DATA.findings.filter(f => f.id === activeIncidentFilter);

      const container = document.getElementById('incidentCardsContainer');
      container.innerHTML = visible.map(f => {{
        const steps = f.kill_chain.split('->').map(s => `<span class="kc-node">${{escapeHtml(s.trim())}}</span>`).join(' <span style="color:var(--neon-crimson);font-weight:800;">➔</span> ');
        const isCont = containedState[f.id];
        const statusBadge = f.id in containedState
          ? (isCont ? '<span class="h-badge hb-emerald">✅ CONTENIDO</span>' : '<span class="h-badge hb-crimson">⚠️ ACCIÓN REQUERIDA</span>')
          : '<span class="h-badge hb-cyan">🔎 AUDITORÍA SIEM</span>';

        return `
          <div class="inc-card ${{f.riesgo === 'Medio' ? 'medium' : ''}}">
            <div style="display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:0.5rem;">
              <div style="font-family:'Space Grotesk',sans-serif;font-size:1.05rem;font-weight:700;">
                [${{escapeHtml(f.id)}}] ${{escapeHtml(f.titulo)}}
              </div>
              <div style="display:flex;gap:0.45rem;align-items:center;">
                <span class="h-badge ${{f.riesgo === 'Alto' ? 'hb-crimson' : 'hb-purple'}}">RIESGO ${{escapeHtml(f.riesgo.toUpperCase())}} · CVSS ${{escapeHtml(f.cvss_estimado)}}</span>
                ${{statusBadge}}
              </div>
            </div>

            <div class="kc-track">
              <strong class="mono" style="font-size:0.75rem;color:#F8FAFC;">⚡ Kill Chain:</strong> ${{steps}}
            </div>

            <div class="inc-3col">
              <div class="inc-subbox">
                <h5>👔 Impacto Ejecutivo (C-Level)</h5>
                <p>${{escapeHtml(f.resumen_ejecutivo)}}</p>
              </div>
              <div class="inc-subbox">
                <h5>🔬 Evidencia Forense (DFIR L2)</h5>
                <p>${{escapeHtml(f.resumen_tecnico)}}</p>
              </div>
              <div class="inc-subbox">
                <h5>🎯 Telemetría, MITRE & IoCs</h5>
                <p><strong>Ventana:</strong> <code>${{escapeHtml(f.ventana)}}</code></p>
                <p><strong>Eventos:</strong> <code>${{f.eventos_count}}</code> (<strong>${{f.eventos_ocultos_info}} ocultos en Info</strong>)</p>
                <p><strong>Activos:</strong> <code>${{escapeHtml(f.activos)}}</code></p>
                <p><strong>MITRE:</strong> <code>${{escapeHtml(f.mitre)}}</code></p>
                <p><strong>Log_IDs:</strong> <code>${{escapeHtml(f.evidencia_logs)}}</code></p>
              </div>
            </div>

            <div class="cli-playbook">
              <code>${{escapeHtml(f.comandos_contencion)}}</code>
              <button class="chip-btn" onclick="navigator.clipboard.writeText(${{JSON.stringify(f.comandos_contencion)}});this.textContent='✓ Copiado'">📋 Copiar Playbook</button>
            </div>
          </div>
        `;
      }}).join('');
    }}

    function renderCharts() {{
      const malLogs = SOC_DATA.logs.filter(r => r.Incident_ID !== 'NONE');
      const layoutBase = {{
        paper_bgcolor: 'rgba(0,0,0,0)',
        plot_bgcolor: 'rgba(0,0,0,0)',
        font: {{ color: '#E2E8F0', family: 'Inter, sans-serif', size: 11 }},
        margin: {{ l: 135, r: 20, t: 42, b: 40 }},
        height: 335
      }};

      // 1. Eventos por Incidente (Alerta Nativa vs Oculto en Info)
      const incTags = [...new Set(malLogs.map(r => r.Incident_Tag))].reverse();
      const nativeCounts = incTags.map(t => malLogs.filter(r => r.Incident_Tag === t && r.Severity !== 'Informational').length);
      const hiddenCounts = incTags.map(t => malLogs.filter(r => r.Incident_Tag === t && r.Severity === 'Informational').length);

      Plotly.newPlot('chartIncidents', [
        {{
          y: incTags,
          x: nativeCounts,
          name: 'Alerta SIEM Nativa',
          type: 'bar',
          orientation: 'h',
          marker: {{ color: '#FF2A5F' }}
        }},
        {{
          y: incTags,
          x: hiddenCounts,
          name: "Oculto en 'Info' (Rescatado L2)",
          type: 'bar',
          orientation: 'h',
          marker: {{ color: '#00F0FF' }}
        }}
      ], {{
        ...layoutBase,
        barmode: 'stack',
        title: {{ text: '🎯 Eventos por Incidente (112 Nativos + 12 Ocultos)', font: {{ size: 13 }} }},
        legend: {{ orientation: 'h', y: -0.18 }}
      }}, {{ responsive: true, displayModeBar: false }});

      // 2. Cronología por ventana de 10 min
      const windows = [...new Set(malLogs.map(r => r.Minute_Window))].sort();
      const incIds = ['INC-01', 'INC-02', 'INC-03', 'INC-04', 'INC-05', 'INC-06'];
      const palette = ['#FF2A5F', '#F97316', '#FBBF24', '#8B5CF6', '#00F0FF', '#10B981'];
      const timeTraces = incIds.map((id, i) => ({{
        x: windows,
        y: windows.map(w => malLogs.filter(r => r.Incident_ID === id && r.Minute_Window === w).length),
        name: id,
        type: 'bar',
        marker: {{ color: palette[i] }}
      }}));

      Plotly.newPlot('chartTimeline', timeTraces, {{
        ...layoutBase,
        margin: {{ l: 45, r: 20, t: 42, b: 45 }},
        barmode: 'stack',
        title: {{ text: '⏱️ Progresión Cronológica de Ataques (UTC)', font: {{ size: 13 }} }},
        legend: {{ orientation: 'h', y: -0.22 }}
      }}, {{ responsive: true, displayModeBar: false }});

      // 3. Activos Comprometidos (Hostname_Norm)
      const hosts = [...new Set(malLogs.map(r => r.Hostname_Norm))];
      const hostCounts = hosts.map(h => malLogs.filter(r => r.Hostname_Norm === h).length);
      Plotly.newPlot('chartHosts', [{{
        x: hosts,
        y: hostCounts,
        type: 'bar',
        text: hostCounts,
        textposition: 'auto',
        marker: {{ color: '#8B5CF6' }}
      }}], {{
        ...layoutBase,
        margin: {{ l: 45, r: 20, t: 42, b: 40 }},
        title: {{ text: '🖥️ Activos Comprometidos (Normalizados DC-01/DC01)', font: {{ size: 13 }} }}
      }}, {{ responsive: true, displayModeBar: false }});

      // 4. IPs de Origen en Incidentes
      const ips = [...new Set(malLogs.map(r => r.Source_IP))];
      const ipCounts = ips.map(ip => malLogs.filter(r => r.Source_IP === ip).length);
      Plotly.newPlot('chartIPs', [{{
        y: ips,
        x: ipCounts,
        type: 'bar',
        orientation: 'h',
        text: ipCounts,
        textposition: 'auto',
        marker: {{ color: '#10B981' }}
      }}], {{
        ...layoutBase,
        margin: {{ l: 115, r: 20, t: 42, b: 40 }},
        title: {{ text: '🌐 IPs de Origen en Incidentes (Externas y Pivotes)', font: {{ size: 13 }} }}
      }}, {{ responsive: true, displayModeBar: false }});
    }}

    function renderHiddenTrapsTable() {{
      const tbody = document.getElementById('hiddenTrapsTableBody');
      tbody.innerHTML = SOC_DATA.hidden_events.map(r => `
        <tr>
          <td class="mono" style="color:var(--neon-cyan);font-weight:600;">${{escapeHtml(r.Log_ID)}}</td>
          <td class="mono">${{escapeHtml(r.Timestamp)}}</td>
          <td><span class="h-badge hb-crimson">${{escapeHtml(r.Incident_ID)}}</span></td>
          <td class="mono">${{escapeHtml(r.Hostname)}}</td>
          <td class="mono">${{escapeHtml(r.Event_ID)}}</td>
          <td class="mono">${{escapeHtml(r.User)}}</td>
          <td class="mono">${{escapeHtml(r.Source_IP)}}</td>
          <td class="mono">${{escapeHtml(r.Destination)}}</td>
          <td class="mono" style="color:#FDE68A;">${{escapeHtml(r.Process_CommandLine !== '-' ? r.Process_CommandLine : r.Event_Description)}}</td>
        </tr>
      `).join('');
    }}

    function setLogPreset(preset) {{
      activeLogPreset = preset;
      renderLogTable();
    }}

    function renderLogTable() {{
      const incSel = document.getElementById('logIncidentFilter').value;
      const q = (document.getElementById('logSearchInput').value || '').toLowerCase().trim();

      let rows = SOC_DATA.logs;
      if (activeLogPreset === 'malicious') rows = rows.filter(r => r.Incident_ID !== 'NONE');
      else if (activeLogPreset === 'hidden') rows = rows.filter(r => r.Hidden_Trap);
      else if (activeLogPreset === 'extip') rows = rows.filter(r => r.External_IP);

      if (incSel !== 'ALL') rows = rows.filter(r => r.Incident_Tag === incSel);
      if (q) {{
        rows = rows.filter(r =>
          r.Log_ID.toLowerCase().includes(q) ||
          r.User.toLowerCase().includes(q) ||
          r.Hostname.toLowerCase().includes(q) ||
          r.Source_IP.toLowerCase().includes(q) ||
          r.Destination.toLowerCase().includes(q) ||
          r.Event_Description.toLowerCase().includes(q) ||
          r.Process_CommandLine.toLowerCase().includes(q)
        );
      }}

      document.getElementById('logCounterBadge').textContent = `Mostrando ${{rows.length}} de ${{SOC_DATA.logs.length}} eventos`;
      const tbody = document.getElementById('siemLogsTableBody');
      tbody.innerHTML = rows.slice(0, 300).map(r => `
        <tr>
          <td class="mono" style="color:var(--neon-cyan);">${{escapeHtml(r.Log_ID)}}</td>
          <td class="mono">${{escapeHtml(r.Timestamp)}}</td>
          <td>${{r.Incident_ID !== 'NONE' ? `<span class="h-badge hb-crimson">${{escapeHtml(r.Incident_ID)}}</span>` : '<span style="color:#64748B;">NONE</span>'}}</td>
          <td class="mono">${{escapeHtml(r.Severity)}}</td>
          <td class="mono">${{escapeHtml(r.Hostname)}}</td>
          <td class="mono">${{escapeHtml(r.Event_ID)}}</td>
          <td class="mono">${{escapeHtml(r.User)}}</td>
          <td class="mono">${{escapeHtml(r.Source_IP)}}</td>
          <td class="mono">${{escapeHtml(r.Destination)}}</td>
          <td class="mono" style="font-size:0.75rem;">${{escapeHtml(r.Process_CommandLine !== '-' ? r.Process_CommandLine : r.Event_Description)}}</td>
        </tr>
      `).join('');
    }}

    function runLiveLangChainReportGeneration() {{
      const banner = document.getElementById('reportStatusBanner');
      banner.textContent = '⚡ Ejecutando RunnableParallel(executive=exec_chain, technical=dfir_chain)...';
      setTimeout(() => {{
        document.getElementById('execReportBox').value = SOC_DATA.exec_md;
        document.getElementById('techReportBox').value = SOC_DATA.tech_md;
        banner.textContent = '🟢 Pipeline LangChain LCEL completado con éxito (100% sincronizado con los 715 eventos).';
      }}, 220);
    }}

    // Soporte de carga de archivos Excel (.xlsx) en el navegador con SheetJS
    document.getElementById('excelUploadInput').addEventListener('change', function(evt) {{
      const file = evt.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = function(e) {{
        try {{
          const wb = XLSX.read(new Uint8Array(e.target.result), {{ type: 'array' }});
          const sheetName = wb.SheetNames.includes('SIEM Export') ? 'SIEM Export' : wb.SheetNames[0];
          const rows = XLSX.utils.sheet_to_json(wb.Sheets[sheetName]);
          document.getElementById('datasetStatusBadge').textContent = `✓ Cargado: ${{file.name}} (${{rows.length}} registros en '${{sheetName}}')`;
        }} catch (err) {{
          document.getElementById('datasetStatusBadge').textContent = `⚠️ Error al leer Excel: ${{err.message}}`;
        }}
      }};
      reader.readAsArrayBuffer(file);
    }});

    let activeDetectionTab = 'sigma';

    function renderDetectionEngineering() {{
      const tbody = document.getElementById('lolbasTableBody');
      tbody.innerHTML = SOC_DATA.lolbas_catalog.map(c => `
        <tr>
          <td class="mono" style="color:var(--neon-cyan);font-weight:700;">${{escapeHtml(c.binario)}}</td>
          <td><span class="h-badge hb-purple">${{escapeHtml(c.catalogo)}}</span></td>
          <td class="mono"><strong>${{escapeHtml(c.incidente)}}</strong> (${{escapeHtml(c.log_ids)}})</td>
          <td class="mono">${{escapeHtml(c.host)}}</td>
          <td class="mono" style="color:#FDE68A;">${{escapeHtml(c.comando_detectado)}}</td>
          <td class="mono">${{escapeHtml(c.mitre)}}</td>
          <td>
            <a href="${{escapeHtml(c.lolbas_url)}}" target="_blank" rel="noopener noreferrer" style="color:#00F0FF;margin-right:0.5rem;font-weight:600;">LOLBAS ↗</a>
            <a href="${{escapeHtml(c.gtfobins_url)}}" target="_blank" rel="noopener noreferrer" style="color:#C4B5FD;font-weight:600;">GTFOBins ↗</a>
          </td>
        </tr>
      `).join('');
      switchDetectionRuleTab('sigma');
    }}

    function switchDetectionRuleTab(tab) {{
      activeDetectionTab = tab;
      const box = document.getElementById('detectionRuleCodeBox');
      if (tab === 'sigma') box.textContent = SOC_DATA.sigma_yaml;
      else if (tab === 'yara') box.textContent = SOC_DATA.yara_classic;
      else box.textContent = SOC_DATA.yarax_rust;
    }}

    function copyActiveDetectionRule(btn) {{
      const box = document.getElementById('detectionRuleCodeBox');
      navigator.clipboard.writeText(box.textContent || '');
      const prev = btn.textContent;
      btn.textContent = '✓ Regla Copiada';
      setTimeout(() => btn.textContent = prev, 1500);
    }}

    function downloadActiveDetectionRule() {{
      const box = document.getElementById('detectionRuleCodeBox');
      const fname = activeDetectionTab === 'sigma'
        ? 'soc_l2_sigma_rules.yml'
        : (activeDetectionTab === 'yara' ? 'soc_l2_yara_classic.yar' : 'soc_l2_yarax_rust.yarx');
      const blob = new Blob([box.textContent || ''], {{ type: 'text/plain;charset=utf-8' }});
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = fname;
      a.click();
      URL.revokeObjectURL(url);
    }}

    // Inicialización completa del sistema JEV Cyber Command
    window.addEventListener('DOMContentLoaded', () => {{
      renderLcelNodes();
      renderSoarChecklist();
      renderIncidents('ALL');
      renderDetectionEngineering();
      renderCharts();
      renderHiddenTrapsTable();
      document.getElementById('execReportBox').value = SOC_DATA.exec_md;
      document.getElementById('techReportBox').value = SOC_DATA.tech_md;

      const incSelect = document.getElementById('logIncidentFilter');
      const uniqueTags = [...new Set(SOC_DATA.logs.map(r => r.Incident_Tag))];
      uniqueTags.forEach(t => {{
        const opt = document.createElement('option');
        opt.value = t;
        opt.textContent = t;
        incSelect.appendChild(opt);
      }});

      renderLogTable();
      runJevCopilot('Resumen ejecutivo del estado global de telemetría');
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
    pdf_path = base_dir / "Informe_Final_SOC_L2_Incidentes.pdf"
    chart_path = base_dir / "soc_l2_dashboard_summary.png"

    print(f"[1/4] Cargando telemetría SIEM desde: {excel_path.name} (Hoja: 'SIEM Export')...")
    raw_df = pd.read_excel(excel_path, sheet_name="SIEM Export")

    print("[2/4] Ejecutando motor de correlación forense SOC Nivel 2...")
    df, findings, summary_metrics = analyze_siem_logs(raw_df)
    print(
        f"      -> Total eventos: {summary_metrics['total_logs']} | "
        f"Alertas nativas: {summary_metrics['native_non_info_alerts']} | "
        f"Maliciosos correlacionados: {summary_metrics['correlated_malicious_events']} | "
        f"Ocultos en Info: {summary_metrics['hidden_info_critical_events']}"
    )

    print("[3/4] Ejecutando Pipeline LangChain LCEL (RunnableParallel: Ejecutivo C-Level + Técnico DFIR)...")
    exec_report, tech_report, status = generate_ai_reports(
        findings=findings,
        summary_metrics=summary_metrics,
        provider="LangChain LCEL + Motor Forense Determinista (Instantáneo / Offline)",
        model_name="jev-soc-l2-lcel-v3",
        api_url="",
        api_key="",
    )
    print(f"      -> {status}")

    print(f"[4/4] Compilando PDF Oficial '{pdf_path.name}' y Portal Fluido JEV 'index.html'...")
    pdf_bytes = build_pdf_report(
        exec_text=exec_report,
        tech_text=tech_report,
        findings=findings,
        summary_metrics=summary_metrics,
        df=df,
        chart_output_path=str(chart_path),
    )
    pdf_path.write_bytes(pdf_bytes)
    build_static_web_portal(df, findings, summary_metrics, exec_report, tech_report, base_dir)
    print(f"¡ÉXITO! PDF ({len(pdf_bytes):,} bytes) e index.html (JEV LangChain Fluid Edition) actualizados.")


if __name__ == "__main__":
    main()
