"""
Motor Profesional de Exportación a PDF (Ejecutivo + Técnico Forense SOC Nivel 2).
Genera gráficos analíticos de alta resolución con validaciones defensivas e incrusta
portada ejecutiva, tarjetas de KPIs, matriz MITRE ATT&CK, desglose forense de los
incidentes, auditoría de eventos críticos ocultos ('Informational') y playbooks CLI.
"""

from __future__ import annotations
import io
from datetime import datetime
from typing import List, Dict, Any
from xml.sax.saxutils import escape

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    Image,
    KeepTogether,
)


def generate_dashboard_chart_png(df: pd.DataFrame, output_path: str = "soc_l2_dashboard_summary.png") -> bytes:
    """
    Genera el panel cuádruple de visualización forense (Línea de tiempo, IPs de origen,
    Eventos por Incidente Correlacionado y Activos Afectados) con validaciones defensivas
    contra DataFrames parciales o vacíos, y lo retorna en bytes PNG.
    """
    plt.rcParams["font.sans-serif"] = "DejaVu Sans"
    fig, axes = plt.subplots(2, 2, figsize=(14, 9.5), dpi=160)
    fig.patch.set_facecolor("#F8FAFC")
    total_events = len(df)
    inc_df = df[df["Incident_ID"] != "NONE"].copy()
    corr_count = len(inc_df)

    fig.suptitle(
        f"Telemetría Forense SIEM — Análisis de Incidentes SOC Nivel 2 ({total_events} Eventos | {corr_count} Correlacionados)",
        fontsize=13.5,
        fontweight="bold",
        color="#0F172A",
        y=0.97,
    )

    # 1. Línea de Tiempo de Alertas (10-min intervals)
    ax1 = axes[0, 0]
    ax1.set_facecolor("#FFFFFF")
    non_info = df[df["Severity"] != "Informational"].copy()
    if not non_info.empty and "Hour_Min_10" in non_info.columns:
        timeline = non_info.groupby(["Hour_Min_10", "Severity"]).size().unstack(fill_value=0)
        for sev in ["Warning", "Medium", "High"]:
            if sev not in timeline.columns:
                timeline[sev] = 0
        timeline = timeline[["Warning", "Medium", "High"]]
        timeline.plot(
            kind="bar",
            stacked=True,
            ax=ax1,
            color=["#F59E0B", "#EA580C", "#DC2626"],
            width=0.78,
        )
        ax1.set_xticklabels([t.strftime("%H:%M") for t in timeline.index], rotation=40, ha="right", fontsize=8)
        ax1.legend(title="Severidad", fontsize=8, title_fontsize=8)
    else:
        ax1.text(0.5, 0.5, "Sin alertas No-Informational", ha="center", va="center", fontsize=10)
    ax1.set_title("1. Línea de Tiempo de Alertas SIEM (No-Informational)", fontweight="bold", fontsize=10.5, color="#1E293B")
    ax1.set_xlabel("Ventana Temporal (UTC)", fontsize=9)
    ax1.set_ylabel("Eventos", fontsize=9)
    ax1.grid(axis="y", linestyle="--", alpha=0.4)

    # 2. Eventos Correlacionados por Incidente Detectado (incluyendo ocultos en Informational)
    ax2 = axes[0, 1]
    ax2.set_facecolor("#FFFFFF")
    if not inc_df.empty:
        inc_counts = inc_df.groupby(["Incident_ID", "Severity"]).size().unstack(fill_value=0)
        for col in ["Informational", "Warning", "Medium", "High"]:
            if col not in inc_counts.columns:
                inc_counts[col] = 0
        inc_counts["Total"] = inc_counts.sum(axis=1)
        inc_counts = inc_counts.sort_values("Total", ascending=True)
        inc_labels = {
            "INC-01": "INC-01: Password Spraying (DC-01)",
            "INC-02": "INC-02: Intrusión RDP & Lateral (admin)",
            "INC-03": "INC-03: Pre-Ransomware VSS (backupsvc)",
            "INC-04": "INC-04: Exfiltración Legal (rrojas)",
            "INC-05": "INC-05: Persistencia Dual (helpdesk)",
            "INC-06": "INC-06: Webshell & RCE IIS (WEB-01)",
        }
        inc_counts.index = [inc_labels.get(idx, idx) for idx in inc_counts.index]
        inc_counts[["Warning", "Medium", "High", "Informational"]].plot(
            kind="barh",
            stacked=True,
            ax=ax2,
            color=["#F59E0B", "#EA580C", "#DC2626", "#2563EB"],
            width=0.72,
        )
        ax2.legend(["Warning", "Medium", "High", "Oculto en Info"], fontsize=7.5, loc="lower right")
    else:
        ax2.text(0.5, 0.5, "Sin incidentes correlacionados", ha="center", va="center", fontsize=10)
    ax2.set_title("2. Eventos por Incidente (Azul = Críticos Ocultos en 'Info')", fontweight="bold", fontsize=10.5, color="#1E293B")
    ax2.set_xlabel(f"Eventos Correlacionados (Total: {corr_count})", fontsize=9)
    ax2.set_ylabel("")
    ax2.grid(axis="x", linestyle="--", alpha=0.4)

    # 3. Distribución de Alertas por IP de Origen
    ax3 = axes[1, 0]
    ax3.set_facecolor("#FFFFFF")
    if not df.empty:
        ip_sev = df.groupby(["Source_IP", "Severity"]).size().unstack(fill_value=0)
        for col in ["Informational", "Warning", "Medium", "High"]:
            if col not in ip_sev.columns:
                ip_sev[col] = 0
        ip_sev["Alerts"] = ip_sev["Warning"] + ip_sev["Medium"] + ip_sev["High"]
        ip_sev = ip_sev.sort_values(by=["Alerts", "Informational"], ascending=True).tail(12)
        ip_sev[["Informational", "Warning", "Medium", "High"]].plot(
            kind="barh",
            stacked=True,
            ax=ax3,
            color=["#94A3B8", "#F59E0B", "#EA580C", "#DC2626"],
            width=0.75,
        )
        ax3.legend(title="Severidad", fontsize=7.5, title_fontsize=8)
    ax3.set_title("3. Distribución de Eventos y Alertas por IP de Origen", fontweight="bold", fontsize=10.5, color="#1E293B")
    ax3.set_xlabel("Total de Eventos", fontsize=9)
    ax3.set_ylabel("Source IP", fontsize=9)
    ax3.grid(axis="x", linestyle="--", alpha=0.4)

    # 4. Activos Más Afectados por Eventos de Incidentes Correlacionados (Hostname_Norm)
    ax4 = axes[1, 1]
    ax4.set_facecolor("#FFFFFF")
    host_col = "Hostname_Norm" if "Hostname_Norm" in inc_df.columns else "Hostname"
    if not inc_df.empty:
        host_inc = inc_df.groupby([host_col, "Severity"]).size().unstack(fill_value=0)
        for col in ["Informational", "Warning", "Medium", "High"]:
            if col not in host_inc.columns:
                host_inc[col] = 0
        host_inc["Total"] = host_inc.sum(axis=1)
        host_inc = host_inc.sort_values(by="Total", ascending=True)
        host_inc[["Warning", "Medium", "High", "Informational"]].plot(
            kind="barh",
            stacked=True,
            ax=ax4,
            color=["#F59E0B", "#EA580C", "#DC2626", "#2563EB"],
            width=0.72,
        )
        ax4.legend(["Warning", "Medium", "High", "Oculto en Info"], fontsize=7.5, loc="lower right")
    else:
        ax4.text(0.5, 0.5, "Sin activos afectados", ha="center", va="center", fontsize=10)
    ax4.set_title("4. Servidores y Estaciones Comprometidas (Normalizado)", fontweight="bold", fontsize=10.5, color="#1E293B")
    ax4.set_xlabel("Eventos Maliciosos Asociados", fontsize=9)
    ax4.set_ylabel("Hostname", fontsize=9)
    ax4.grid(axis="x", linestyle="--", alpha=0.4)

    plt.tight_layout(rect=[0, 0.02, 1, 0.94])
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=160)
    png_bytes = buf.getvalue()
    if output_path:
        try:
            with open(output_path, "wb") as f:
                f.write(png_bytes)
        except Exception:
            pass
    plt.close(fig)
    return png_bytes


def _draw_header_footer(canvas, doc):
    """Dibuja barra superior corporativa y pie de página numerado en cada hoja."""
    canvas.saveState()
    width, height = letter

    # Barra superior oscura SOC L2
    canvas.setFillColor(colors.HexColor("#0F172A"))
    canvas.rect(0, height - 28, width, 28, fill=1, stroke=0)
    canvas.setFillColor(colors.HexColor("#F8FAFC"))
    canvas.setFont("Helvetica-Bold", 8.5)
    canvas.drawString(36, height - 18, "CENTRO DE OPERACIONES DE SEGURIDAD (SOC NIVEL 2) — INFORME FORENSE Y EJECUTIVO")
    canvas.setFillColor(colors.HexColor("#F59E0B"))
    canvas.drawRightString(width - 36, height - 18, "CLASIFICACIÓN: TLP:AMBER+STRICT")

    # Pie de página
    canvas.setStrokeColor(colors.HexColor("#CBD5E1"))
    canvas.setLineWidth(0.6)
    canvas.line(36, 34, width - 36, 34)
    canvas.setFillColor(colors.HexColor("#475569"))
    canvas.setFont("Helvetica", 8)
    canvas.drawString(36, 21, "Bootcamp SOC Nivel 2 — Análisis de Incidentes asistido por IA Generativa y Correlación Forense")
    canvas.drawRightString(width - 36, 21, f"Página {doc.page}")
    canvas.restoreState()


def build_pdf_report(
    exec_text: str,
    tech_text: str,
    findings: List[Dict[str, Any]],
    summary_metrics: Dict[str, Any],
    df: pd.DataFrame,
    chart_output_path: str = "soc_l2_dashboard_summary.png",
) -> bytes:
    """
    Construye el archivo PDF oficial unificado (Informe Ejecutivo + Informe Técnico Detallado +
    Matriz MITRE ATT&CK + Gráficos Forenses + Tabla de Eventos Críticos Ocultos en Informational).
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=44,
        bottomMargin=46,
        title="Informe Final SOC Nivel 2 - Analisis de Incidentes",
        author="Analista SOC Nivel 2 - AI Incident Analyzer",
    )

    styles = getSampleStyleSheet()
    style_title = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=17,
        leading=21,
        textColor=colors.HexColor("#FFFFFF"),
        alignment=0,
    )
    style_subtitle = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=13,
        textColor=colors.HexColor("#E2E8F0"),
    )
    style_h1 = ParagraphStyle(
        "SecH1",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12.5,
        leading=16,
        textColor=colors.HexColor("#0F172A"),
        spaceBefore=10,
        spaceAfter=6,
    )
    style_h2 = ParagraphStyle(
        "SecH2",
        parent=styles["Heading3"],
        fontName="Helvetica-Bold",
        fontSize=10.5,
        leading=14,
        textColor=colors.HexColor("#1E3A8A"),
        spaceBefore=8,
        spaceAfter=4,
    )
    style_body = ParagraphStyle(
        "Body",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9.2,
        leading=13.2,
        textColor=colors.HexColor("#1E293B"),
        spaceAfter=5,
    )
    style_small = ParagraphStyle(
        "SmallCell",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.0,
        leading=10.5,
        textColor=colors.HexColor("#1E293B"),
    )
    style_small_bold = ParagraphStyle(
        "SmallCellBold",
        parent=style_small,
        fontName="Helvetica-Bold",
        textColor=colors.HexColor("#0F172A"),
    )
    style_header_cell = ParagraphStyle(
        "HeaderCell",
        parent=style_small_bold,
        textColor=colors.HexColor("#FFFFFF"),
    )
    style_code = ParagraphStyle(
        "CodeBlock",
        parent=styles["Code"],
        fontName="Courier",
        fontSize=7.8,
        leading=10.2,
        textColor=colors.HexColor("#0F172A"),
        backColor=colors.HexColor("#F1F5F9"),
        borderPadding=5,
        leftIndent=4,
        rightIndent=4,
        spaceAfter=6,
    )

    story = []
    high_cnt = summary_metrics.get("critical_incidents_count", 6)
    med_cnt = summary_metrics.get("medium_findings_count", 1)

    # =========================================================================
    # BLOQUE DE PORTADA / BANNER EJECUTIVO
    # =========================================================================
    banner_html = (
        "<b>INFORME DE AUDITORÍA FORENSE Y RESPUESTA A INCIDENTES (SOC NIVEL 2)</b><br/>"
        "<font size='9.5' color='#93C5FD'>Análisis Multi-Incidente asistido por IA Generativa, Correlación Heurística y Mapeo MITRE ATT&amp;CK</font>"
    )
    meta_html = (
        f"<b>Dataset Auditado:</b> SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx (Hoja: SIEM Export) &nbsp;|&nbsp; "
        f"<b>Ventana de Logs:</b> {escape(str(summary_metrics['time_start']))} a {escape(str(summary_metrics['time_end']))}<br/>"
        f"<b>Fecha de Emisión:</b> {datetime.now().strftime('%Y-%m-%d %H:%M UTC-5')} &nbsp;|&nbsp; "
        f"<b>Estado de Contención:</b> CRÍTICO — {high_cnt} Incidentes de Riesgo Alto + {med_cnt} Observación de Visibilidad SIEM"
    )
    banner_table = Table(
        [[Paragraph(banner_html, style_title)], [Paragraph(meta_html, style_subtitle)]],
        colWidths=[540],
    )
    banner_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0F172A")),
                ("TOPPADDING", (0, 0), (-1, 0), 12),
                ("BOTTOMPADDING", (0, -1), (-1, -1), 12),
                ("LEFTPADDING", (0, 0), (-1, -1), 14),
                ("RIGHTPADDING", (0, 0), (-1, -1), 14),
                ("LINEBELOW", (0, -1), (-1, -1), 3, colors.HexColor("#DC2626")),
            ]
        )
    )
    story.append(banner_table)
    story.append(Spacer(1, 10))

    # =========================================================================
    # TARJETAS DE MÉTRICAS CLAVE (KPIs)
    # =========================================================================
    kpi_style_num = ParagraphStyle(
        "KpiNum", parent=style_body, fontName="Helvetica-Bold", fontSize=13, leading=15, alignment=1, textColor=colors.HexColor("#0F172A")
    )
    kpi_style_lbl = ParagraphStyle(
        "KpiLbl", parent=style_small, fontSize=7.5, leading=9.5, alignment=1, textColor=colors.HexColor("#475569")
    )
    kpi_data = [
        [
            Paragraph(f"{summary_metrics['total_logs']}", kpi_style_num),
            Paragraph(f"{summary_metrics['native_non_info_alerts']}", kpi_style_num),
            Paragraph(f"<font color='#DC2626'>{summary_metrics['correlated_malicious_events']}</font>", kpi_style_num),
            Paragraph(f"<font color='#2563EB'>{summary_metrics['hidden_info_critical_events']}</font>", kpi_style_num),
            Paragraph(f"<font color='#DC2626'>{high_cnt} ALTOS / {med_cnt} MEDIO</font>", kpi_style_num),
            Paragraph(f"<font color='#B91C1C'>{summary_metrics['exfil_mib']} MiB</font>", kpi_style_num),
        ],
        [
            Paragraph("Eventos SIEM<br/>Analizados", kpi_style_lbl),
            Paragraph("Alertas Nativas<br/>SIEM (No-Info)", kpi_style_lbl),
            Paragraph("Eventos Maliciosos<br/>Correlacionados", kpi_style_lbl),
            Paragraph("Eventos Críticos<br/>Ocultos en 'Info'", kpi_style_lbl),
            Paragraph("Clasificación<br/>de Incidentes", kpi_style_lbl),
            Paragraph(f"Exfiltración HTTPS<br/>({summary_metrics['exfil_mb']} MB)", kpi_style_lbl),
        ],
    ]
    kpi_table = Table(kpi_data, colWidths=[90, 90, 90, 90, 90, 90])
    kpi_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F1F5F9")),
                ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("TOPPADDING", (0, 0), (-1, 0), 7),
                ("BOTTOMPADDING", (0, 1), (-1, 1), 7),
            ]
        )
    )
    story.append(kpi_table)
    story.append(Spacer(1, 10))

    # =========================================================================
    # SECCIÓN 1: INFORME EJECUTIVO (PARA ALTA DIRECCIÓN / C-LEVEL)
    # =========================================================================
    story.append(Paragraph("SECCIÓN 1 — RESUMEN EJECUTIVO (ENFOQUE DIRECTIVO Y DE NEGOCIO)", style_h1))
    for line in exec_text.splitlines():
        clean = escape(line.strip())
        if not clean:
            story.append(Spacer(1, 3))
            continue
        if clean.startswith(("1.", "2.", "3.", "RESUMEN", "IMPACTO", "DECISIONES", "#")):
            story.append(Paragraph(f"<b>{clean.lstrip('# ').strip()}</b>", style_h2))
        elif clean.startswith(("-", "•", "*")):
            story.append(Paragraph(f"&bull; {clean.lstrip('-•* ').strip()}", style_body))
        else:
            story.append(Paragraph(clean, style_body))

    story.append(Spacer(1, 8))

    # =========================================================================
    # SECCIÓN 2: MATRIZ CONSOLIDADA DE RIESGO Y MAPEO MITRE ATT&CK
    # =========================================================================
    story.append(Paragraph("SECCIÓN 2 — MATRIZ EJECUTIVA DE CLASIFICACIÓN DE RIESGO Y MITRE ATT&CK", style_h1))
    matrix_rows = [
        [
            Paragraph("ID", style_header_cell),
            Paragraph("Incidente / Hallazgo Detectado", style_header_cell),
            Paragraph("Ventana (UTC)", style_header_cell),
            Paragraph("Activos y Cuentas", style_header_cell),
            Paragraph("Técnicas MITRE ATT&amp;CK", style_header_cell),
            Paragraph("Eventos (Info)", style_header_cell),
            Paragraph("Riesgo", style_header_cell),
        ]
    ]
    for f in findings:
        risk_color = "#DC2626" if f["riesgo"] == "Alto" else "#D97706"
        matrix_rows.append(
            [
                Paragraph(f"<b>{escape(f['id'])}</b>", style_small_bold),
                Paragraph(escape(f["titulo"]), style_small),
                Paragraph(escape(f["ventana"].replace("2026-10-23 ", "")), style_small),
                Paragraph(escape(f"{f['activos']} | {f['usuarios'][:48]}"), style_small),
                Paragraph(escape(f["mitre"]), style_small),
                Paragraph(f"{f['eventos_count']} ({f['eventos_ocultos_info']})", style_small),
                Paragraph(f"<font color='{risk_color}'><b>{escape(f['riesgo'].upper())}</b></font>", style_small_bold),
            ]
        )

    matrix_table = Table(matrix_rows, colWidths=[42, 136, 72, 105, 95, 45, 45], repeatRows=1)
    matrix_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#FFFFFF"), colors.HexColor("#F8FAFC")]),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.append(matrix_table)

    # Salto a Página 2 con el Panel Visual Forense
    story.append(PageBreak())
    story.append(Paragraph("SECCIÓN 3 — VISUALIZACIÓN ANALÍTICA Y DASHBOARD FORENSE DE TELEMETRÍA", style_h1))
    story.append(
        Paragraph(
            f"El siguiente panel consolida la distribución temporal de alertas, los {summary_metrics['correlated_malicious_events']} "
            f"eventos correlacionados en los {high_cnt} incidentes críticos (destacando en azul los "
            f"{summary_metrics['hidden_info_critical_events']} eventos críticos que estaban ocultos bajo severidad "
            "<i>Informational</i>), el volumen por IP de origen y los activos corporativos comprometidos:",
            style_body,
        )
    )
    png_bytes = generate_dashboard_chart_png(df, output_path=chart_output_path)
    img_flowable = Image(io.BytesIO(png_bytes), width=535, height=363)
    story.append(img_flowable)
    story.append(Spacer(1, 10))

    # =========================================================================
    # TABLA DE AUDITORÍA DE "TRAMPAS DE NIVEL 2" (EVENTOS CRÍTICOS EN INFORMATIONAL)
    # =========================================================================
    story.append(
        Paragraph(
            "AUDITORÍA DE EVASIÓN Y VISIBILIDAD: EVENTOS CRÍTICOS ETIQUETADOS COMO 'INFORMATIONAL'",
            style_h2,
        )
    )
    story.append(
        Paragraph(
            "Un análisis superficial que filtre únicamente <i>Severity != Informational</i> omitiría la evidencia "
            f"de éxito de intrusión y preparación de exfiltración. La correlación SOC Nivel 2 rescató estos "
            f"{len(summary_metrics['hidden_events_records'])} registros:",
            style_body,
        )
    )
    hidden_rows = [
        [
            Paragraph("Log_ID", style_header_cell),
            Paragraph("Timestamp", style_header_cell),
            Paragraph("Incidente", style_header_cell),
            Paragraph("Host", style_header_cell),
            Paragraph("Event_ID", style_header_cell),
            Paragraph("Usuario", style_header_cell),
            Paragraph("IP Origen", style_header_cell),
            Paragraph("Comando / Destino / Relevancia Forense", style_header_cell),
        ]
    ]
    for rec in summary_metrics["hidden_events_records"]:
        cmd_or_dest = (
            rec["Process_CommandLine"]
            if rec["Process_CommandLine"] not in ("-", "explorer.exe", "")
            else f"Destino: {rec['Destination']}"
        )
        hidden_rows.append(
            [
                Paragraph(escape(str(rec["Log_ID"])), style_small_bold),
                Paragraph(escape(str(rec["Timestamp"]).replace("2026-10-23 ", "")), style_small),
                Paragraph(escape(str(rec["Incident_ID"])), style_small_bold),
                Paragraph(escape(str(rec["Hostname"])), style_small),
                Paragraph(escape(str(rec["Event_ID"])), style_small),
                Paragraph(escape(str(rec["User"])), style_small),
                Paragraph(escape(str(rec["Source_IP"])), style_small),
                Paragraph(escape(str(cmd_or_dest)), style_small),
            ]
        )
    if len(hidden_rows) > 1:
        hidden_table = Table(hidden_rows, colWidths=[52, 50, 44, 52, 44, 72, 66, 160], repeatRows=1)
        hidden_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E3A8A")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#EFF6FF"), colors.HexColor("#FFFFFF")]),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#BFDBFE")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 3.5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
                ]
            )
        )
        story.append(hidden_table)

    # =========================================================================
    # SECCIÓN 4: INFORME TÉCNICO FORENSE DETALLADO (INGENIERÍA SOC L2 / DFIR)
    # =========================================================================
    story.append(PageBreak())
    story.append(
        Paragraph(
            "SECCIÓN 4 — INFORME TÉCNICO DETALLADO (EVIDENCIA FORENSE, IOCs, MITRE ATT&CK Y REMEDIACIÓN)",
            style_h1,
        )
    )

    for f in findings:
        badge_bg = "#FEE2E2" if f["riesgo"] == "Alto" else "#FEF3C7"
        badge_fg = "#991B1B" if f["riesgo"] == "Alto" else "#92400E"
        header_box = Table(
            [
                [
                    Paragraph(
                        f"<font color='{badge_fg}'><b>[{escape(f['id'])}] {escape(f['titulo'])} — RIESGO {escape(f['riesgo'].upper())} ({escape(f['cvss_estimado'])})</b></font>",
                        style_small_bold,
                    )
                ]
            ],
            colWidths=[540],
        )
        header_box.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(badge_bg)),
                    ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor(badge_fg)),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ]
            )
        )

        details_html = (
            f"<b>Ventana de Tiempo:</b> {escape(f['ventana'])} &nbsp;|&nbsp; "
            f"<b>Kill Chain:</b> {escape(f['kill_chain'])}<br/>"
            f"<b>Activos Comprometidos:</b> {escape(f['activos'])} &nbsp;|&nbsp; "
            f"<b>Cuentas:</b> {escape(f['usuarios'])}<br/>"
            f"<b>Mapeo MITRE ATT&amp;CK:</b> {escape(f['mitre'])}<br/>"
            f"<b>Indicadores de Compromiso (IoCs):</b> {escape(f['ioc'])}<br/>"
            f"<b>Registros de Evidencia (Log_IDs):</b> {escape(f['evidencia_logs'])}<br/><br/>"
            f"<b>Análisis Forense Detallado:</b><br/>{escape(f['resumen_tecnico'])}<br/><br/>"
            f"<b>Plan de Contención y Remediación Paso a Paso:</b><br/>"
            + "<br/>".join(escape(line) for line in f["remediacion"].splitlines())
        )
        cmd_paragraph = Paragraph(
            f"<b>Playbook CLI / Regla de Contención:</b><br/>{escape(f['comandos_contencion'])}",
            style_code,
        )

        inc_block = KeepTogether(
            [
                header_box,
                Spacer(1, 4),
                Paragraph(details_html, style_body),
                cmd_paragraph,
                Spacer(1, 8),
            ]
        )
        story.append(inc_block)

    doc.build(story, onFirstPage=_draw_header_footer, onLaterPages=_draw_header_footer)
    return buffer.getvalue()
