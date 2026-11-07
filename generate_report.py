"""
Script CLI de generación directa del Informe Oficial en PDF y Gráficos Forenses.
Permite generar 'Informe_Final_SOC_L2_Incidentes.pdf' y 'soc_l2_dashboard_summary.png'
desde la terminal sin necesidad de abrir el navegador.
"""

import pandas as pd
from core.parser import analyze_siem_logs
from core.agents import generate_ai_reports
from core.pdf_generator import build_pdf_report


def main():
    excel_path = "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx"
    print(f"[*] Cargando archivo oficial: {excel_path} ...")
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

    pdf_path = "Informe_Final_SOC_L2_Incidentes.pdf"
    chart_path = "soc_l2_dashboard_summary.png"
    print(f"[*] Compilando PDF oficial ({pdf_path}) y panel gráfico ({chart_path})...")
    pdf_bytes = build_pdf_report(
        exec_rep,
        tech_rep,
        findings,
        summary_metrics,
        df,
        chart_output_path=chart_path,
    )
    with open(pdf_path, "wb") as f:
        f.write(pdf_bytes)

    print(f"[+] ¡Éxito! PDF generado en '{pdf_path}' ({len(pdf_bytes):,} bytes).")


if __name__ == "__main__":
    main()

