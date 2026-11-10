# 🛡️ SOC Nivel 2 — Plataforma de Análisis Forense e Incidentes con IA Generativa

[![Live Portal GitHub Pages](https://img.shields.io/badge/🌐_GitHub_Pages_(Live_App)-bckdrx--collab.github.io-2563EB?style=for-the-badge)](https://bckdrx-collab.github.io/soc-l2-incident-response/)
[![Descargar Informe PDF Oficial](https://img.shields.io/badge/📄_Informe_Oficial_PDF-Descargar_Directo-EF4444?style=for-the-badge)](https://bckdrx-collab.github.io/soc-l2-incident-response/Informe_Final_SOC_L2_Incidentes.pdf)

Proyecto final desarrollado para el **Bootcamp de Analista SOC Nivel 2 (Dojo Community)**.  
Esta aplicación automatiza la **ingesta de registros SIEM en Excel (`.xlsx`)**, ejecuta un **motor híbrido de correlación heurística + Inteligencia Artificial Generativa**, descubre **eventos críticos ocultos bajo severidad `Informational`**, construye un **Dashboard interactivo** (tanto en **Streamlit** como en **Web SPA en GitHub Pages `github.io`**) y exporta el **Informe Oficial en PDF (Resumen Ejecutivo C-Level + Informe Técnico Forense con mapeo MITRE ATT&CK)**.

### 🌐 Enlaces Publicados en Vivo (`github.io`)
- **Portal Web Interactivo (GitHub Pages Proyecto):** [https://bckdrx-collab.github.io/soc-l2-incident-response/](https://bckdrx-collab.github.io/soc-l2-incident-response/)
- **Portal Principal de Usuario (`bckdrx-collab.github.io`):** [https://bckdrx-collab.github.io/](https://bckdrx-collab.github.io/)
- **Descarga Directa del Informe PDF Oficial:** [Informe_Final_SOC_L2_Incidentes.pdf](https://bckdrx-collab.github.io/soc-l2-incident-response/Informe_Final_SOC_L2_Incidentes.pdf)
- **Repositorio de Código Fuente:** [https://github.com/bckdrx-collab/soc-l2-incident-response](https://github.com/bckdrx-collab/soc-l2-incident-response)

---

## 🏗️ Arquitectura Modular del Proyecto

```text
BOOTCAMP SOC L2/
├── app.py                                              # Dashboard interactivo en Streamlit + Plotly
├── generate_report.py                                  # Generador CLI unificado (PDF, PNG e index.html)
├── index.html                                          # Portal web interactivo estático para GitHub Pages
├── core/
│   ├── __init__.py
│   ├── parser.py                                       # Ingesta Excel, validación, normalización y correlación L2
│   ├── agents.py                                       # Agentes de IA (Ollama Local / OpenAI API / Motor Determinista)
│   └── pdf_generator.py                                # Renderizador PDF corporativo (ReportLab + Matplotlib)
├── SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx     # Dataset oficial del SIEM (715 eventos)
├── Informe_Final_SOC_L2_Incidentes.pdf                 # Entregable oficial en PDF (Ejecutivo + Técnico)
├── soc_l2_dashboard_summary.png                        # Panel gráfico forense de alta resolución
└── requirements.txt                                    # Dependencias del proyecto
```

---

## 🔎 Hallazgos Forenses en el Dataset Oficial (`715 Eventos`)

El análisis de la hoja `SIEM Export` (**23 de octubre de 2026**, `07:46:07` a `13:44:06`) identificó **6 incidentes de Riesgo ALTO** y **1 hallazgo de calidad de telemetría SIEM de Riesgo MEDIO**, vinculando **124 eventos maliciosos** (112 alertas nativas del SIEM + **12 eventos críticos camuflados como `Informational`**):

| ID | Incidente Detectado | Ventana (UTC) | Activos / Usuarios | MITRE ATT&CK | Eventos (Ocultos Info) | Riesgo |
| :--- | :--- | :--- | :--- | :--- | :---: | :---: |
| **INC-01** | Password Spraying Externo y Compromiso de `CORP\mgarcia` | `08:25` – `08:40` | `DC-01`, `WS-031` / `CORP\mgarcia` | `T1110.003`, `T1078.002` | `35` (`2` en Info) | 🔴 **ALTO** |
| **INC-02** | Intrusión RDP, Mov. Lateral SMB y Exfiltración (`Budget2027.xlsx`) | `09:02` – `09:22` | `APP-SRV01`, `FS-SRV01` / `CORP\admin` | `T1021.001`, `T1059.001`, `T1021.002`, `T1560.001`, `T1041` | `16` (`1` en Info) | 🔴 **ALTO** |
| **INC-03** | Pre-Ransomware: Recolección Financiera y Borrado de Shadow Copies (`vssadmin`) | `09:36` – `09:43` | `WS-023`, `FS-SRV01` / `CORP\backupsvc` | `T1059.001`, `T1039`, `T1490` | `19` (`1` en Info) | 🔴 **ALTO** |
| **INC-04** | Exfiltración Masiva Legal vía HTTPS POST (`241.57 MiB` / `253.31 MB`) | `10:40` – `10:49` | `WS-018`, `FS-SRV01` / `CORP\rrojas` | `T1039`, `T1560.001`, `T1048.002` | `24` (`2` en Info) | 🔴 **ALTO** |
| **INC-05** | Persistencia Dual por Tarea Programada y Servicio (`wuhelper.exe`) | `11:35` – `12:04` | `APP-SRV01` / `CORP\helpdesk` | `T1053.005`, `T1543.003` | `8` (`6` en Info) | 🔴 **ALTO** |
| **INC-06** | Explotación Web IIS, Webshell ASPX (`/uploads/test.aspx`) y RCE (`whoami`) | `12:10` – `12:15` | `WEB-01` / `DefaultAppPool` | `T1190`, `T1505.003`, `T1059.003` | `22` (`0` en Info) | 🔴 **ALTO** |
| **OBS-01** | Brechas de Visibilidad SIEM (`Informational`) y Normalización (`DC-01` vs `DC01`) | `07:46` – `13:44` | `DC-01`/`DC01`, `backupsvc`/`svc_backup` | `T1562` / Telemetría SOC | `12` rescatados | 🟠 **MEDIO** |

---

## 🚀 Instalación y Ejecución Rápida

### 1. Instalar dependencias
```bash
pip install -r requirements.txt
```

### 2. Iniciar el Dashboard Interactivo en Streamlit
```bash
streamlit run app.py
# o directamente:
python app.py
```

### 3. Regenerar el PDF Oficial, Gráficos e `index.html` por CLI
```bash
python generate_report.py
```
