# ⚡ JEV // SOC L2 Cyber Command OS — LangChain LCEL & Análisis Forense SIEM

[![Live Portal GitHub Pages](https://img.shields.io/badge/🌐_GitHub_Pages_(Live_App)-bckdrx--collab.github.io-00F0FF?style=for-the-badge&logoColor=black)](https://bckdrx-collab.github.io/soc-l2-incident-response/)
[![LangChain LCEL Engine](https://img.shields.io/badge/🔗_Orquestador-LangChain_LCEL-8B5CF6?style=for-the-badge)](https://github.com/bckdrx-collab/soc-l2-incident-response)
[![Descargar Informe PDF Oficial](https://img.shields.io/badge/📄_Informe_Oficial_PDF-Descargar_Directo-FF2A5F?style=for-the-badge)](https://bckdrx-collab.github.io/soc-l2-incident-response/Informe_Final_SOC_L2_Incidentes.pdf)

Proyecto final desarrollado para el **Bootcamp de Analista SOC Nivel 2 (Dojo Community)**.  
**JEV // Cyber Command OS v3.0** combina una **interfaz fluida Bento / Glassmorphic** con un **motor de orquestación Multi-Agente en LangChain (`LCEL — LangChain Expression Language`)** que procesa exportaciones SIEM en Excel (`.xlsx`), ejecuta correlación multi-etapa sobre **715 eventos**, destapa **12 eventos críticos ocultos bajo severidad `Informational`**, incluye un **Copiloto Forense Interactivo (`JEVCyberCopilotChain`)** y compila el **Informe Oficial en PDF (Ejecutivo C-Level + Técnico DFIR con mapeo MITRE ATT&CK)**.

### 🌐 Enlaces Publicados en Vivo (`github.io`)
- **Portal Web Interactivo Fluido (JEV Cyber Command OS):** [https://bckdrx-collab.github.io/soc-l2-incident-response/](https://bckdrx-collab.github.io/soc-l2-incident-response/)
- **Portal Principal de Usuario (`bckdrx-collab.github.io`):** [https://bckdrx-collab.github.io/](https://bckdrx-collab.github.io/)
- **Descarga Directa del Informe PDF Oficial (7 Páginas):** [Informe_Final_SOC_L2_Incidentes.pdf](https://bckdrx-collab.github.io/soc-l2-incident-response/Informe_Final_SOC_L2_Incidentes.pdf)
- **Repositorio de Código Fuente:** [https://github.com/bckdrx-collab/soc-l2-incident-response](https://github.com/bckdrx-collab/soc-l2-incident-response)

---

## 🔗 Arquitectura del Grafo LangChain LCEL (`core/agents.py`)

```python
chain = (
    RunnableLambda(load_siem_telemetry)
    | RunnableParallel(
        executive=exec_prompt | llm_runnable | StrOutputParser(),
        technical=dfir_prompt | llm_runnable | StrOutputParser(),
    )
)
```

1. **`SIEMContextLoader` (`RunnableLambda`):** Normaliza 715 eventos, unifica `DC-01`/`DC01` y extrae 124 alertas correlacionadas + 12 trampas `Informational`.
2. **`MITRETriagePrompt` (`ChatPromptTemplate`):** Clasifica tácticas MITRE ATT&CK v15 (`T1110.003`, `T1490`, `T1048.002`, `T1505.003`) y severidad CVSS v3.1.
3. **`RunnableParallel(executive, technical)`:** Bifurca la generación simultánea del Informe Ejecutivo C-Level y del Informe Técnico Forense DFIR (compatible con `ChatOpenAI`, `Ollama Local` y Respaldo Determinista).
4. **`JEVCyberCopilotChain` (`ChatPromptTemplate | llm_runnable | StrOutputParser`):** Copiloto conversacional interactivo sobre los 715 eventos SIEM, IoCs y Playbooks PowerShell.

---

## 🏗️ Estructura Modular del Proyecto

```text
BOOTCAMP SOC L2/
├── app.py                                              # Interfaz Fluida JEV Cyber Command OS en Streamlit + LangChain
├── generate_report.py                                  # Generador CLI unificado (PDF, PNG e index.html fluido)
├── index.html                                          # Portal web interactivo fluido para GitHub Pages (github.io)
├── core/
│   ├── __init__.py
│   ├── parser.py                                       # Ingesta Excel, validación, normalización y correlación L2
│   ├── agents.py                                       # Orquestador LangChain LCEL + Copiloto Interactivo JEV
│   └── pdf_generator.py                                # Renderizador PDF corporativo de 7 páginas (ReportLab)
├── SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx     # Dataset oficial del SIEM (715 eventos)
├── Informe_Final_SOC_L2_Incidentes.pdf                 # Entregable oficial en PDF (Ejecutivo + Técnico)
├── soc_l2_dashboard_summary.png                        # Panel gráfico forense de alta resolución
└── requirements.txt                                    # Dependencias del proyecto (incluye langchain & langchain-core)
```

---

## 🔎 Hallazgos Forenses en el Dataset Oficial (`715 Eventos`)

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

```bash
pip install -r requirements.txt
streamlit run app.py
# o directamente:
python app.py
```
