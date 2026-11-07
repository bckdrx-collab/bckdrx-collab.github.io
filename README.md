# 🛡️ SOC Nivel 2 — Plataforma de Análisis Forense e Incidentes con IA Generativa

[![Live Portal GitHub Pages](https://img.shields.io/badge/🌐_GitHub_Pages_(Live_App)-bckdrx--collab.github.io-2563EB?style=for-the-badge)](https://bckdrx-collab.github.io/soc-l2-incident-response/)
[![Descargar Informe PDF Oficial](https://img.shields.io/badge/📄_Informe_Oficial_PDF-Descargar_Directo-EF4444?style=for-the-badge)](https://bckdrx-collab.github.io/soc-l2-incident-response/Informe_Final_SOC_L2_Incidentes.pdf)
[![30 Leyes UX](https://img.shields.io/badge/🧠_Arquitectura_UX-30_Laws_of_UX-A855F7?style=for-the-badge)](https://bckdrx-collab.github.io/soc-l2-incident-response/)

Proyecto final desarrollado para el **Bootcamp de Analista SOC Nivel 2 (Dojo Community)**.  
Esta aplicación automatiza la **ingesta de registros SIEM en Excel (`.xlsx`)**, ejecuta un **motor híbrido de correlación heurística + Inteligencia Artificial Generativa**, descubre **eventos críticos ocultos bajo severidad `Informational`**, construye un **Dashboard interactivo** (tanto en **Streamlit** como en **Web SPA estática en GitHub Pages `github.io`**) y exporta el **Informe Oficial en PDF (Resumen Ejecutivo C-Level + Informe Técnico Forense con mapeo MITRE ATT&CK)**.

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
├── generate_report.py                                  # Generador CLI directo del PDF y gráficos
├── core/
│   ├── __init__.py
│   ├── parser.py                                       # Ingesta Excel, normalización y correlación de 6 incidentes
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

## 🎨 Ingeniería de Interfaz Basada en las 30 Leyes de UX (Laws of UX)

El dashboard ([`app.py`](app.py)) fue diseñado aplicando los 30 principios de **Laws of UX (Jon Yablonski)** adaptados a un Centro de Operaciones de Seguridad (SOC Nivel 2):
- **Umbral de Doherty (`< 400 ms`) & Fluir:** Procesamiento en caché (`@st.cache_data`) con telemetría de latencia en vivo (`< 50 ms`).
- **Efecto Von Restorff & Mitigación de Sesgo Cognitivo:** Aislamiento visual en azul eléctrico de los **12 eventos críticos ocultos bajo severidad `Informational`** para neutralizar el sesgo de anclaje en la severidad nativa del SIEM.
- **Ley de Miller (`7 ± 2`), Fragmentación & Ley de Región Común:** 5 tarjetas KPI superiores agrupadas semánticamente y descomposición de cada incidente en 3 bloques (*Impacto Ejecutivo*, *Evidencia Forense* y *Metadatos/IoCs + Playbook CLI*).
- **Ley de Conectividad Uniforme:** Visualización de cadenas de ataque conectadas (`Initial Access ➔ Execution ➔ Lateral Movement ➔ Exfiltration`).
- **Ley de Hick, Principio de Pareto (`80/20`) & Ley de Tesler:** Píldoras de filtro rápido de 1 clic (`Solo los 124 eventos maliciosos = 17.3% de logs que concentran el 100% del riesgo`) y divulgación progresiva de parámetros avanzados de LLM.
- **Efecto Zeigarnik & Tendencia a la Meta:** Checklist interactivo de contención (`X/6 Incidentes Contenidos`) con barra de progreso en tiempo real.
- **Ley de Fitts, Posición en Serie & Regla de Fin de Pico:** Botón primario de descarga de PDF en la esquina superior derecha (primera posición) y al cierre del flujo de reportes con confirmación visual.

---

## 🚀 Instalación y Ejecución Rápida

### 1. Instalar dependencias
```bash
pip install -r requirements.txt
```

### 2. Iniciar el Dashboard Interactivo en Streamlit
```bash
streamlit run app.py
```

### 3. Generar el PDF Oficial por línea de comandos (opcional)
```bash
python generate_report.py
```

---

## 🎥 Guion Sugerido de 3 Minutos para el Video Demostrativo

1. **0:00 – 0:45 | Arquitectura Modular y Decisión de Diseño SOC L2:**
   - Muestra la estructura del proyecto (`app.py`, `core/parser.py`, `core/agents.py`, `core/pdf_generator.py`).
   - Explica que en lugar de enviar las 715 filas crudas del Excel a un prompt (lo que produce alucinaciones o errores de conteo), implementaste una **arquitectura híbrida**: `core/parser.py` correlaciona los eventos con precisión matemática y alimenta a los agentes de IA en `core/agents.py`.
2. **0:45 – 2:00 | Demostración del Dashboard y Caza de "Trampas de Nivel 2":**
   - Muestra el dashboard en vivo con el archivo `SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx`.
   - Destaca los KPIs: **715 eventos**, **112 alertas nativas**, pero **124 eventos maliciosos correlacionados** al descubrir **12 eventos críticos ocultos como `Informational`** (`EVT-00123` login exitoso en `CORP\mgarcia`, `EVT-00428` compresión con `7z.exe` previa a exfiltrar **241.57 MiB**, y las 5 ejecuciones de `wuhelper.exe`), además de la inconsistencia `DC-01` vs `DC01`.
3. **2:00 – 3:00 | Generación con Agente de IA y Descarga del PDF Oficial:**
   - Ve a la pestaña **3. Informes Ejecutivo y Técnico (IA) + Exportar PDF**, muestra ambos reportes y descarga `Informe_Final_SOC_L2_Incidentes.pdf`. Ábrelo para mostrar la portada, los KPIs, la matriz MITRE ATT&CK, los gráficos integrados y el detalle técnico.

