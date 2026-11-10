"""
core/graph_builder.py
=====================
Generador de Grafos Forenses de Ataque y Correlación de Telemetría SIEM (SOC Nivel 2).
Construye grafos dirigidos interactivos (NetworkX + Plotly) modelando las relaciones
entre Atacantes (IPs externas), Cuentas Comprometidas, Activos/Hosts, Técnicas MITRE
e Infraestructura C2 de Exfiltración.
"""

from typing import Any, Dict, List, Tuple
import math
import networkx as nx
import pandas as pd
import plotly.graph_objects as go
from core.parser import is_external_ip


def build_siem_attack_graph_data(
    df: pd.DataFrame, findings: List[Dict[str, Any]]
) -> Tuple[nx.DiGraph, Dict[str, Any]]:
    """
    Construye un grafo dirigido NetworkX a partir de la telemetría SIEM y hallazgos.
    Retorna (G, metadata).
    """
    G = nx.DiGraph()

    # 1. Agregar Nodos de Incidentes
    for f in findings:
        inc_id = f.get("id", "INC")
        riesgo = f.get("riesgo", "Medio")
        color = "#FF2A5F" if riesgo == "Alto" else "#F59E0B"
        G.add_node(
            inc_id,
            node_type="incident",
            label=f"{inc_id}: {f.get('categoria', f.get('titulo', 'Incidente'))}",
            full_title=f.get("titulo", ""),
            risk=riesgo,
            cvss=f.get("cvss_estimado", "N/A"),
            events_count=f.get("eventos_count", 0),
            hidden_info=f.get("eventos_ocultos_info", 0),
            mitre=f.get("mitre", ""),
            color="#8B5CF6",
            size=28,
            symbol="diamond",
        )

    # 2. Extraer Nodos de IPs Externas, Hosts y Usuarios desde hallazgos y logs
    mal_logs = df[df["Incident_ID"] != "NONE"] if "Incident_ID" in df.columns else df

    # IPs de Origen Atacantes
    for ip in mal_logs["Source_IP"].unique():
        if ip and ip != "-" and is_external_ip(ip):
            count = len(mal_logs[mal_logs["Source_IP"] == ip])
            G.add_node(
                f"IP:{ip}",
                node_type="attacker_ip",
                label=f"🔴 {ip}",
                raw_id=ip,
                events_count=count,
                color="#FF2A5F",
                size=24,
                symbol="circle",
            )

    # IPs de Destino C2
    for ip in mal_logs["Destination"].unique():
        if ip and ip != "-" and is_external_ip(ip):
            count = len(mal_logs[mal_logs["Destination"] == ip])
            G.add_node(
                f"C2:{ip}",
                node_type="c2_ip",
                label=f"💀 C2: {ip}",
                raw_id=ip,
                events_count=count,
                color="#EC4899",
                size=24,
                symbol="hexagon",
            )

    # Hosts / Activos Comprometidos
    host_col = "Hostname_Norm" if "Hostname_Norm" in df.columns else "Hostname"
    for host in mal_logs[host_col].unique():
        if host and host != "-":
            count = len(mal_logs[mal_logs[host_col] == host])
            G.add_node(
                f"HOST:{host}",
                node_type="host",
                label=f"🖥️ {host}",
                raw_id=host,
                events_count=count,
                color="#00F0FF",
                size=22,
                symbol="square",
            )

    # Usuarios Involucrados
    user_col = "User_Norm" if "User_Norm" in df.columns else "User"
    for user in mal_logs[user_col].unique():
        if user and user != "-":
            count = len(mal_logs[mal_logs[user_col] == user])
            clean_u = user.replace("CORP\\", "")
            G.add_node(
                f"USER:{user}",
                node_type="user",
                label=f"👤 {clean_u}",
                raw_id=user,
                events_count=count,
                color="#FBBF24",
                size=18,
                symbol="circle",
            )

    # 3. Conectar Aristas Basadas en los Hallazgos y Correlación
    for f in findings:
        inc_id = f.get("id")
        # Conectar Hosts
        hosts_str = str(f.get("activos", ""))
        for h in hosts_str.split(","):
            h = h.strip()
            host_node = f"HOST:{h}"
            if host_node in G:
                G.add_edge(inc_id, host_node, label="Impacta Activo", edge_type="impact", weight=2)

        # Conectar Usuarios
        users_str = str(f.get("usuarios", ""))
        for u in users_str.split(","):
            u = u.strip().split(" ")[0]
            user_node = f"USER:{u}"
            if user_node in G:
                G.add_edge(user_node, inc_id, label="Involucra Identidad", edge_type="identity", weight=2)

        # Conectar IPs desde IoCs
        ioc_str = str(f.get("ioc", ""))
        for part in ioc_str.split(";"):
            part = part.strip()
            if "IP Atacante:" in part or "IP Origen:" in part:
                ip = part.split(":")[-1].strip()
                ip_node = f"IP:{ip}"
                if ip_node in G:
                    G.add_edge(ip_node, inc_id, label="Vector de Intrusión", edge_type="attack", weight=3)
            elif "IP Destino:" in part or "C2:" in part or "Destino:" in part:
                ip = part.split(":")[-1].strip()
                c2_node = f"C2:{ip}"
                if c2_node in G:
                    G.add_edge(inc_id, c2_node, label="Exfiltración C2", edge_type="exfil", weight=3)

    # Movimiento Lateral entre Hosts (ej. APP-SRV01 -> FS-SRV01)
    if "APP-SRV01" in mal_logs[host_col].values and "FS-SRV01" in mal_logs["Destination"].values:
        if "HOST:APP-SRV01" in G and "HOST:FS-SRV01" in G:
            G.add_edge("HOST:APP-SRV01", "HOST:FS-SRV01", label="Movimiento Lateral SMB (T1021.002)", edge_type="lateral", weight=4)

    meta = {
        "total_nodes": G.number_of_nodes(),
        "total_edges": G.number_of_edges(),
        "attackers_count": sum(1 for _, d in G.nodes(data=True) if d.get("node_type") == "attacker_ip"),
        "hosts_count": sum(1 for _, d in G.nodes(data=True) if d.get("node_type") == "host"),
        "users_count": sum(1 for _, d in G.nodes(data=True) if d.get("node_type") == "user"),
        "incidents_count": sum(1 for _, d in G.nodes(data=True) if d.get("node_type") == "incident"),
    }
    return G, meta


def create_attack_graph_figure(
    G: nx.DiGraph,
    filter_incident: str = "ALL",
) -> go.Figure:
    """
    Genera una figura interactiva Plotly Dark Cyberpunk a partir del grafo NetworkX.
    """
    if G.number_of_nodes() == 0:
        fig = go.Figure()
        fig.update_layout(
            paper_bgcolor="#0A0F1D",
            plot_bgcolor="#0A0F1D",
            annotations=[dict(text="No se registran nodos de ataque para graficar", showarrow=False, font=dict(color="#94A3B8", size=14))],
        )
        return fig

    # Filtrar subgrafo si se selecciona un incidente específico
    if filter_incident != "ALL" and filter_incident in G:
        neighbors = set(G.neighbors(filter_incident)) | set(G.predecessors(filter_incident)) | {filter_incident}
        subG = G.subgraph(neighbors)
    else:
        subG = G

    # Disposición de posiciones con layout de resortes (spring_layout)
    pos = nx.spring_layout(subG, k=0.85, iterations=60, seed=42)

    # Dibujar Aristas (Edges)
    edge_x = []
    edge_y = []
    edge_hover = []
    for u, v, data in subG.edges(data=True):
        x0, y0 = pos[u]
        x1, y1 = pos[v]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x,
        y=edge_y,
        line=dict(width=1.8, color="rgba(139, 92, 246, 0.45)"),
        hoverinfo="none",
        mode="lines",
    )

    # Dibujar Flechas o Nodos Intermedios para Aristas Direccionadas
    mid_edge_x = []
    mid_edge_y = []
    mid_edge_text = []
    for u, v, data in subG.edges(data=True):
        x0, y0 = pos[u]
        x1, y1 = pos[v]
        mid_x = (x0 + x1) / 2.0
        mid_y = (y0 + y1) / 2.0
        mid_edge_x.append(mid_x)
        mid_edge_y.append(mid_y)
        mid_edge_text.append(f"{u} ➔ {v}<br><b>Acción:</b> {data.get('label', 'Relación')}")

    mid_edge_trace = go.Scatter(
        x=mid_edge_x,
        y=mid_edge_y,
        mode="markers",
        hoverinfo="text",
        text=mid_edge_text,
        marker=dict(size=6, color="#00F0FF", opacity=0.85),
    )

    # Dibujar Nodos por Categoría
    traces = [edge_trace, mid_edge_trace]
    categories = [
        ("attacker_ip", "Atacantes Externos (Inbound)", "#FF2A5F", "circle"),
        ("incident", "Vectores e Incidentes MITRE", "#8B5CF6", "diamond"),
        ("host", "Activos Comprometidos (Hosts)", "#00F0FF", "square"),
        ("user", "Identidades y Cuentas", "#FBBF24", "circle"),
        ("c2_ip", "Destinos C2 / Exfiltración", "#EC4899", "hexagon"),
    ]

    for cat_type, cat_name, cat_color, cat_symbol in categories:
        cat_nodes = [n for n, d in subG.nodes(data=True) if d.get("node_type") == cat_type]
        if not cat_nodes:
            continue

        nx_list = [pos[n][0] for n in cat_nodes]
        ny_list = [pos[n][1] for n in cat_nodes]
        labels = [subG.nodes[n].get("label", n) for n in cat_nodes]
        sizes = [subG.nodes[n].get("size", 20) for n in cat_nodes]

        hover_texts = []
        for n in cat_nodes:
            d = subG.nodes[n]
            ntype = d.get("node_type", "")
            if ntype == "incident":
                txt = (
                    f"<b>🎯 {d.get('label')}</b><br>"
                    f"• <b>Título:</b> {d.get('full_title')}<br>"
                    f"• <b>Riesgo:</b> {d.get('risk')} (CVSS {d.get('cvss')})<br>"
                    f"• <b>Eventos:</b> {d.get('events_count')} (Ocultos en Info: {d.get('hidden_info')})<br>"
                    f"• <b>MITRE:</b> {d.get('mitre')}"
                )
            elif ntype in ["attacker_ip", "c2_ip"]:
                txt = (
                    f"<b>🌐 {d.get('label')}</b><br>"
                    f"• <b>IP:</b> {d.get('raw_id')}<br>"
                    f"• <b>Rol:</b> {'Atacante Inbound' if ntype == 'attacker_ip' else 'Receptor C2 Outbound'}<br>"
                    f"• <b>Eventos Asociados:</b> {d.get('events_count')}"
                )
            elif ntype == "host":
                txt = (
                    f"<b>🖥️ Activo: {d.get('raw_id')}</b><br>"
                    f"• <b>Eventos Registrados:</b> {d.get('events_count')}<br>"
                    f"• <b>Estado:</b> Comprometido en la cadena de ataque"
                )
            else:
                txt = (
                    f"<b>👤 Cuenta: {d.get('raw_id')}</b><br>"
                    f"• <b>Eventos Registrados:</b> {d.get('events_count')}<br>"
                    f"• <b>Impacto:</b> Identidad utilizada en el vector"
                )
            hover_texts.append(txt)

        node_trace = go.Scatter(
            x=nx_list,
            y=ny_list,
            mode="markers+text",
            text=labels,
            textposition="top center",
            textfont=dict(family="JetBrains Mono, monospace", size=10, color="#E2E8F0"),
            hoverinfo="text",
            hovertext=hover_texts,
            name=cat_name,
            marker=dict(
                size=sizes,
                color=cat_color,
                symbol=cat_symbol,
                line=dict(width=2, color="#FFFFFF"),
                opacity=0.95,
            ),
        )
        traces.append(node_trace)

    fig = go.Figure(
        data=traces,
        layout=go.Layout(
            title=dict(
                text="🕸️ Grafo Forense Interactivo de Ataque y Correlación SIEM (SOC L2)",
                font=dict(family="Inter, sans-serif", size=15, color="#F8FAFC"),
                x=0.03,
                y=0.96,
            ),
            showlegend=True,
            legend=dict(
                orientation="h",
                yanchor="bottom",
                y=-0.12,
                xanchor="center",
                x=0.5,
                font=dict(family="Inter, sans-serif", size=11, color="#CBD5E1"),
                bgcolor="rgba(15, 23, 42, 0.75)",
                bordercolor="rgba(139, 92, 246, 0.3)",
                borderwidth=1,
            ),
            hovermode="closest",
            margin=dict(b=60, l=20, r=20, t=50),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            paper_bgcolor="#0A0F1D",
            plot_bgcolor="#0A0F1D",
            height=560,
        ),
    )
    return fig


def get_attack_graph_json_export(df: pd.DataFrame, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Retorna el grafo en formato JSON serializable para renderizado nativo en index.html con Plotly.
    """
    G, meta = build_siem_attack_graph_data(df, findings)
    pos = nx.spring_layout(G, k=0.85, iterations=60, seed=42)

    nodes_list = []
    for n, d in G.nodes(data=True):
        x, y = pos[n]
        nodes_list.append({
            "id": n,
            "x": float(x),
            "y": float(y),
            "label": d.get("label", n),
            "type": d.get("node_type", ""),
            "color": d.get("color", "#00F0FF"),
            "size": d.get("size", 20),
            "events_count": d.get("events_count", 0),
            "risk": d.get("risk", ""),
            "mitre": d.get("mitre", ""),
            "symbol": d.get("symbol", "circle"),
        })

    edges_list = []
    for u, v, d in G.edges(data=True):
        edges_list.append({
            "source": u,
            "target": v,
            "label": d.get("label", ""),
            "edge_type": d.get("edge_type", ""),
        })

    return {"meta": meta, "nodes": nodes_list, "edges": edges_list}
