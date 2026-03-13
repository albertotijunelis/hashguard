"""IOC graph generation and relationship mapping for HashGuard v2.

Builds a relationship graph:  file → domain → IP → malware family
Supports visualization via vis.js network graph.
"""

import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from hashguard.logger import get_logger

logger = get_logger(__name__)


@dataclass
class GraphNode:
    id: str
    label: str
    node_type: str  # file, domain, ip, email, wallet, family, url
    properties: Dict = field(default_factory=dict)


@dataclass
class GraphEdge:
    source: str
    target: str
    relationship: str  # contains, resolves_to, communicates_with, belongs_to
    weight: float = 1.0


@dataclass
class IOCGraph:
    nodes: List[GraphNode] = field(default_factory=list)
    edges: List[GraphEdge] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "nodes": [
                {
                    "id": n.id,
                    "label": n.label,
                    "type": n.node_type,
                    "properties": n.properties,
                }
                for n in self.nodes
            ],
            "edges": [
                {
                    "from": e.source,
                    "to": e.target,
                    "relationship": e.relationship,
                    "weight": e.weight,
                }
                for e in self.edges
            ],
        }

    def to_visjs(self) -> dict:
        """Convert to vis.js compatible format."""
        color_map = {
            "file": "#ef4444",  # red
            "domain": "#3b82f6",  # blue
            "ip": "#8b5cf6",  # purple
            "email": "#f59e0b",  # amber
            "wallet": "#10b981",  # green
            "family": "#ec4899",  # pink
            "url": "#06b6d4",  # cyan
            "registry": "#f97316",  # orange
        }
        shape_map = {
            "file": "diamond",
            "domain": "dot",
            "ip": "triangle",
            "email": "square",
            "wallet": "hexagon",
            "family": "star",
            "url": "dot",
            "registry": "box",
        }
        nodes = []
        for n in self.nodes:
            nodes.append(
                {
                    "id": n.id,
                    "label": n.label[:30],
                    "title": n.label,
                    "color": color_map.get(n.node_type, "#94a3b8"),
                    "shape": shape_map.get(n.node_type, "dot"),
                    "size": 25 if n.node_type == "file" else 15,
                    "group": n.node_type,
                }
            )
        edges = []
        for e in self.edges:
            edges.append(
                {
                    "from": e.source,
                    "to": e.target,
                    "label": e.relationship,
                    "arrows": "to",
                    "color": {"color": "#64748b", "opacity": 0.6},
                }
            )
        return {"nodes": nodes, "edges": edges}


def build_graph(result_dict: dict) -> IOCGraph:
    """Build IOC relationship graph from analysis results."""
    graph = IOCGraph()
    seen_nodes: Set[str] = set()

    sha256 = result_dict.get("hashes", {}).get("sha256", "unknown")
    filename = result_dict.get("path", "unknown").split("\\")[-1].split("/")[-1]

    # Central file node
    file_id = f"file_{sha256[:16]}"
    graph.nodes.append(
        GraphNode(
            id=file_id,
            label=filename,
            node_type="file",
            properties={
                "sha256": sha256,
                "risk_score": result_dict.get("risk_score", {}).get("score", 0),
                "verdict": result_dict.get("risk_score", {}).get("verdict", "unknown"),
            },
        )
    )
    seen_nodes.add(file_id)

    # IOCs from string extraction
    strings_info = result_dict.get("strings_info") or result_dict.get("strings", {})
    # Support both nested (iocs.urls) and flat (urls) layouts
    iocs = strings_info.get("iocs", {}) if strings_info else {}
    if not iocs and strings_info:
        iocs = strings_info

    for url in iocs.get("urls", [])[:15]:
        node_id = f"url_{hash(url) & 0xFFFFFF:06x}"
        if node_id not in seen_nodes:
            graph.nodes.append(GraphNode(id=node_id, label=url, node_type="url"))
            seen_nodes.add(node_id)
        graph.edges.append(GraphEdge(source=file_id, target=node_id, relationship="contacts"))

    for ip in (iocs.get("ips", []) or iocs.get("ip_addresses", []))[:15]:
        node_id = f"ip_{ip.replace('.', '_')}"
        if node_id not in seen_nodes:
            graph.nodes.append(GraphNode(id=node_id, label=ip, node_type="ip"))
            seen_nodes.add(node_id)
        graph.edges.append(
            GraphEdge(source=file_id, target=node_id, relationship="communicates_with")
        )

    for domain in iocs.get("domains", [])[:15]:
        node_id = f"domain_{hash(domain) & 0xFFFFFF:06x}"
        if node_id not in seen_nodes:
            graph.nodes.append(GraphNode(id=node_id, label=domain, node_type="domain"))
            seen_nodes.add(node_id)
        graph.edges.append(GraphEdge(source=file_id, target=node_id, relationship="resolves"))

    for email in iocs.get("emails", [])[:10]:
        node_id = f"email_{hash(email) & 0xFFFFFF:06x}"
        if node_id not in seen_nodes:
            graph.nodes.append(GraphNode(id=node_id, label=email, node_type="email"))
            seen_nodes.add(node_id)
        graph.edges.append(GraphEdge(source=file_id, target=node_id, relationship="contains"))

    for wallet in iocs.get("crypto_wallets", [])[:10]:
        node_id = f"wallet_{hash(wallet) & 0xFFFFFF:06x}"
        if node_id not in seen_nodes:
            graph.nodes.append(
                GraphNode(
                    id=node_id,
                    label=wallet[:20] + "...",
                    node_type="wallet",
                    properties={"full": wallet},
                )
            )
            seen_nodes.add(node_id)
        graph.edges.append(GraphEdge(source=file_id, target=node_id, relationship="contains"))

    for regkey in iocs.get("registry_keys", [])[:10]:
        node_id = f"reg_{hash(regkey) & 0xFFFFFF:06x}"
        if node_id not in seen_nodes:
            label = regkey.split("\\")[-1] if "\\" in regkey else regkey
            graph.nodes.append(
                GraphNode(
                    id=node_id, label=label, node_type="registry", properties={"full_key": regkey}
                )
            )
            seen_nodes.add(node_id)
        graph.edges.append(GraphEdge(source=file_id, target=node_id, relationship="modifies"))

    # Family node from ML or threat intel
    family = result_dict.get("family_detection", {})
    if family and family.get("family"):
        fam_id = f"family_{family['family'].lower().replace(' ', '_')}"
        if fam_id not in seen_nodes:
            graph.nodes.append(
                GraphNode(
                    id=fam_id,
                    label=family["family"],
                    node_type="family",
                    properties={"confidence": family.get("confidence", 0)},
                )
            )
            seen_nodes.add(fam_id)
        graph.edges.append(
            GraphEdge(
                source=file_id,
                target=fam_id,
                relationship="belongs_to",
                weight=family.get("confidence", 0.5),
            )
        )

    # Threat intel connections
    ti = result_dict.get("threat_intel", {})
    if ti:
        for hit in ti.get("hits", []):
            if hit.get("found"):
                fam = hit.get("malware_family", "")
                if fam:
                    fam_id = f"family_{fam.lower().replace(' ', '_')}"
                    if fam_id not in seen_nodes:
                        graph.nodes.append(
                            GraphNode(
                                id=fam_id,
                                label=fam,
                                node_type="family",
                                properties={"source": hit.get("source", "")},
                            )
                        )
                        seen_nodes.add(fam_id)
                    graph.edges.append(
                        GraphEdge(
                            source=file_id,
                            target=fam_id,
                            relationship="identified_as",
                        )
                    )

    return graph
