"""Lay out the network map as a diagram: positions for every node and link.

The layout is worked out once, from the report model, and drawn by both the
HTML report (as SVG) and the PDF report, so the two always match.

Each subnet is a box. Its gateway sits at the top centre, and its hosts are
placed in a grid below. If traceroute was used, this computer and any
routers in between sit above the subnets, and the observed paths are drawn
as solid lines. Inferred links are dashed.
"""

import math
from dataclasses import dataclass, field


WIDTH = 1000
MARGIN = 20
CELL_W = 150
CELL_H = 64
BOX_HEADER = 70
BOX_GAP = 30
TOP_BAND = 110
MAX_HOSTS_PER_SUBNET = 60


@dataclass
class DiagramNode:
    id: str
    kind: str
    x: float
    y: float
    label: str
    sublabel: str = ""
    criticality: str | None = None
    findings: int = 0
    risk: float | None = None


@dataclass
class DiagramLink:
    source: str
    target: str
    kind: str
    x1: float
    y1: float
    x2: float
    y2: float
    reason: str = ""


@dataclass
class DiagramBox:
    label: str
    x: float
    y: float
    width: float
    height: float
    note: str = ""


@dataclass
class Diagram:
    width: float
    height: float
    nodes: list[DiagramNode] = field(default_factory=list)
    links: list[DiagramLink] = field(default_factory=list)
    boxes: list[DiagramBox] = field(default_factory=list)


def _short(text: str | None, limit: int = 22) -> str:
    if not text:
        return ""
    return text if len(text) <= limit else text[: limit - 3] + "..."


def build_diagram(report: dict) -> Diagram:
    """Positions for the report's network map."""
    network = report["network"]
    nodes_by_id = {node["id"]: node for node in network["nodes"]}
    hosts = {host["ip"]: host for host in report["hosts"]}
    finding_counts: dict[str, int] = {}

    for finding in report["findings"]:
        if finding["host"]:
            finding_counts[finding["host"]] = finding_counts.get(finding["host"], 0) + 1

    diagram = Diagram(width=WIDTH, height=0)
    placed: dict[str, DiagramNode] = {}

    def place(node_id: str, x: float, y: float) -> None:
        node = nodes_by_id.get(node_id, {"kind": "hop", "label": node_id})
        host = hosts.get(node_id, {})
        role = node.get("role_label")
        sublabel = f"{role} ({node.get('confidence')})" if role else ""
        placed[node_id] = DiagramNode(
            id=node_id,
            kind=node.get("kind", "host"),
            x=x,
            y=y,
            label=_short(node.get("ip") or node.get("label"), 26),
            sublabel=_short(sublabel, 26),
            criticality=node.get("criticality"),
            findings=finding_counts.get(node_id, 0),
            risk=host.get("risk_score"),
        )

    # ----- top band: this computer and routers outside every subnet -----
    traced = bool(network["traced_paths"])
    in_subnets = {ip for group in network["subnets"] for ip in group["hosts"]}
    gateways = {group["gateway"] for group in network["subnets"] if group["gateway"]}
    upstream = [
        node["id"] for node in network["nodes"]
        if node["kind"] in ("hop", "gateway") and node["id"] not in in_subnets
        and node["id"] not in gateways and node["id"] != "argus"
    ]
    y = MARGIN

    if traced:
        place("argus", WIDTH / 2, y + 20)
        placed["argus"].label = "This computer (ARGUS)"

        for index, hop in enumerate(upstream[:8]):
            spacing = WIDTH / (min(len(upstream), 8) + 1)
            place(hop, spacing * (index + 1), y + 75)

        y += TOP_BAND + (40 if upstream else 0)

    # ----- one box per subnet, two per row when they are small -----
    row_y = y
    row_height = 0
    column = 0

    subnets = network["subnets"]

    for position, group in enumerate(subnets):
        members = [ip for ip in group["hosts"] if ip != group["gateway"]]
        shown = members[:MAX_HOSTS_PER_SUBNET]
        # Big subnets, and a subnet that would sit alone on its row, use the full width.
        alone = column == 0 and position == len(subnets) - 1
        wide = len(shown) > 8 or alone
        box_width = WIDTH - 2 * MARGIN if wide else (WIDTH - 2 * MARGIN - BOX_GAP) / 2

        if wide and column == 1:
            row_y += row_height + BOX_GAP
            row_height, column = 0, 0

        columns = max(1, int(box_width // CELL_W))
        rows = math.ceil(len(shown) / columns) if shown else 0
        gateway_space = 70 if group["gateway"] else 0
        height = BOX_HEADER + gateway_space + rows * CELL_H + 20
        x = MARGIN + (0 if column == 0 else box_width + BOX_GAP)

        note = []
        if group["size_assumed"]:
            note.append("size assumed")
        if len(members) > len(shown):
            note.append(f"{len(members) - len(shown)} more hosts not drawn")

        diagram.boxes.append(DiagramBox(
            label=group["network"],
            x=x, y=row_y, width=box_width, height=height,
            note=", ".join(note),
        ))

        if group["gateway"]:
            place(group["gateway"], x + box_width / 2, row_y + BOX_HEADER + 10)

        for index, ip in enumerate(shown):
            cell_x = x + (index % columns) * (box_width / columns) + box_width / columns / 2
            cell_y = row_y + BOX_HEADER + gateway_space + (index // columns) * CELL_H + 22
            place(ip, cell_x, cell_y)

        row_height = max(row_height, height)

        if wide or column == 1:
            row_y += row_height + BOX_GAP
            row_height, column = 0, 0
        else:
            column = 1

    diagram.height = row_y + row_height + MARGIN

    # ----- links between nodes that were drawn -----
    for link in network["links"]:
        source, target = placed.get(link["source"]), placed.get(link["target"])

        if source is None or target is None:
            continue

        diagram.links.append(DiagramLink(
            source=link["source"], target=link["target"], kind=link["kind"],
            x1=source.x, y1=source.y, x2=target.x, y2=target.y,
            reason=link["reason"],
        ))

    diagram.nodes = list(placed.values())
    return diagram
