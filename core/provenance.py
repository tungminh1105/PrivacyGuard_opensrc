"""Data Provenance Engine for PrivacyGuard.

Constructs directed causal graphs (NetworkX DiGraph) connecting:
  Sensitive File -> Process -> Network Socket
Tracks process trees (PPID/ParentProcessGuid) and links file actions with
subsequent network egress within a configurable sliding temporal window (Delta_T).
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional, Set, Tuple

import networkx as nx

from core.sensitive import get_sensitivity_score, is_sensitive_path
from core.intel import is_local_ip

logger = logging.getLogger(__name__)


def normalize_file_node_id(path: str) -> str:
    """Normalize file path for consistent node identification."""
    return f"file:{os.path.normpath(path).lower().replace('/', chr(92))}"


def normalize_proc_node_id(proc_key: str) -> str:
    """Normalize process key for consistent node identification."""
    return f"proc:{str(proc_key).strip().lower()}"


def normalize_socket_node_id(ip: str, port: Any) -> str:
    """Normalize destination socket for consistent node identification."""
    return f"socket:{str(ip).strip().lower()}:{int(port) if port else 0}"


class ProcessHierarchy:
    """Tracks parent-child relationships between processes."""

    def __init__(self, processes: Optional[List[Dict[str, Any]]] = None):
        # Maps proc_key -> parent_proc_key
        self.parent_map: Dict[str, str] = {}
        # Maps parent_proc_key -> set of child_proc_keys
        self.children_map: Dict[str, Set[str]] = {}
        # Maps PID -> latest proc_key
        self.pid_to_key: Dict[int, str] = {}

        if processes:
            self.load_processes(processes)

    def load_processes(self, processes: List[Dict[str, Any]]) -> None:
        """Populate hierarchy from process records or start events."""
        for p in processes:
            pk = p.get("proc_key")
            if not pk:
                continue
            pk_norm = str(pk).strip().lower()
            pid = p.get("pid")
            ppid = p.get("ppid")

            if pid is not None:
                try:
                    self.pid_to_key[int(pid)] = pk_norm
                except (ValueError, TypeError):
                    pass

            # If ppid is available, link to parent
            if ppid is not None and int(ppid) in self.pid_to_key:
                parent_key = self.pid_to_key[int(ppid)]
                if parent_key != pk_norm:
                    self.parent_map[pk_norm] = parent_key
                    self.children_map.setdefault(parent_key, set()).add(pk_norm)

    def register_process(self, proc_key: str, pid: int, ppid: Optional[int] = None) -> None:
        """Register a single active process."""
        pk_norm = str(proc_key).strip().lower()
        try:
            pid_int = int(pid)
        except (ValueError, TypeError):
            pid_int = None

        if pid_int is not None:
            self.pid_to_key[pid_int] = pk_norm

        if ppid is not None:
            try:
                ppid_int = int(ppid)
                if ppid_int in self.pid_to_key:
                    parent_key = self.pid_to_key[ppid_int]
                    if parent_key != pk_norm:
                        self.parent_map[pk_norm] = parent_key
                        self.children_map.setdefault(parent_key, set()).add(pk_norm)
            except (ValueError, TypeError):
                pass

    def get_family_keys(self, root_proc_key: str) -> Set[str]:
        """Return all proc_keys belonging to the process and all its descendants."""
        root_norm = str(root_proc_key).strip().lower()
        family: Set[str] = {root_norm}
        queue = [root_norm]
        while queue:
            curr = queue.pop(0)
            children = self.children_map.get(curr, set())
            for child in children:
                if child not in family:
                    family.add(child)
                    queue.append(child)
        return family


class ProvenanceEngine:
    """Builds and analyzes causality graphs from normalized event logs."""

    def __init__(self, delta_t_sec: float = 30.0):
        self.delta_t = delta_t_sec

    def build_graph(
        self,
        events: List[Dict[str, Any]],
        hierarchy: Optional[ProcessHierarchy] = None,
    ) -> nx.DiGraph:
        """Build directed provenance graph from a sequence of events.

        Nodes:
          - Process: proc:<proc_key>
          - File: file:<normalized_path>
          - Socket: socket:<dest_ip>:<dest_port>

        Edges:
          - SPAWN: Parent Process -> Child Process
          - CREATE / WRITE: Process -> File
          - READ: File -> Process (data input)
          - CONNECT / SEND: Process -> Socket
          - CAUSAL_FLOW: File -> Socket (derived when file is read/created then sent within delta_t)

        Returns:
            NetworkX DiGraph
        """
        G = nx.DiGraph()
        h = hierarchy or ProcessHierarchy()

        # Track file and network events per process family for temporal causal correlation
        file_events: List[Dict[str, Any]] = []
        net_events: List[Dict[str, Any]] = []

        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda e: float(e.get("ts", 0.0)))

        for ev in sorted_events:
            ts = float(ev.get("ts", 0.0))
            pk = str(ev.get("proc_key", "")).strip().lower()
            ev_type = ev.get("type", "")
            pid = ev.get("pid", 0)
            ppid = ev.get("ppid")

            if not pk:
                continue

            h.register_process(pk, pid, ppid)

            proc_node = normalize_proc_node_id(pk)
            if not G.has_node(proc_node):
                G.add_node(
                    proc_node,
                    node_type="process",
                    proc_key=pk,
                    pid=pid,
                    image=ev.get("image", ""),
                )

            # 1. Process Lifecycle / Hierarchy
            if ev_type == "proc_start" and ppid is not None:
                try:
                    ppid_int = int(ppid)
                    if ppid_int in h.pid_to_key:
                        parent_pk = h.pid_to_key[ppid_int]
                        parent_node = normalize_proc_node_id(parent_pk)
                        if G.has_node(parent_node):
                            G.add_edge(parent_node, proc_node, relation="SPAWN", ts=ts)
                except (ValueError, TypeError):
                    pass


            # 2. File Events (file_create, file_write, file_read)
            elif ev_type in ("file_create", "file_write", "file_read"):
                path = ev.get("path")
                if path:
                    file_node = normalize_file_node_id(path)
                    score = get_sensitivity_score(path)
                    is_sens = score >= 0.4

                    if not G.has_node(file_node):
                        G.add_node(
                            file_node,
                            node_type="file",
                            path=path,
                            sensitivity=score,
                            is_sensitive=is_sens,
                        )

                    # Direction: File supplies data to Process (data flow)
                    G.add_edge(file_node, proc_node, relation="READ" if ev_type == "file_read" else "TOUCH", ts=ts)
                    # Process creates/writes to file
                    G.add_edge(proc_node, file_node, relation="CREATE" if ev_type == "file_create" else "WRITE", ts=ts)

                    file_events.append({
                        "node": file_node,
                        "proc_key": pk,
                        "proc_node": proc_node,
                        "path": path,
                        "is_sensitive": is_sens,
                        "sensitivity": score,
                        "ts": ts,
                    })

            # 3. Network Events (net_connect, net_send)
            elif ev_type in ("net_connect", "net_send"):
                dest_ip = ev.get("dest_ip")
                dest_port = ev.get("dest_port")
                if dest_ip:
                    sock_node = normalize_socket_node_id(dest_ip, dest_port)
                    local_flag = is_local_ip(dest_ip)

                    if not G.has_node(sock_node):
                        G.add_node(
                            sock_node,
                            node_type="socket",
                            dest_ip=dest_ip,
                            dest_port=dest_port,
                            is_local=local_flag,
                        )

                    nbytes = ev.get("nbytes", 0)
                    G.add_edge(
                        proc_node,
                        sock_node,
                        relation="CONNECT" if ev_type == "net_connect" else "SEND",
                        ts=ts,
                        nbytes=nbytes,
                    )

                    net_events.append({
                        "node": sock_node,
                        "proc_key": pk,
                        "proc_node": proc_node,
                        "dest_ip": dest_ip,
                        "dest_port": dest_port,
                        "is_local": local_flag,
                        "nbytes": nbytes,
                        "ts": ts,
                    })

        # 4. Infer Causal Links: File -> Socket within Delta_T
        for fev in file_events:
            f_pk = fev["proc_key"]
            f_family = h.get_family_keys(f_pk)
            f_node = fev["node"]
            f_ts = fev["ts"]

            for nev in net_events:
                n_pk = nev["proc_key"]
                # Must belong to same process tree family
                if n_pk in f_family or f_pk in h.get_family_keys(n_pk):
                    dt = nev["ts"] - f_ts
                    if 0.0 <= dt <= self.delta_t:
                        # Causal proximity weight in [0.0, 1.0]
                        weight = max(0.0, min(1.0, 1.0 - (dt / max(1.0, self.delta_t))))
                        G.add_edge(
                            f_node,
                            nev["node"],
                            relation="CAUSAL_FLOW",
                            dt=dt,
                            weight=weight,
                            ts_file=f_ts,
                            ts_net=nev["ts"],
                            is_sensitive=fev["is_sensitive"],
                        )

        return G

    def explain_paths(
        self, graph: nx.DiGraph, target_socket: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Extract and explain all causal chains from sensitive files to sockets."""
        explanations = []

        file_nodes = [
            n for n, attr in graph.nodes(data=True)
            if attr.get("node_type") == "file" and attr.get("is_sensitive", False)
        ]
        socket_nodes = [
            n for n, attr in graph.nodes(data=True)
            if attr.get("node_type") == "socket"
        ]

        if target_socket:
            target_norm = normalize_socket_node_id(target_socket.split(":")[0], target_socket.split(":")[-1])
            socket_nodes = [s for s in socket_nodes if s == target_norm]

        for f_node in file_nodes:
            f_attr = graph.nodes[f_node]
            for s_node in socket_nodes:
                s_attr = graph.nodes[s_node]

                # Check if there is a path or direct CAUSAL_FLOW edge
                has_causal_edge = graph.has_edge(f_node, s_node)
                path_found = None
                try:
                    if nx.has_path(graph, f_node, s_node):
                        path_found = nx.shortest_path(graph, f_node, s_node)
                except Exception:
                    path_found = None

                if has_causal_edge or path_found:
                    edge_data = graph.get_edge_data(f_node, s_node, {}) if has_causal_edge else {}
                    explanations.append({
                        "file_path": f_attr.get("path"),
                        "sensitivity": f_attr.get("sensitivity", 0.0),
                        "destination": f"{s_attr.get('dest_ip')}:{s_attr.get('dest_port')}",
                        "is_local": s_attr.get("is_local", False),
                        "path_nodes": path_found or [f_node, s_node],
                        "causal_dt": edge_data.get("dt"),
                        "causal_weight": edge_data.get("weight", 1.0),
                    })

        return explanations


def build_provenance_graph(
    events: List[Dict[str, Any]], delta_t_sec: float = 30.0
) -> nx.DiGraph:
    """Convenience function to build provenance graph from events list."""
    engine = ProvenanceEngine(delta_t_sec=delta_t_sec)
    return engine.build_graph(events)
