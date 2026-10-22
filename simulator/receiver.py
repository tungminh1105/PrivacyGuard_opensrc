"""TCP Receiver Server for PrivacyGuard Simulator.

Listens strictly on 127.0.0.1 to record incoming network connections and byte counts.
STRICT SAFETY ENFORCEMENT:
- Binds strictly to 127.0.0.1 (loopback interface).
- Discards payload immediately: counts bytes and records UTC timestamp in SQLite.
- Never stores payload contents.
"""

from __future__ import annotations

import argparse
import logging
import os
import select
import socket
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple

# Ensure project root in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.store import EventStore

try:
    import yaml
except ImportError:
    yaml = None

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [Receiver] %(message)s",
)


def load_simulator_config(config_path: str = "config.yaml") -> Dict[str, Any]:
    """Load simulator section from config.yaml with default fallback."""
    if os.path.exists(config_path) and yaml is not None:
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if isinstance(data, dict):
                    sim_cfg = data.get("simulator", {})
                    db_cfg = data.get("database", {})
                    return {
                        "host": sim_cfg.get("receiver_host", "127.0.0.1"),
                        "port": sim_cfg.get("receiver_port", 8765),
                        "scenario5_port": sim_cfg.get("scenario5_port", 443),
                        "db_path": db_cfg.get("db_path", "data/privacyguard.db"),
                    }
        except Exception as e:
            logger.warning("Could not read %s: %s", config_path, e)

    return {
        "host": "127.0.0.1",
        "port": 8765,
        "scenario5_port": 443,
        "db_path": "data/privacyguard.db",
    }


class ReceiverServer:
    """Multi-port TCP receiver strictly bound to 127.0.0.1."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        ports: Optional[List[int]] = None,
        db_path: str = "data/privacyguard.db",
    ):
        if host not in ("127.0.0.1", "localhost"):
            raise ValueError(f"SAFETY VIOLATION: Receiver can only bind to 127.0.0.1! Got: {host}")

        self.host = "127.0.0.1"
        self.ports = ports or [8765]
        self.db_path = db_path
        self.store = EventStore(db_path=self.db_path)

        self._sockets: List[socket.socket] = []
        self._listening_ports: List[int] = []
        self._threads: List[threading.Thread] = []
        self._running = False
        self._lock = threading.Lock()
        self.total_bytes_received = 0
        self.connection_count = 0

    def _handle_client(self, client_sock: socket.socket, client_addr: Tuple[str, int], dest_port: int) -> None:
        """Read all bytes from client until EOF, record count, discard content."""
        src_ip, src_port = client_addr
        bytes_for_conn = 0
        try:
            while self._running:
                chunk = client_sock.recv(65536)
                if not chunk:
                    break
                bytes_for_conn += len(chunk)
                del chunk  # Explicitly discard payload
        except Exception as e:
            logger.debug("Socket read error on port %d: %s", dest_port, e)
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

        if bytes_for_conn > 0:
            ts_utc = time.time()
            with self._lock:
                self.total_bytes_received += bytes_for_conn
                self.connection_count += 1
                try:
                    self.store.log_receiver_bytes(
                        ts_utc=ts_utc,
                        src_ip=src_ip,
                        src_port=src_port,
                        dest_port=dest_port,
                        bytes_received=bytes_for_conn,
                    )
                except Exception as e:
                    logger.error("Failed to log receiver bytes to DB: %s", e)

            logger.info(
                "Received %d bytes on 127.0.0.1:%d from %s:%d (total: %d bytes)",
                bytes_for_conn,
                dest_port,
                src_ip,
                src_port,
                self.total_bytes_received,
            )

    def _listen_on_port(self, port: int) -> None:
        """Worker loop listening on a specific port."""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server_sock.bind((self.host, port))
            server_sock.listen(128)
            server_sock.settimeout(0.5)
            with self._lock:
                self._sockets.append(server_sock)
                self._listening_ports.append(port)
            logger.info("Receiver listening on %s:%d", self.host, port)
        except Exception as e:
            logger.warning("Could not bind receiver to port %d: %s", port, e)
            try:
                server_sock.close()
            except Exception:
                pass
            return

        while self._running:
            try:
                client_sock, client_addr = server_sock.accept()
                t = threading.Thread(
                    target=self._handle_client,
                    args=(client_sock, client_addr, port),
                    daemon=True,
                )
                t.start()
            except socket.timeout:
                continue
            except Exception:
                if self._running:
                    logger.debug("Accept error on port %d", port)
                break

    def start(self) -> None:
        """Start listening threads in the background."""
        if self._running:
            return
        self._running = True
        for port in self.ports:
            t = threading.Thread(target=self._listen_on_port, args=(port,), daemon=True)
            self._threads.append(t)
            t.start()
        # Give sockets a moment to bind
        time.sleep(0.1)

    def stop(self) -> None:
        """Stop receiver server and close all sockets."""
        self._running = False
        for s in self._sockets:
            try:
                s.close()
            except Exception:
                pass
        self._sockets.clear()
        for t in self._threads:
            t.join(timeout=1.0)
        self._threads.clear()
        try:
            self.store.close()
        except Exception:
            pass
        logger.info("Receiver stopped. Total bytes recorded: %d", self.total_bytes_received)

    @property
    def listening_ports(self) -> List[int]:
        with self._lock:
            return list(self._listening_ports)

    def __enter__(self) -> ReceiverServer:
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()


def main():
    parser = argparse.ArgumentParser(description="PrivacyGuard Simulator TCP Receiver")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Must be 127.0.0.1")
    parser.add_argument("--port", type=int, default=None, help="TCP port (default from config)")
    parser.add_argument("--ports", type=str, default=None, help="Comma-separated list of ports (e.g. 8765,443)")
    parser.add_argument("--db", type=str, default=None, help="Path to SQLite database")
    parser.add_argument("--duration", type=float, default=None, help="Run duration in seconds")
    args = parser.parse_args()

    cfg = load_simulator_config()
    host = args.host or cfg["host"]
    db_path = args.db or cfg["db_path"]

    ports_to_listen = []
    if args.ports:
        ports_to_listen = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
    elif args.port:
        ports_to_listen = [args.port]
    else:
        # Default listen on primary port and scenario5 port
        ports_to_listen = [cfg["port"]]
        if cfg.get("scenario5_port") and cfg["scenario5_port"] not in ports_to_listen:
            ports_to_listen.append(cfg["scenario5_port"])

    server = ReceiverServer(host=host, ports=ports_to_listen, db_path=db_path)
    server.start()

    print(f"Receiver server running on {host}:{server.listening_ports}. DB: {db_path}")
    print("Press Ctrl+C to terminate.")

    start_t = time.time()
    try:
        while True:
            time.sleep(1.0)
            if args.duration and (time.time() - start_t) >= args.duration:
                break
    except KeyboardInterrupt:
        print("\nStopping receiver...")
    finally:
        server.stop()


if __name__ == "__main__":
    main()
