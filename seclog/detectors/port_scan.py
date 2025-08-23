from collections import defaultdict
from datetime import timedelta

from ..models import Event, Finding
from .abstract import AbstractDetector


class PortScanDetector(AbstractDetector):
    name = "port_scan"

    def __init__(self, threshold: int, window_seconds: int):
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)
        self.current_clusters: defaultdict[str, list[Event]] = defaultdict(list)
        self.final_clusters: defaultdict[str, list[list[Event]]] = defaultdict(list)

    def feed(self, e: Event) -> None:
        if e.event_type != "PORT_SCAN_ATTEMPT":
            return
        ip = e.src_ip
        cluster = self.current_clusters[ip]
        if not cluster:
            cluster.append(e)
        else:
            if (e.timestamp - cluster[-1].timestamp) <= self.window:
                # If the event is within the time window to the last event,
                # add it to the cluster.
                cluster.append(e)
            else:
                # Otherwise, finalize the cluster.
                if len(cluster) >= self.threshold:
                    self.final_clusters[ip].append(cluster)
                self.current_clusters[ip] = [e]

    def flush(self) -> list[Finding]:
        findings = []
        # Process finalized clusters
        for ip, clusters in self.final_clusters.items():
            for cluster in clusters:
                if len(cluster) >= self.threshold:
                    findings.append(self._create_finding(ip, cluster))

        # Process current clusters and clean up empty ones
        empty_ips = []
        for ip, cluster in self.current_clusters.items():
            if len(cluster) >= self.threshold:
                findings.append(self._create_finding(ip, cluster))
            elif len(cluster) == 0:
                empty_ips.append(ip)

        # Clean up empty clusters
        for ip in empty_ips:
            del self.current_clusters[ip]
            if ip in self.final_clusters and not self.final_clusters[ip]:
                del self.final_clusters[ip]

        return findings

    def _create_finding(self, ip: str, cluster: list[Event]) -> Finding:
        """Create a Finding object from a cluster of events."""
        ports = []
        raw = []
        for e in cluster:
            raw.append(e.raw)
            try:
                port = int(e.msg.split("target=", 1)[1])
                if port is not None:
                    ports.append(port)
            except Exception:
                continue
        return Finding(
            detector=self.name,
            timestamp_first=cluster[0].timestamp,
            timestamp_last=cluster[-1].timestamp,
            src_ip=ip,
            summary=f"Port scan behavior: {len(cluster)} ports probed",
            details={"ports": ports, "raw": raw},
        )
