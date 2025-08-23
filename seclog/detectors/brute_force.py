from collections import defaultdict
from datetime import timedelta

from ..models import Event, Finding
from .abstract import AbstractDetector


class BruteForceDetector(AbstractDetector):
    name = "brute_force"

    def __init__(self, threshold: int, window_seconds: int):
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)
        self.current_clusters: defaultdict[str, list[Event]] = defaultdict(list)
        self.final_clusters: defaultdict[str, list[list[Event]]] = defaultdict(list)

    def feed(self, e: Event):
        if e.event_type != "FAILED_LOGIN":
            return
        ip = e.src_ip
        cluster = self.current_clusters[ip]
        if not cluster:
            cluster.append(e)
        else:
            if (e.timestamp - cluster[-1].timestamp) <= self.window:
                cluster.append(e)
            else:
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
        users = set()
        raw = []
        for e in cluster:
            raw.append(e.raw)
            if "user=" in e.msg:
                users.add(e.msg.split("user=", 1)[1].strip())
        return Finding(
            detector=self.name,
            timestamp_first=cluster[0].timestamp,
            timestamp_last=cluster[-1].timestamp,
            src_ip=ip,
            summary=f"{len(cluster)} failed logins within {int(self.window.total_seconds())}s threshold.", # noqa: E501
            details={
                "usernames": list(users),
                "raw": raw,
            },
        )
