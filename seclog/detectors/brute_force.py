from collections import defaultdict
from datetime import timedelta

from ..models import Event, Finding
from .abstract import AbstractDetector


class BruteForceDetector(AbstractDetector):
    name = "brute_force"

    def __init__(self, threshold: int, window_seconds: int):
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)
        self.current_cluster: defaultdict[str, list[Event]] = defaultdict(list)
        self.final_clusters: defaultdict[str, list[list[Event]]] = defaultdict(list)

    def feed(self, e: Event) -> None:
        if e.event_type != "FAILED_LOGIN":
            return
        ip = e.src_ip
        cluster = self.current_cluster[ip]
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
                self.current_cluster[ip] = [e]

    def flush(self) -> list[Finding]:
        findings = []
        # Process finalized clusters
        for ip, clusters in self.final_clusters.items():
            for cluster in clusters:
                findings.append(self._create_finding(ip, cluster))

        # Process current cluster
        for ip, cluster in self.current_cluster.items():
            if len(cluster) >= self.threshold:
                findings.append(self._create_finding(ip, cluster))

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
            summary=(
                f"{len(cluster)} failed logins within "
                f"{int(self.window.total_seconds())}s threshold."
            ),
            details={
                "usernames": list(users),
                "raw": raw,
            },
        )
