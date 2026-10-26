"""A verdict and the audit line. The verdict names the row that decided; the audit line never
carries a body or a secret, only the shape of the request and what was decided."""
import json
import sys
import time
from collections import deque
from dataclasses import asdict, dataclass, field


@dataclass
class Verdict:
    allowed : bool
    status  : int
    reason  : str = ""
    row     : str = ""                 # the row that decided, in the policy's words
    body    : dict = field(default_factory=dict)

    @classmethod
    def ok(cls, status: int = 200, **body) -> "Verdict":
        return cls(True, status, body=body)

    @classmethod
    def refuse(cls, reason: str, row: str = "", status: int = 403) -> "Verdict":
        return cls(False, status, reason, row)

    def payload(self) -> dict:
        d = {"allowed": self.allowed, "status": self.status}
        if self.reason:
            d["reason"] = self.reason
        if self.row:
            d["row"] = self.row
        d.update(self.body)
        return d


class Audit:
    """One line per request, kept in memory (capped) and, when `stream` is given, written there."""
    def __init__(self, door: str, keep: int = 1000, stream=None):
        self.door, self.lines, self.stream = door, deque(maxlen=keep), stream

    def record(self, peer: str, method: str, path: str, size: int, verdict: Verdict) -> dict:
        line = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "door": self.door, "peer": peer or "?",
                "method": method, "path": path, "bytes": size, "allowed": verdict.allowed, "status": verdict.status,
                "reason": verdict.reason, "row": verdict.row}
        self.lines.append(line)
        if self.stream is not None:
            print(json.dumps(line), file=self.stream, flush=True)
        return line

    def dump(self) -> list:
        return list(self.lines)


def say(text: str):
    print(text, file=sys.stderr, flush=True)


__all__ = ["Audit", "Verdict", "asdict", "say"]
