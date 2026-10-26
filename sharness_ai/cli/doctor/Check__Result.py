"""One check's outcome. `status` is PASS, WARN, FAIL or SKIP; `hint` is what to do about it."""
import time
from dataclasses import asdict, dataclass, field

PASS, WARN, FAIL, SKIP = "pass", "warn", "fail", "skip"


@dataclass
class Check__Result:
    name        : str
    status      : str = SKIP
    message     : str = ""
    hint        : str = ""
    duration_ms : int = 0
    fatal       : bool = False            # a failure here makes the later checks meaningless
    details     : dict = field(default_factory=dict)

    def done(self, t0: float) -> "Check__Result":
        self.duration_ms = int((time.monotonic() - t0) * 1000)
        return self

    def as_dict(self) -> dict:
        return asdict(self)
