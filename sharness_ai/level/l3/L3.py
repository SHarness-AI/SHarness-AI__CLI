"""Level 3: rows in plain nouns, compiled to the v0 policy the kernel holds.

A level-3 document is the v0 shape with `"level": 3` and, in `network`, `sites` instead of
ports: `{"sites": ["github.com", "http://example.org", "host:8443"]}`. A site compiles to the
port the kernel can hold (443; 80 for `http://`; the port written after the host), and the host
name itself is an UNHELD row until `sharness.net` runs here, said in so many words. A
`connect_tcp_ports` row beside `sites` is a level-1 row passed through unchanged (the escape
hatch) and is reported as such. Everything else passes down as written; the result is checked by
policy.check, so the v0 standard is untouched."""
import re

from sharness_ai.policy import PolicyError, canonical, check, path_problem

HOST = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$|^localhost$")
LEVEL = 3


class L3:
    level = LEVEL
    emits = 2

    @staticmethod
    def site(text: str):
        """('github.com', 443) from 'github.com', 'https://github.com', 'http://x.org' (80), 'host:8443'."""
        s = text.strip().lower()
        port = 443
        if s.startswith("http://"):
            s, port = s[7:], 80
        elif s.startswith("https://"):
            s = s[8:]
        s = s.split("/", 1)[0]
        if ":" in s:
            host, _, p = s.rpartition(":")
            if not p.isdigit() or not 0 < int(p) < 65536:
                raise PolicyError(f"network.sites: {text!r}: the port must be 1 to 65535")
            s, port = host, int(p)
        if not HOST.match(s):
            raise PolicyError(f"network.sites: {text!r} is not a host name (no scheme, no path, lower case)")
        return s, port

    @classmethod
    def check(cls, doc: dict) -> list:
        """Problems with a level-3 document, in its own nouns."""
        p = []
        if doc.get("level") != LEVEL:
            p.append(f"level must be {LEVEL}")
        net = doc.get("network")
        if isinstance(net, dict) and "sites" in net:
            if not isinstance(net["sites"], list):
                p.append("network.sites must be a list of host names")
            else:
                for s in net["sites"]:
                    try:
                        cls.site(s)
                    except (PolicyError, AttributeError) as e:
                        p.append(str(e) if isinstance(e, PolicyError) else f"network.sites: {s!r} is not a string")
            for k in net:
                if k not in ("sites", "connect_tcp_ports"):
                    p.append(f"network.{k}: unknown key at level 3")
        files = doc.get("files")
        if isinstance(files, dict):
            for k in ("read", "write", "exec"):
                for x in files.get(k, []) if isinstance(files.get(k, []), list) else []:
                    why = path_problem(x)
                    if why:
                        p.append(f"files.{k}: {x!r} {why}")
        return p

    @classmethod
    def compile(cls, doc: dict) -> dict:
        """The v0 policy (level 2 in this MVP), the rows it does not hold, and the rows passed
        through from level 1. Deterministic: the same document always gives the same bytes."""
        problems = cls.check(doc)
        if problems:
            raise PolicyError("level 3: " + "; ".join(problems))
        out = {k: v for k, v in doc.items() if k != "level"}
        unheld, passthrough = [], []
        net = doc.get("network")
        if isinstance(net, dict) and "sites" in net:
            ports = set()
            for s in net["sites"]:
                host, port = cls.site(s)
                ports.add(port)
                unheld.append(f"{host}: held as port {port}; the host name is not held until sharness.net runs here")
            extra = net.get("connect_tcp_ports", [])
            if extra:
                passthrough.append(f"network.connect_tcp_ports {sorted(set(extra))}: a level-1 row, passed through unchanged")
                ports |= set(extra)
            out["network"] = {"connect_tcp_ports": sorted(ports)} if ports else "none"
        if doc.get("secrets"):
            out.pop("secrets", None)
            unheld.append(f"secrets {doc['secrets']}: no door holds a secret here yet (sharness.kms is designed, not built)")
        elif "secrets" in out:
            out.pop("secrets")
        v0_problems = check(out)
        if v0_problems:
            raise PolicyError("level 3 compiled to a v0 policy that is not well-formed: " + "; ".join(v0_problems))
        canonical(out)
        return {"document": out, "unheld": unheld, "passthrough": passthrough}
