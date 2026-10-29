"""`sharness-ai probe`: the grant, drawn, with what it means for the person and the next step."""
import json
import os

from sharness_ai.probe import caps_label, kernel_rows, other_os_reading, probe


class CLI__Probe:
    def __init__(self, main):
        self.main = main

    @staticmethod
    def where(p: dict, sep: str = " · ") -> str:
        """One line: where you are. Shared with the guide."""
        cg = p.get("cgroups")
        return sep.join([f"{p['os']} {p['kernel']}", f"Landlock {kernel_rows(p)['landlock']}",
                         f"uid {p['uid']}", f"cgroups {cg}" if cg else "no cgroups"])

    @staticmethod
    def readings(p: dict) -> list:
        """What the grant means for a policy here, in sentences. Each is a fact of this machine."""
        out = []
        abi = p["landlock_abi"] or 0
        if p["os"] == "emscripten":
            return ["no kernel here: this is Python compiled to WebAssembly (Pyodide). A policy can be "
                    "hashed, checked, written and translated here; it can be enforced only by a Linux kernel. "
                    "The Linux tab of the playground has one: https://sharness.ai/code/playground/index.html"]
        if other_os_reading(p):
            return [other_os_reading(p)]
        if abi < 1:
            out.append("Landlock is not available on this kernel: run refuses rather than run a command "
                       "without its policy. Linux 5.13 or later, with CONFIG_SECURITY_LANDLOCK, has it")
            return out
        out.append(f"a policy will hold here: files by Landlock ABI {abi}"
                   + ("; TCP ports by Landlock too" if abi >= 4 else
                      "; ports need ABI 4 (Linux 6.7): a policy naming ports is refused here"))
        if p["uid"] == 0:
            out.append("network none gets an empty network namespace (uid 0)")
        elif "user" in (p.get("namespaces") or []):
            out.append("network none tries a user namespace for an empty network namespace, else Landlock "
                       "TCP rules (UDP not covered)")
        else:
            out.append("network none falls back to Landlock TCP rules: UDP (DNS) is not covered without a namespace")
        if p["uid"] == 0 and p["caps_all"]:
            out.append("this process is root with every capability and no seccomp: the grant is everything. "
                       "A policy applied from here binds its children, not itself")
        return out

    def cmd_probe(self, args) -> int:
        m = self.main
        with m.trace.step("probe"):
            p = probe()
        m.state.record("probe", os=p["os"], landlock_abi=p["landlock_abi"], uid=p["uid"])
        if m.json:
            print(json.dumps(p, indent=1))
            return 0
        t, d = m.term, m.draw
        sep = f" {t.glyph('dot')} "

        def yn(v):
            return "yes" if v else "no"

        who = f"uid {p['uid']}" + (" (root)" if p["uid"] == 0 else "")
        caps = caps_label(p)
        k = kernel_rows(p)
        tools = "  ".join(f"{name} {t.mark('ok') if v else t.mark('no')}" for name, v in p["tools"].items())
        lines = d.head("probe", "the grant: what a process here can do before any policy")
        lines += d.kv("identity", sep.join([who, f"capabilities {caps}", f"NoNewPrivs {k['no_new_privs']}",
                                            f"Seccomp {k['seccomp']}"]))
        lines += d.kv("kernel", sep.join([f"{p['os']} {p['kernel']}", f"Landlock {k['landlock']}",
                                          f"memfd_secret {k['memfd_secret']}", f"cgroups {k['cgroups']}"]))
        lines += d.kv("namespaces", k["namespaces"])
        lines += d.kv("config", k["config"])
        lines += d.kv("tools", tools)
        lines += d.kv("egress", f"proxy variables set: {', '.join(p['egress_proxy_vars']) or 'none'} "
                                "(names only; values are never printed)")
        lines += d.kv("workspace", f"{os.getcwd()} writable: {yn(p['cwd_writable'])}{sep}python {p['python']}")
        for i, r in enumerate(self.readings(p)):
            lines += d.kv("reading" if i == 0 else "", r, style="bold" if i == 0 else None)
        nxt = ("sharness-ai hello   the acceptance test: six probes under one policy"
               if p["os"].startswith("linux") and p["landlock_abi"] else
               "sharness-ai policy new   write a policy here; enforce it where there is a kernel")
        lines += d.kv("next", nxt, style="head")
        t.write(*lines)
        return 0
