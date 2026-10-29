"""The processes of one uid, from /proc: pid, ppid, the command, resident memory. What the live
page shows under "processes"; nothing is traced, only read."""
import os


def processes(uid: int = None) -> list:
    out = []
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            with open(f"/proc/{name}/status") as f:
                st = {}
                for line in f:
                    k, _, v = line.partition(":")
                    st[k] = v.strip()
            if uid is not None and int(st.get("Uid", "0").split()[0]) != uid:
                continue
            with open(f"/proc/{name}/cmdline", "rb") as f:
                cmd = f.read().replace(b"\0", b" ").decode("utf-8", "replace").strip()
            out.append({"pid": int(name), "ppid": int(st.get("PPid", "0")), "uid": int(st.get("Uid", "0").split()[0]),
                        "cmd": cmd[:160] or st.get("Name", ""), "rss_kb": int(st.get("VmRSS", "0 kB").split()[0] or 0),
                        "state": st.get("State", "")[:1], "no_new_privs": st.get("NoNewPrivs", "?"), "seccomp": st.get("Seccomp", "?")})
        except (OSError, ValueError, IndexError):
            continue
    return sorted(out, key=lambda p: p["pid"])
