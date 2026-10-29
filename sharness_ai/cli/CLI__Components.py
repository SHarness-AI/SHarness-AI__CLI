"""`sharness-ai components [NAME]`, and the verbs `bash`, `net`, `kms`, `fs`, `llm`, `launcher`:
the operating system a process sees, drawn with honest status. None is built. A verb prints the
map with its component, the proposed REST surface and the page, then exits EX_UNAVAILABLE (69),
so a script that guesses ahead learns the truth."""
import json

EXIT_NOT_BUILT = 69            # sysexits.h EX_UNAVAILABLE: designed, not here yet
SITE = "https://sharness.ai/components"

COMPONENTS = {
    "bash":     ("the shell, as a service", "runs one command under a profile's policy and returns exit, stdout, stderr",
                 ("POST /v0/run {profile, cmd, cwd, timeout_s}", "GET /v0/profiles", "GET /v0/policy")),
    "net":      ("the only network client", "every request leaves through it: host allowlists, no redirects elsewhere, logged",
                 ("POST /v0/fetch {method, url, headers, body}", "POST /v0/vault/pull", "GET /v0/log", "GET /v0/policy")),
    "kms":      ("where a secret lives", "keys never leave; callers get derived keys sealed to a one-time key",
                 ("POST /v0/unwrap", "POST /v0/seal_to", "GET /v0/identity", "GET /v0/policy")),
    "fs":       ("the only writer", "the one process with a writable root; every write checked against its rules",
                 ("PUT /v0/files/<path>", "POST /v0/files/<path>/append", "DELETE /v0/files/<path>", "POST /v0/mkdir", "GET /v0/hello", "GET /v0/policy")),
    "llm":      ("the only model client", "the Messages API unchanged, behind a model allowlist, a budget and a filter",
                 ("POST /v1/messages", "GET /v0/log", "GET /v0/policy")),
    "launcher": ("the bootstrap", "one user, one policy per component, every component started bound before it runs",
                 ("starts the components; no REST surface of its own is proposed yet",)),
    "policy":   ("the manifest", "the hashes of every component's policy; GET /v0/policy on each must match it",
                 ("GET /v0/policy on every component",)),
}
ORDER = ("bash", "net", "kms", "fs", "llm", "launcher", "policy")
RUNNABLE = {"fs": "runnable: sharness.fs.disk and sharness.fs.disk.twin (sharness-ai fs serve); a Setting for the app until the launcher",
            "net": "runnable: sharness.net.proxy (sharness-ai net serve): CONNECT and HTTP for one uid under a host allowlist; TLS is not terminated",
            "launcher": "runnable, the first slice: sharness-ai shell (a unique uid, the net door for it, a live page); not yet the launcher of the design"}

# WYSIWYG template: every placeholder is one character wide, so the columns line up as shown.
# { ┌  } ┐  [ └  ] ┘  < ├  > ┤  ~ ┬  = ┴  | │  - ─
MAP = (
    "                  {- kms -------}    {- llm -------}",
    "                  | a secret    |    | the model   |",
    "                  [------~------]    [------~------]",
    "   {- fs --------}       |                 |        {- net -------}",
    "   | the files   <-------=--------~---------=--------> egress      |",
    "   [-------------]     {----------=-----------}      [-------------]",
    "                       |      sharness.bash   |",
    "                       | the shell as service |",
    "                       [-----------~----------]",
    "                       {- launcher =----------}",
    "                       | the bootstrap        |",
    "                       [----------------------]",
    "   policy: the manifest every component reads; each answers GET /v0/policy with its hash",
)
GLYPHS = {"{": "tl", "}": "tr", "[": "bl", "]": "br", "<": "lt", ">": "rt", "~": "tt", "=": "bt", "|": "v", "-": "h"}


class CLI__Components:
    def __init__(self, main):
        self.main = main

    def map(self, selected: str = None) -> list:
        """The drawing: bash at the centre, kms and llm above, fs and net beside, launcher below.
        The selected component is written in capitals (and colour where there is one)."""
        t = self.main.term
        out = []
        for row in MAP:
            if selected and f" {selected} " in row or (selected == "policy" and row.strip().startswith("policy:")):
                word = selected if selected != "policy" else "policy:"
                shown = selected.upper() if selected != "policy" else "POLICY:"
                row = row.replace(word, "\0", 1)
            else:
                shown = None
            line = "".join(t.glyph(GLYPHS[c]) if c in GLYPHS else c for c in row)
            if shown is not None:
                line = line.replace("\0", t.style(shown, "accent", "bold"))
            out.append(line)
        return out

    def cmd_components(self, args) -> int:
        selected = getattr(args, "name", None)
        if selected and selected not in COMPONENTS:
            return self.main.fail(f"no component called {selected!r}",
                                  hint="the components are " + ", ".join(ORDER), code=2)
        if self.main.json:
            print(json.dumps({"status": "designed, not built", "components": {
                k: {"role": v[0], "does": v[1], "surface": list(v[2]), "page": f"{SITE}/{k}/index.html"}
                for k, v in COMPONENTS.items()}, "selected": selected}, indent=1))
            return EXIT_NOT_BUILT if selected and selected not in RUNNABLE else 0
        t, d = self.main.term, self.main.draw
        lines = d.head("components", "the operating system a process sees")
        lines.append("")
        lines += self.map(selected)
        lines.append("")
        if selected:
            role, does, surface = COMPONENTS[selected]
            lines += d.kv(f"sharness.{selected}", f"{role}: {does}", style="bold")
            for i, s in enumerate(surface):
                lines += d.kv("proposed" if i == 0 else "", s)
            lines += d.kv("page", f"{SITE}/{selected}/index.html")
            if selected in RUNNABLE:
                lines += d.kv("status", RUNNABLE[selected], style="ok")
                lines += d.kv("next", "sharness-ai shell --workspace . --sites github.com   everything that runs, together", style="head")
            else:
                lines += d.kv("status", "designed, not built. This verb exists so that the shape is visible; it exits 69 "
                                        "(unavailable) until the component is runnable", style="warn")
        else:
            for k in ORDER:
                lines += d.kv(f"sharness.{k}", COMPONENTS[k][0] + (f"  {t.mark('ok')} runnable" if k in RUNNABLE else ""))
            lines += d.kv("status", f"fs, net and a first slice of the launcher run (sharness-ai shell); kms, llm, bash and the manifest: designed, not built {t.glyph('dot')} {SITE}/", style="warn")
            lines += d.kv("today", "the experiments are what runs: probe, policy, run, hello, translate", style="dim")
            lines += d.kv("next", "sharness-ai components net   one component in detail; sharness-ai hello   what runs today",
                          style="head")
        t.write(*lines)
        return EXIT_NOT_BUILT if selected and selected not in RUNNABLE else 0
