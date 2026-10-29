"""How sharness-ai draws: one result object, three voices (a terminal, plain ASCII, JSON).

Term says where the output goes and what it can show; Draw turns results into lines for that
Term; Prompt asks questions with a non-interactive path for scripts and tests; Trace records the
steps behind --debug. Nothing here touches the kernel: the engine modules return objects and
these draw them. Design: sharness.ai/articles/the-cli-is-the-front-door.html
"""
from sharness_ai.ui.Draw   import Draw
from sharness_ai.ui.Prompt import Prompt
from sharness_ai.ui.Term   import Term
from sharness_ai.ui.Trace  import Trace

__all__ = ["Draw", "Prompt", "Term", "Trace"]
