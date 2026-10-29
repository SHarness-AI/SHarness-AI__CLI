"""`sharness-ai doctor`: can a policy hold here? One small class per check, each returning a
Check__Result with pass, warn, fail or skip, a message, a hint and its duration; CLI__Doctor runs
them in order, stops after a fatal failure, and prints the report. The shape is the sgit CLI's
doctor (SGit-AI/SGit-AI__CLI, sgit_ai/cli/doctor/), in the standard library."""
from sharness_ai.cli.doctor.Check__Result import Check__Result

__all__ = ["Check__Result"]
