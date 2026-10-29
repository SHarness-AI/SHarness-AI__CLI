"""Run a door's vectors against a running instance, the twin first: each vector is a request and
what the door must answer. Prints held, failed, the way hello does; exit 0 only when every vector
held. A vector: {"name", "method", "path", "body" (text) | "body_b64", "expect": {"status", "reason"?}}."""
import base64
import json

from sharness_ai.door.Client import Client, DoorError


class Conformance:
    def __init__(self, client: Client):
        self.client = client

    def run(self, vectors: list) -> list:
        results = []
        for v in vectors:
            body = base64.b64decode(v["body_b64"]) if "body_b64" in v else v.get("body", "").encode()
            try:
                status, data = self.client.request(v["method"], v["path"], body if body else None)
            except DoorError as e:
                results.append({"name": v["name"], "held": False, "got": str(e)})
                continue
            exp = v["expect"]
            ok = status == exp["status"]
            reason = data.get("reason", "") if isinstance(data, dict) else str(data)
            if ok and exp.get("reason"):
                ok = exp["reason"] in reason
            results.append({"name": v["name"], "held": ok, "expected": exp, "got": {"status": status, "reason": reason}})
        return results

    @staticmethod
    def summary(results: list) -> dict:
        held = sum(1 for r in results if r["held"])
        return {"held": held, "of": len(results), "failed": [r["name"] for r in results if not r["held"]]}

    @staticmethod
    def load(path: str) -> list:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data["vectors"] if isinstance(data, dict) else data
