"""example-addon's contract tests: standard library only, run from this folder.

    python3 -m unittest discover -s tests

1. Every route routes.json declares is one the server serves, and the other way
   round (step 4 of docs/development/addons.md).
2. The overlay never puts the add-on key in the environment, and has no
   environment entry without a value (the gateway's guard refuses both).
3. resources.json delivers the key, the gateway CA and the TLS leaf as FILES.
"""
import ast
import json
import pathlib
import re
import unittest

HERE = pathlib.Path(__file__).resolve().parents[1]


class Contract(unittest.TestCase):
    def test_routes_json_equals_what_the_server_serves(self):
        manifest = json.loads((HERE / "routes.json").read_text())
        declared = {r["path"] for r in manifest["routes"] if not r.get("internal")}
        tree = ast.parse((HERE / "app" / "server.py").read_text())
        served = next(ast.literal_eval(n.value) for n in ast.walk(tree)
                      if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "ROUTES" for t in n.targets))
        self.assertEqual(declared, served)

    def test_the_overlay_takes_nothing_from_the_environment_by_name(self):
        text = (HERE / "docker-compose.yml").read_text()
        env = re.search(r"\n    environment:\n((?:      .*\n)+)", text).group(1)
        for line in env.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            self.assertNotRegex(line, r"^-\s*[A-Z_]+\s*$", "a list entry with no value is a pass-through")
            self.assertNotRegex(line, r"^[A-Z_]+:\s*$", "a key with no value is a pass-through")
            self.assertNotIn("NOO_SVC_KEY", line, "the add-on key never goes in the environment")

    def test_secrets_arrive_as_files(self):
        res = json.loads((HERE / "resources.json").read_text())["resources"]
        for r in res:
            secret = r["kind"] in ("addon_key", "shared_secret") or r.get("part") in ("key", "passfile")
            if secret:
                targets = r["deliver"] if isinstance(r["deliver"], list) else [r["deliver"]]
                self.assertTrue(all("file" in t for t in targets), r["name"])


if __name__ == "__main__":
    unittest.main()
