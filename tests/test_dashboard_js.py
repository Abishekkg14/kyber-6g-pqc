"""Dashboard JavaScript checks that need no browser: syntax of app.js and the overlay-tracking simulation."""
import json
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "kyber6g" / "ground" / "static"


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class TestDashboardJs(unittest.TestCase):
    def test_scripts_parse(self):
        for name in ("app.js", "boxtracker.js", "voxel.js"):
            src = (STATIC / name).read_text()
            if name == "voxel.js":                 # ES module: only check that it parses as one
                r = subprocess.run(["node", "--input-type=module", "--check"], input=src, capture_output=True, text=True)
            else:
                r = subprocess.run(["node", "-e", "new Function(require('fs').readFileSync(process.argv[1],'utf8'))", str(STATIC / name)],
                                   capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, f"{name}: {r.stderr[:300]}")

    def test_overlay_boxes_stick_to_moving_objects_and_do_not_jitter(self):
        r = subprocess.run(["node", str(ROOT / "tests" / "js" / "boxtracker_sim.js")], capture_output=True, text=True, timeout=60)
        res = json.loads(r.stdout.strip().splitlines()[-1])
        self.assertEqual(r.returncode, 0, json.dumps(res))
        self.assertLess(res["moving"]["errorPx"]["tracker"], res["moving"]["errorPx"]["naive"])

    def test_every_dom_id_used_by_app_js_exists_in_index_html(self):
        import re
        html = (STATIC / "index.html").read_text()
        ids = set(re.findall(r'\sid="([^"]+)"', html))
        used = set(re.findall(r'\$\("([A-Za-z0-9_]+)"\)', (STATIC / "app.js").read_text())) | \
            set(re.findall(r'setHTML\("([A-Za-z0-9_]+)"', (STATIC / "app.js").read_text())) | \
            set(re.findall(r'(?:setText|setLog)\("([A-Za-z0-9_]+)"', (STATIC / "app.js").read_text()))
        self.assertEqual(sorted(used - ids), [], "app.js references ids that index.html does not define")


if __name__ == "__main__":
    unittest.main()
