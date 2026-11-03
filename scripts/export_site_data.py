"""Export the attack catalogue and the robustness matrix for the interactive site (docs/).

Run:  python scripts/export_site_data.py
"""
import json
import sys
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import redteam_lab as rl  # noqa: E402

data = {
    "canary": rl.DEFAULT_CANARY,
    "system_prompt": rl.build_system_prompt(),
    "attacks": [
        {"id": a.id, "name": a.name, "category": a.category, "description": a.description,
         "mitigation": a.mitigation, "prompt": a.build()}
        for a in rl.ATTACKS
    ],
    "benign": list(rl.BENIGN_PROMPTS),
    "results": [asdict(s) for s in rl.evaluate()],
    "markdown": rl.to_markdown(rl.evaluate()),
}
out = ROOT / "docs" / "data" / "results.json"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(data, ensure_ascii=False, indent=1))
print(f"wrote {out.relative_to(ROOT)}")
