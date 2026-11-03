"""Command line: ``python -m redteam_lab [--json]`` prints the robustness matrix for the toy target."""
import argparse

from .evaluate import evaluate, to_json, to_markdown


def main() -> None:
    ap = argparse.ArgumentParser(description="Evaluate prompt-injection robustness of the toy target.")
    ap.add_argument("--json", action="store_true", help="print JSON instead of a Markdown table")
    args = ap.parse_args()
    res = evaluate()
    print(to_json(res) if args.json else to_markdown(res))


if __name__ == "__main__":
    main()
