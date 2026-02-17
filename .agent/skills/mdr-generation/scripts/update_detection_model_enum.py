"""
Update the MDR schema's 'detection_model' enum with DOM signal UUIDs.

Scans all DOM YAML files in Objects/Detection Objectives/ and populates
the detection_model enum and markdownEnumDescriptions in
Schemas/MDR Schema.json so that MDR files can reference DOM signal
UUIDs without validation errors.

Usage:
    python update_detection_model_enum.py
    python update_detection_model_enum.py --repo-root /path/to/InitTide
"""

import argparse
import json
import sys
from pathlib import Path

import yaml


def find_repo_root(start: Path = Path(__file__)) -> Path:
    """Walk up from this script to find the repo root (contains Schemas/)."""
    current = start.resolve().parent
    for _ in range(10):
        if (current / "Schemas").is_dir() and (current / "Objects").is_dir():
            return current
        current = current.parent
    raise FileNotFoundError("Could not locate repository root with Schemas/ and Objects/ directories.")


def load_dom_signals(objects_dir: Path) -> list[dict]:
    """Load all DOM YAML files and extract signal uuid + name + parent DOM name."""
    dom_dir = objects_dir / "Detection Objectives"
    if not dom_dir.is_dir():
        print(f"WARNING: {dom_dir} does not exist. No DOMs found.")
        return []

    signals = []
    for yaml_file in sorted(dom_dir.glob("*.yaml")):
        try:
            with open(yaml_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if not data:
                continue

            dom_name = data.get("name", yaml_file.stem)
            objective = data.get("objective", {})
            signal_list = objective.get("signals", [])

            if not signal_list:
                print(f"WARNING: No signals found in {yaml_file.name}")
                continue

            for signal in signal_list:
                sig_uuid = signal.get("uuid")
                sig_name = signal.get("name")
                if sig_uuid and sig_name:
                    signals.append({
                        "uuid": str(sig_uuid),
                        "name": str(sig_name),
                        "dom_name": str(dom_name),
                        "file": yaml_file.name,
                    })
                else:
                    print(f"WARNING: Skipping signal in {yaml_file.name} - missing uuid or name")
        except Exception as e:
            print(f"ERROR: Failed to parse {yaml_file.name}: {e}")
    return signals


def build_enum_description(signal: dict) -> str:
    """Build a markdownEnumDescription entry matching the existing schema style."""
    return (
        f"\n### {signal['name']}\n\n"
        f"\U0001f511 **Identifier** : `{signal['uuid']}`\n\n"
        f"_Vocabulary_ : `Detection Signals`\n\n"
        f"_Detection Objective_ : `{signal['dom_name']}`\n\n"
        f"---\n\n"
        f"Signal: {signal['name']} — DOM: {signal['dom_name']}\n"
    )


def update_schema(schema_path: Path, signals: list[dict]) -> bool:
    """Update the detection_model enum in the MDR schema."""
    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)

    # Navigate to detection_model field: properties -> detection_model -> enum
    detection_model = schema.get("properties", {}).get("detection_model")
    if detection_model is None:
        print("ERROR: Could not find detection_model in schema properties.")
        return False

    # Build new enum values and descriptions
    enum_values = [sig["uuid"] for sig in signals]
    enum_descriptions = [build_enum_description(sig) for sig in signals]

    # Update the schema
    detection_model["enum"] = enum_values
    detection_model["markdownEnumDescriptions"] = enum_descriptions

    # Write back
    with open(schema_path, "w", encoding="utf-8") as f:
        json.dump(schema, f, indent=4, ensure_ascii=False)
        f.write("\n")

    return True


def main():
    parser = argparse.ArgumentParser(
        description="Update MDR schema detection_model enum with DOM signal UUIDs."
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help="Path to the InitTide repository root. Auto-detected if not provided.",
    )
    args = parser.parse_args()

    repo_root = args.repo_root or find_repo_root()
    schema_path = repo_root / "Schemas" / "MDR Schema.json"
    objects_dir = repo_root / "Objects"

    if not schema_path.exists():
        print(f"ERROR: Schema file not found: {schema_path}")
        sys.exit(1)

    print(f"Repository root: {repo_root}")
    print(f"Schema file:     {schema_path}")
    print(f"Objects dir:     {objects_dir}")
    print()

    # Load all DOM signals
    signals = load_dom_signals(objects_dir)
    if not signals:
        print("No DOM signals found. Nothing to update.")
        sys.exit(0)

    print(f"Found {len(signals)} signal(s) across DOM files:")
    for sig in signals:
        print(f"  - {sig['uuid']}  {sig['name']}  (DOM: {sig['dom_name']})")
    print()

    # Update schema
    if update_schema(schema_path, signals):
        print(f"Successfully updated detection_model enum with {len(signals)} signal UUID(s).")
    else:
        print("Failed to update schema.")
        sys.exit(1)


if __name__ == "__main__":
    main()
