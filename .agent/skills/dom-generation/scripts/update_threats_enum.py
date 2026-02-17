"""
Update the Detection Objective schema's 'threats' enum with TVM UUIDs.

Scans all TVM YAML files in Objects/Threat Vectors/ and populates
the threats enum and markdownEnumDescriptions in
Schemas/Detection Objective.schema.json so that DOM files can
reference TVM UUIDs without validation errors.

Usage:
    python update_threats_enum.py
    python update_threats_enum.py --repo-root /path/to/InitTide
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


def load_tvms(objects_dir: Path) -> list[dict]:
    """Load all TVM YAML files and extract uuid + name."""
    tvm_dir = objects_dir / "Threat Vectors"
    if not tvm_dir.is_dir():
        print(f"WARNING: {tvm_dir} does not exist. No TVMs found.")
        return []

    tvms = []
    for yaml_file in sorted(tvm_dir.glob("*.yaml")):
        try:
            with open(yaml_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if not data:
                continue
            uuid_val = data.get("metadata", {}).get("uuid")
            name_val = data.get("name")
            if uuid_val and name_val:
                tvms.append({"uuid": str(uuid_val), "name": str(name_val), "file": yaml_file.name})
            else:
                print(f"WARNING: Skipping {yaml_file.name} - missing uuid or name")
        except Exception as e:
            print(f"ERROR: Failed to parse {yaml_file.name}: {e}")
    return tvms


def build_enum_description(tvm: dict) -> str:
    """Build a markdownEnumDescription entry matching the existing schema style."""
    return (
        f"\n### {tvm['name']}\n\n"
        f"\U0001f511 **Identifier** : `{tvm['uuid']}`\n\n"
        f"_Vocabulary_ : `Threat Vectors`\n\n"
        f"---\n\n"
        f"{tvm['name']}\n"
    )


def update_schema(schema_path: Path, tvms: list[dict]) -> bool:
    """Update the threats enum in the Detection Objective schema."""
    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)

    # Navigate to the threats field:
    # properties -> objective -> properties -> threats -> items -> enum
    try:
        threats_items = (
            schema["properties"]["objective"]["properties"]["threats"]["items"]
        )
    except KeyError:
        # Try alternate path through allOf/oneOf/if-then structures
        found = False
        for key in ("allOf", "oneOf", "anyOf"):
            if key in schema:
                for entry in schema[key]:
                    props = entry.get("properties", {})
                    if "objective" in props:
                        obj_props = props["objective"].get("properties", {})
                        if "threats" in obj_props:
                            threats_items = obj_props["threats"]["items"]
                            found = True
                            break
                    then = entry.get("then", {})
                    if then:
                        props = then.get("properties", {})
                        if "objective" in props:
                            obj_props = props["objective"].get("properties", {})
                            if "threats" in obj_props:
                                threats_items = obj_props["threats"]["items"]
                                found = True
                                break
            if found:
                break
        if not found:
            print("ERROR: Could not find threats.items in schema. Schema structure may have changed.")
            return False

    # Build new enum values and descriptions
    enum_values = [tvm["uuid"] for tvm in tvms]
    enum_descriptions = [build_enum_description(tvm) for tvm in tvms]

    # Update the schema
    threats_items["enum"] = enum_values
    threats_items["markdownEnumDescriptions"] = enum_descriptions

    # Write back
    with open(schema_path, "w", encoding="utf-8") as f:
        json.dump(schema, f, indent=4, ensure_ascii=False)
        f.write("\n")

    return True


def main():
    parser = argparse.ArgumentParser(
        description="Update Detection Objective schema threats enum with TVM UUIDs."
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help="Path to the InitTide repository root. Auto-detected if not provided.",
    )
    args = parser.parse_args()

    repo_root = args.repo_root or find_repo_root()
    schema_path = repo_root / "Schemas" / "Detection Objective.schema.json"
    objects_dir = repo_root / "Objects"

    if not schema_path.exists():
        print(f"ERROR: Schema file not found: {schema_path}")
        sys.exit(1)

    print(f"Repository root: {repo_root}")
    print(f"Schema file:     {schema_path}")
    print(f"Objects dir:     {objects_dir}")
    print()

    # Load all TVMs
    tvms = load_tvms(objects_dir)
    if not tvms:
        print("No TVM files found. Nothing to update.")
        sys.exit(0)

    print(f"Found {len(tvms)} TVM(s):")
    for tvm in tvms:
        print(f"  - {tvm['uuid']}  {tvm['name']}")
    print()

    # Update schema
    if update_schema(schema_path, tvms):
        print(f"Successfully updated threats enum with {len(tvms)} TVM UUID(s).")
    else:
        print("Failed to update schema.")
        sys.exit(1)


if __name__ == "__main__":
    main()
