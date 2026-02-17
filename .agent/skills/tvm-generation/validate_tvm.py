#!/usr/bin/env python3
"""
OpenTide TVM Validator

Validates Threat Vector Model (TVM) YAML files against the TVM JSON schema.
Usage: python validate_tvm.py <path_to_tvm_file>
"""

import sys
import json
import yaml
from pathlib import Path
from jsonschema import validate, ValidationError, SchemaError
from typing import Dict, Any, Tuple


def normalize_references(data: Dict[Any, Any]) -> Dict[Any, Any]:
    """Convert integer keys in references.public/internal to strings (YAML quirk)."""
    if 'references' in data:
        refs = data['references']
        if 'public' in refs and isinstance(refs['public'], dict):
            refs['public'] = {str(k): v for k, v in refs['public'].items()}
        if 'internal' in refs and isinstance(refs['internal'], dict):
            refs['internal'] = {str(k): v for k, v in refs['internal'].items()}
    return data


def normalize_dates(data: Dict[Any, Any]) -> Dict[Any, Any]:
    """Convert date objects to ISO format strings (YAML date parsing)."""
    import datetime
    if 'metadata' in data:
        meta = data['metadata']
        for field in ['created', 'modified']:
            if field in meta and isinstance(meta[field], datetime.date):
                meta[field] = meta[field].isoformat()
    return data


def load_yaml(file_path: Path) -> Tuple[Dict[Any, Any], str]:
    """Load and parse YAML file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        # Normalize integer keys in references
        data = normalize_references(data)
        # Normalize YAML dates to strings
        data = normalize_dates(data)
        return data, None
    except yaml.YAMLError as e:
        return None, f"YAML parsing error: {str(e)}"
    except FileNotFoundError:
        return None, f"File not found: {file_path}"
    except Exception as e:
        return None, f"Error reading file: {str(e)}"


def load_schema(schema_path: Path) -> Tuple[Dict[Any, Any], str]:
    """Load JSON schema file."""
    try:
        with open(schema_path, 'r', encoding='utf-8') as f:
            schema = json.load(f)
        return schema, None
    except json.JSONDecodeError as e:
        return None, f"Schema JSON parsing error: {str(e)}"
    except FileNotFoundError:
        return None, f"Schema file not found: {schema_path}"
    except Exception as e:
        return None, f"Error reading schema: {str(e)}"


def validate_tvm(tvm_data: Dict[Any, Any], schema: Dict[Any, Any]) -> Tuple[bool, str]:
    """Validate TVM data against schema."""
    try:
        validate(instance=tvm_data, schema=schema)
        return True, "[PASS] TVM validation passed - file is schema compliant"
    except ValidationError as e:
        error_path = " > ".join([str(p) for p in e.path]) if e.path else "root"
        error_msg = f"""
[FAIL] TVM validation failed

Error location: {error_path}
Error message: {e.message}

Validator: {e.validator}
Failed value: {e.instance}
"""
        return False, error_msg
    except SchemaError as e:
        return False, f"Schema itself is invalid: {str(e)}"


def print_summary(tvm_data: Dict[Any, Any]):
    """Print summary of TVM contents."""
    print("\nTVM Summary:")
    print(f"  Name: {tvm_data.get('name', 'N/A')}")
    print(f"  Criticality: {tvm_data.get('criticality', 'N/A')}")
    
    metadata = tvm_data.get('metadata', {})
    print(f"  UUID: {metadata.get('uuid', 'N/A')}")
    print(f"  Schema: {metadata.get('schema', 'N/A')}")
    print(f"  TLP: {metadata.get('tlp', 'N/A')}")
    print(f"  Author: {metadata.get('author', 'N/A')}")
    
    threat = tvm_data.get('threat', {})
    att_ack = threat.get('att&ck', [])
    print(f"  ATT&CK Techniques: {len(att_ack)} mapped")
    
    actors = threat.get('actors', [])
    print(f"  Threat Actors: {len(actors)} attributed")
    
    domains = threat.get('domains', [])
    print(f"  Domains: {', '.join(domains) if domains else 'N/A'}")
    
    platforms = threat.get('platforms', [])
    print(f"  Platforms: {', '.join(platforms) if platforms else 'N/A'}")
    
    print(f"  Severity: {threat.get('severity', 'N/A')}")
    print(f"  Viability: {threat.get('viability', 'N/A')}")


def main():
    """Main validation function."""
    if len(sys.argv) < 2:
        print("Usage: python validate_tvm.py <path_to_tvm_file>")
        print("\nExample:")
        print('  python validate_tvm.py "Objects/Threat Vectors/TVM - Example.yaml"')
        sys.exit(1)
    
    tvm_file = Path(sys.argv[1])
    script_dir = Path(__file__).parent
    
    # Try to find schema file relative to script location or workspace root
    possible_schema_paths = [
        script_dir / "Schemas" / "TVM Schema.json",
        script_dir.parent / "Schemas" / "TVM Schema.json",
        script_dir.parent.parent / "Schemas" / "TVM Schema.json",
        Path("Schemas/TVM Schema.json"),
    ]
    
    schema_path = None
    for path in possible_schema_paths:
        if path.exists():
            schema_path = path
            break
    
    if not schema_path:
        print("[ERROR] Could not find 'TVM Schema.json'")
        print("\nSearched in:")
        for path in possible_schema_paths:
            print(f"  - {path}")
        sys.exit(1)
    
    print(f"\nValidating TVM file: {tvm_file}")
    print(f"Using schema: {schema_path}\n")
    
    # Load TVM file
    tvm_data, error = load_yaml(tvm_file)
    if error:
        print(f"[ERROR] {error}")
        sys.exit(1)
    
    # Load schema
    schema, error = load_schema(schema_path)
    if error:
        print(f"❌ {error}")
        sys.exit(1)
    
    # Validate
    is_valid, message = validate_tvm(tvm_data, schema)
    
    if is_valid:
        print(message)
        print_summary(tvm_data)
        sys.exit(0)
    else:
        print(message)
        print("\nCommon issues:")
        print("  - Missing required fields: criticality, threat, metadata")
        print("  - Invalid enum values (check criticality, severity, TLP, etc.)")
        print("  - Missing threat subfields: att&ck, terrain, domains, targets, platforms")
        print("  - Invalid threat actor format (must be 'att&ck::GXXXX' or 'misp::UUID')")
        print("  - Invalid UUID format (must be UUIDv4)")
        print("\nSee TVM generation skill for valid enum values:")
        print("  .agent/skills/tvm-generation/SKILL.md")
        sys.exit(1)


if __name__ == "__main__":
    main()
