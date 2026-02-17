#!/usr/bin/env python3
"""
TVM Actor Mapping Helper
Maps common threat actor names to ATT&CK Group IDs
"""

import sys
import json
from difflib import get_close_matches

# ATT&CK Group ID mappings extracted from schema
ACTOR_MAPPINGS = {
    # APT Groups
    "APT1": "att&ck::G0006",
    "APT5": "att&ck::G1023",
    "APT12": "att&ck::G0005",
    "APT16": "att&ck::G0023",
    "APT17": "att&ck::G0025",
    "APT18": "att&ck::G0026",
    "APT19": "att&ck::G0073",
    "APT28": "att&ck::G0007",
    "APT29": "att&ck::G0016",
    "APT3": "att&ck::G0022",
    "APT30": "att&ck::G0013",
    "APT32": "att&ck::G0050",
    "APT33": "att&ck::G0064",
    "APT34": "att&ck::G0049",
    "APT35": "att&ck::G0059",
    "APT36": "att&ck::G0134",
    "APT37": "att&ck::G0067",
    "APT38": "att&ck::G0082",
    "APT39": "att&ck::G0087",
    "APT40": "att&ck::G0065",
    "APT41": "att&ck::G0096",
    "APT42": "att&ck::G1044",
    "APT43": "att&ck::G0094",
    
    # Named Groups
    "TRANSPARENT TRIBE": "att&ck::G0134",
    "MYTHIC LEOPARD": "att&ck::G0134",
    "COPPER FIELDSTONE": "att&ck::G0134",
    "SIDECOPY": "att&ck::G1008",
    "LAZARUS GROUP": "att&ck::G0032",
    "LAZARUS": "att&ck::G0032",
    "KIMSUKY": "att&ck::G0094",
    "VOLT TYPHOON": "att&ck::G1017",
    "BRONZE SILHOUETTE": "att&ck::G1017",
    "MUSTANG PANDA": "att&ck::G0129",
    "BRONZE PRESIDENT": "att&ck::G0129",
   
 "SANDWORM": "att&ck::G0034",
    "FANCY BEAR": "att&ck::G0007",
    "COZY BEAR": "att&ck::G0016",
    "TURLA": "att&ck::G0010",
    "DRAGONFLY": "att&ck::G0035",
    "ENERGETIC BEAR": "att&ck::G0035",
    "EQUATION GROUP": "att&ck::G0020",
    "CARBANAK": "att&ck::G0008",
    "FIN7": "att&ck::G0046",
    "FIN8": "att&ck::G0061",
    "FIN10": "att&ck::G0051",
    "FIN13": "att&ck::G1016",
    "LEVIATHAN": "att&ck::G0065",
    "OILRIG": "att&ck::G0049",
    "MAGIC HOUND": "att&ck::G0059",
    "CHARMING KITTEN": "att&ck::G0059",
    "GALLIUM": "att&ck::G0093",
    "GRANITE TYPHOON": "att&ck::G0093",
    "HAFNIUM": "att&ck::G0125",
    "SILK TYPHOON": "att&ck::G0125",
    "MUDDYWATER": "att&ck::G0069",
    "MANGO SANDSTORM": "att&ck::G0069",
    "NAIKON": "att&ck::G0019",
    "OCEAN LOTUS": "att&ck::G0050",
    "OCEANLOTUS": "att&ck::G0050",
    "PATCHWORK": "att&ck::G0040",
    "DROPPING ELEPHANT": "att&ck::G0040",
    "ROCKE": "att&ck::G0106",
    "SCARLET MIMIC": "att&ck::G0029",
    "STEALTH FALCON": "att&ck::G0038",
    "THREAT GROUP-3390": "att&ck::G0027",
    "TG-3390": "att&ck::G0027",
    "TICK": "att&ck::G0060",
    "BRONZE BUTLER": "att&ck::G0060",
    "WIZARD SPIDER": "att&ck::G0102",
    "TEMP.MIXMASTER": "att&ck::G0102",
    "GRIM SPIDER": "att&ck::G0102",
    "INDRIK SPIDER": "att&ck::G0119",
    "EVIL CORP": "att&ck::G0119",
    
    # Add more as needed
}

# Alias mappings for common variations
ALIASES = {
    "APT 36": "APT36",
    "APT-36": "APT36",
    "SIDECOP": "SIDECOPY",
    "SIDE COPY": "SIDECOPY",
    "TRANSPARENT-TRIBE": "TRANSPARENT TRIBE",
}


def normalize_name(name):
    """Normalize actor name for matching"""
    name = name.upper().strip()
    # Check aliases first
    if name in ALIASES:
        name = ALIASES[name]
    return name


def map_actor(actor_name):
    """Map threat actor name to ATT&CK Group ID"""
    normalized = normalize_name(actor_name)
    
    if normalized in ACTOR_MAPPINGS:
        return ACTOR_MAPPINGS[normalized]
    
    # Try fuzzy matching
    all_names = list(ACTOR_MAPPINGS.keys())
    matches = get_close_matches(normalized, all_names, n=3, cutoff=0.6)
    
    if matches:
        return {
            "query": actor_name,
            "exact_match": None,
            "suggestions": [
                {"name": match, "id": ACTOR_MAPPINGS[match]}
                for match in matches
            ]
        }
    
    return {
        "query": actor_name,
        "exact_match": None,
        "suggestions": [],
        "error": "No matching ATT&CK group found"
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: python map_actors.py <actor_name1> [actor_name2] ...")
        print("\nExample: python map_actors.py 'APT36' 'SideCopy'")
        sys.exit(1)
    
    results = []
    for actor_name in sys.argv[1:]:
        result = map_actor(actor_name)
        
        if isinstance(result, str):
            # Exact match
            print(f"{actor_name} -> {result}")
            results.append({"actor": actor_name, "id": result})
        else:
            # No exact match or suggestions
            print(f"\n{actor_name}:")
            if result.get("suggestions"):
                print("  Did you mean:")
                for suggestion in result["suggestions"]:
                    print(f"    - {suggestion['name']} -> {suggestion['id']}")
            else:
                print(f"  ❌ {result.get('error', 'Unknown error')}")
            
            results.append(result)
    
    # Output JSON for programmatic use
    if len(sys.argv) > 2:
        print("\n--- JSON Output ---")
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
