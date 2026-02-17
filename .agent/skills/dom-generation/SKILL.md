---
name: DOM Generation
description: Comprehensive workflow for generating OpenTide Detection Objective (DOM) YAML files from Threat Vector Models with schema compliance
---

# DOM Generation Skill

## Overview

This skill provides a comprehensive workflow for generating Detection Objective (DOM) YAML files from existing Threat Vector Model (TVM) files in the OpenTide framework. It ensures schema compliance and uses validated field values from the DOM schema.

## When to Use This Skill

- When generating Detection Objectives from existing TVMs
- When the user requests creation of detection signals or objectives
- When following the OpenTide top-down workflow: TVM → DOM → MDR

## Prerequisites

- Existing TVM file(s) to generate DOM from
- Access to the DOM schema and template files
- Ability to generate UUIDs using PowerShell

## Schema-Compliant Field Values

### Required Fields

#### metadata section
- `uuid`: Generated via `[guid]::NewGuid()` in PowerShell
- `schema`: `"dom::1.0"` (fixed value)
- `version`: Numeric version, start with `1.0`
- `created`: `YYYY-MM-DD` format
- `modified`: `YYYY-MM-DD` format
- `tlp`: Traffic Light Protocol - `"clear"`, `"white"`, `"green"`, `"amber"`, `"red"`

#### objective section
- `priority`: `"Low"`, `"Medium"`, `"High"`, `"Critical"`
- `type`: `"Threat"`, `"Hunt"`, `"Compliance"`, `"Baseline"`
- `threats`: Array of TVM UUIDs (e.g., `["8f88da38-ac40-4c93-b7b0-696ec02cea7a"]`)

### Composition Strategy (CRITICAL)
Valid values for `objective.composition.strategy`:
- `"Independent"` - Signals work independently
- `"Combined"` - Multiple signals must fire together
- `"Threshold"` - Threshold-based detection
- `"Entity"` - Entity-based correlation
- `"Sequence"` - Sequential event detection
- `"Risk"` - Risk-scoring approach

⚠️ **DO NOT USE**: "Defense in Depth", "Layered", or other custom values

### Signal Fields

Each signal in `objective.signals` must include:

#### Required Signal Fields
- `name`: Descriptive name of the detection signal
- `uuid`: Generated via `[guid]::NewGuid()`
- `description`: Multi-line detailed description
- `severity`: `"Informational"`, `"Low"`, `"Medium"`, `"High"`, `"Critical"`
- `effort`: **NUMBER** (1-5, where 1=Low, 2=Low-Medium, 3=Medium, 4=Medium-High, 5=High)
- `methodology`: See methodology values below
- `data.availability`: See availability values below
- `data.requirements`: Multi-line description of data requirements
- `entities`: Array of namespaced entity types (see below)

#### Effort Mapping
**CRITICAL**: Use numeric values, NOT text!
- `1` = Low effort
- `2` = Low-Medium / Medium-Low effort
- `3` = Medium effort
- `4` = Medium-High effort
- `5` = High effort

#### Methodology (CRITICAL)
Valid values for `signals[].methodology`:
- `"Artifacts"`
- `"Pattern Matching"`
- `"Event Search"`
- `"Statistical"`
- `"Behavioural"` (British spelling!)
- `"Anomaly"`
- `"Machine Learning"`
- `"Heuristic"`
- `"Threat Intelligence"`
- `"Frequency Analysis"`

⚠️ **DO NOT USE**: "Correlation" (not valid - use "Behavioural" or "Statistical" instead)

#### Data Availability (CRITICAL)
Valid values for `signals[].data.availability`:
- `"Unknown"` - Availability is unknown
- `"Not Available"` - Data is not available in most environments
- `"Partial"` - Data is partially available (requires configuration)
- `"Complete"` - Data is completely available in most environments

⚠️ **DO NOT USE**: "Usually", "Rarely", "Sometimes", "Always"

#### Entity Types (CRITICAL - Must be Namespaced!)

All entity values MUST use the `namespace::Entity` format:

**Host Entities:**
- `"host::Account"`
- `"host::Hostname"`
- `"host::Process"`
- `"host::Command Line"`
- `"host::File"`
- `"host::File Hash"`
- `"host::Registry Key/Value"`
- `"host::Domain"`
- `"host::Email"`
- `"host::Geolocation"`
- `"host::Device Type"`
- `"host::Token"`
- `"host::Software"`
- `"host::Authentication"`
- `"host::Service"`
- `"host::Scheduled Task"`
- `"host::Permissions"`

**Network Entities:**
- `"network::IP Address"`
- `"network::URL"`
- `"network::Email"`
- `"network::Protocol"`
- `"network::Network Connection"`
- `"network::Port"`
- `"network::Session"`
- `"network::Certificate"`
- `"network::DNS Query"`
- `"network::API Call"`

**Cloud Entities:**
- `"cloud::Account"`
- `"cloud::Resource"`
- `"cloud::Token"`
- `"cloud::API Call"`
- `"cloud::Authentication"`
- `"cloud::Permissions"`

⚠️ **DO NOT USE**: Unnamespaced values like "Process", "File", "User", "Network", "DNS" etc.

## DOM Generation Workflow

### Step 1: Review Source TVM

1. Read the source TVM file to understand:
   - The threat vector name and description
   - ATT&CK techniques involved
   - Attack stages and TTPs
   - Detection opportunities
   - TVM UUID for linkage

### Step 2: Generate UUIDs

Generate UUIDs for the DOM and all signals:

```powershell
# Generate DOM UUID
[guid]::NewGuid()

# Generate multiple signal UUIDs (adjust count as needed)
1..5 | ForEach-Object { [guid]::NewGuid() }
```

### Step 3: Identify Detection Signals

Analyze the TVM to identify distinct detection signals. Consider:

- **Attack stages**: Initial execution, payload delivery, persistence, C2, etc.
- **Technical indicators**: Process behaviour, network connections, file operations
- **Data availability**: What telemetry is realistically available?
- **Coverage strategy**: How do signals work together?

Typically aim for 3-7 signals per DOM that cover:
- Early attack stages (high priority, easier to implement)
- Mid-stage activity (moderate priority, moderate implementation)
- Late-stage activity (informational, may be harder to implement)

### Step 4: Create DOM File Structure

```yaml
name: [Name matching or derived from TVM name]

references:
  public:
    1: [URL from TVM or related intelligence]

metadata:
  uuid: [Generated UUID]
  schema: dom::1.0
  version: 1.0
  created: YYYY-MM-DD
  modified: YYYY-MM-DD
  tlp: clear
  author: Detection Engineering Team

objective:
  priority: High  # or Medium, Low, Critical
  att&ck:
    - [Copy ATT&CK techniques from TVM]
  type: Threat
  threats:
    - [TVM UUID]
  description: |
    [Multi-line description of what this DOM aims to detect,
     referencing the threat vector and actor TTPs]

  composition:
    strategy: Combined  # or Independent, Threshold, Entity, Sequence, Risk
    description: |
      [Explain how the signals work together and the overall
       detection strategy approach]

  signals:
    - name: [Signal Name]
      uuid: [Generated UUID]
      description: |
        [Detailed description of what this signal detects,
         including key indicators and detection logic]
      severity: High  # Informational, Low, Medium, High, Critical
      effort: 1  # NUMBER: 1-5
      methodology: Behavioural  # See valid values above
      data:
        availability: Complete  # Unknown, Not Available, Partial, Complete
        requirements: |
          [Specific data sources needed, e.g.:
           - Sysmon Event ID X
           - Windows Security Event ID Y
           - Network flow logs
           etc.]
      entities:
        - host::Process
        - host::File
        - network::Network Connection
```

### Step 5: Define Each Signal

For each signal, ensure:

1. **Name**: Clear, concise, describes the detection
2. **Description**: Detailed explanation including:
   - What behaviour is detected
   - Key indicators to look for
   - Attack stage it covers
   - Context for analysts
3. **Severity**: Based on impact and confidence
4. **Effort**: Realistic implementation effort (1-5)
5. **Methodology**: Appropriate detection technique
6. **Data Requirements**: Specific log sources and events
7. **Entities**: Correct namespaced entity types

### Step 6: Validate Against Schema

Before saving, verify:

✅ All UUIDs are unique and properly formatted
✅ `effort` values are numbers (1-5), not text
✅ `availability` uses valid enum values
✅ `methodology` uses valid enum values
✅ `strategy` uses valid enum values
✅ `entities` all use `namespace::Entity` format
✅ `threats` array contains source TVM UUID
✅ ATT&CK techniques are formatted as `T####` or `T####.###`

### Step 7: Place File in Correct Location

Save the DOM file to:
```
Objects/Detection Objectives/DOM - [Name].yaml
```

File naming convention: `DOM - [Descriptive Name].yaml`

### Step 8: Update Schema Enums

After creating the DOM, run the schema update script to populate the `threats` enum in `Detection Objective.schema.json` with all TVM UUIDs. This ensures that DOM files can reference TVMs without validation errors.

**Run the script:**

```bash
python .agent/skills/dom-generation/scripts/update_threats_enum.py
```

Or specify a custom repo root:

```bash
python .agent/skills/dom-generation/scripts/update_threats_enum.py --repo-root /path/to/InitTide
```

The script will:
1. Scan all TVM files in `Objects/Threat Vectors/`
2. Extract each TVM's `metadata.uuid` and `name`
3. Update the `threats.items.enum` array in `Schemas/Detection Objective.schema.json`
4. Populate `markdownEnumDescriptions` with TVM names for editor autocomplete

> [!IMPORTANT]
> **Why This Step is Necessary**
>
> The DOM schema validates the `threats` field using an enum list of valid TVM UUIDs. Without registration, DOMs referencing new TVMs will show validation errors even though the UUIDs are valid.
>
> This is a framework design pattern that ensures referential integrity across object types (TVM → DOM → MDR).

**When to Run**:
- ✅ Run immediately after creating a new TVM or DOM
- ✅ Run whenever new TVM files are added to the repository
- ✅ Safe to re-run — it rebuilds the full enum list from all existing TVMs

**Expected Result**:
- The `threats` field in DOMs will validate correctly against all existing TVM UUIDs
- Editor autocomplete will show TVM names alongside their UUIDs



## Common Pitfalls to Avoid

❌ **DON'T** use text values for `effort` field (use numbers 1-5)
❌ **DON'T** use "Usually", "Rarely" for availability (use Complete, Partial, etc.)
❌ **DON'T** use unnamespaced entities like "Process" or "File"
❌ **DON'T** use "Correlation" for methodology (use "Behavioural" or "Statistical")
❌ **DON'T** use custom strategy values like "Defense in Depth"
❌ **DON'T** forget to link to source TVM via UUID in `threats` field
❌ **DON'T** reuse UUIDs from other objects

✅ **DO** generate fresh UUIDs for DOM and all signals
✅ **DO** use British spelling "Behavioural" (not "Behavioral")
✅ **DO** use numeric effort values (1-5)
✅ **DO** namespace all entities (host::, network::, cloud::)
✅ **DO** validate all enum fields against schema
✅ **DO** provide detailed signal descriptions with context
✅ **DO** specify realistic, concrete data requirements

## Example Signal Patterns

### High-Confidence, Low-Effort Signal
```yaml
- name: Suspicious Process Execution Pattern
  uuid: [UUID]
  description: |
    Detects anomalous process execution patterns indicative of
    [specific attack behaviour]. High-confidence signal with
    low implementation effort.
  severity: High
  effort: 1  # Low effort
  methodology: Pattern Matching
  data:
    availability: Complete
    requirements: |
      Process creation events (Sysmon Event ID 1)
  entities:
    - host::Process
    - host::Command Line
```

### Medium-Confidence, Medium-Effort Signal
```yaml
- name: Network Connection to Suspicious Domain
  uuid: [UUID]
  description: |
    Identifies network connections to domains with low reputation
    or unusual characteristics, requiring threat intelligence integration.
  severity: Medium
  effort: 3  # Medium effort
  methodology: Threat Intelligence
  data:
    availability: Partial
    requirements: |
      Network connection events (Sysmon Event ID 3)
      DNS resolution events (Sysmon Event ID 22)
      Threat intelligence feeds
  entities:
    - host::Process
    - network::Network Connection
    - network::DNS Query
```

### Advanced Detection Signal
```yaml
- name: Multi-Stage Attack Chain Correlation
  uuid: [UUID]
  description: |
    Correlates multiple events across attack stages to identify
    complete attack chain execution. Requires advanced SIEM correlation.
  severity: Critical
  effort: 5  # High effort
  methodology: Behavioural
  data:
    availability: Partial
    requirements: |
      Process creation, file operations, network connections
      Registry modifications, authentication events
      Correlation engine with temporal analysis
  entities:
    - host::Process
    - host::File
    - host::Registry Key/Value
    - network::Network Connection
    - host::Authentication
```

## Signal Prioritization Guidelines

When creating signals, prioritize in this order:

1. **High Severity + Low Effort (effort: 1-2)**: Implement first
   - Quick wins with significant impact
   - Process-based detections with clear indicators

2. **High/Critical Severity + Medium Effort (effort: 3)**: High priority
   - Important detections requiring moderate configuration
   - Network-based detections with TI integration

3. **Medium Severity + Low/Medium Effort**: Standard priority
   - Good coverage for common attack variations
   - Provides defense in depth

4. **Any Severity + High Effort (effort: 4-5)**: Lower priority
   - Advanced correlation and ML-based detections
   - Document for future implementation when resources available

## Post-Generation Steps

After creating the DOM:

1. **Schema Validation**: Verify the file passes schema validation
2. **Peer Review**: Have detection engineering team review signals
3. **Data Source Verification**: Confirm required data is available
4. **Follow-Up Planning**: Identify which MDRs should be created first
5. **Documentation**: Update walkthrough with generation details

## Next Steps After DOM Creation

Following OpenTide top-down workflow:

1. **Created TVM** ✅
2. **Created DOM** ✅ (current step)
3. **Create MDR**: Next step - generate Detection Rules from DOM signals

When ready to create MDRs, focus on:
- High severity, low effort signals first
- Signals where data is readily available (Complete availability)
- Signals using simpler methodologies (Pattern Matching, Event Search)
