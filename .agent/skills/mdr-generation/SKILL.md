---
description: Comprehensive workflow for generating OpenTide Detection Rule (MDR) YAML files from DOM signals with schema compliance
---

# MDR Generation Skill

This skill provides a systematic workflow for creating Detection Rules (MDRs) from Detection Objective (DOM) signals with proper Splunk Enterprise configuration and schema compliance.

## Prerequisites

Before generating an MDR, ensure you have:
1. ✅ A validated DOM file with one or more signals
2. ✅ Access to the MDR schema (`Schemas/MDR Schema.json`)
3. ✅ Access to the Splunk Sub Schema and template from CoreTide
4. ✅ Understanding of the target SIEM platform (Splunk, Sentinel, etc.)

## Workflow: DOM Signal → MDR

### Step 1: Select DOM Signal for Implementation

**Input Required:**
- DOM file path
- Signal UUID or signal name

**Actions:**
1. Open and review the DOM file
2. Identify the target signal to implement as an MDR
3. Extract key information from the signal:
   - Signal UUID (for `detection_model` field)
   - Signal name (for MDR `name` field)
   - Signal description
   - Severity level
   - Effort rating
   - Methodology
   - Data requirements
   - Entities involved

**Example:**
```yaml
# From DOM
signals:
  - name: LNK File Execution Invoking MSHTA
    uuid: da5a73a9-0d72-4c0b-b003-bce1e8c69be4
    severity: High
    effort: 1
    methodology: Behavioural
```

---

### Step 2: Generate Unique MDR UUID

**Command:**
```powershell
[guid]::NewGuid()
```

**Save the UUID** for the `metadata.uuid` field.

---

### Step 3: Create MDR Core Structure

Use the MDR template as a starting point. Required fields per `mdr::2.1` schema:

#### Core Required Fields

| Field | Description | Example |
|-------|-------------|---------|
| `name` | Verbose, human-readable name | "LNK File Execution Invoking MSHTA" |
| `metadata.uuid` | Unique identifier (generated in Step 2) | `edbc828b-6b51-4aa5-8d7f-c33c41b65282` |
| `metadata.schema` | Schema version | `mdr::2.1` |
| `metadata.version` | MDR version | `1.0` |
| `metadata.created` | Creation date | `YYYY-MM-DD` |
| `metadata.modified` | Last modified date | `YYYY-MM-DD` |
| `metadata.tlp` | Traffic Light Protocol | `amber` (lowercase!) |
| `metadata.author` | Author name | `InitTide Framework` |
| `description` | Detailed explanation of detection logic | Multi-line string |
| `detection_model` | Array of DOM signal UUIDs | `[da5a73a9-0d72-4c0b-b003-bce1e8c69be4]` |
| `response.alert_severity` | Alert severity from DOM signal | `High`, `Medium`, `Low`, `Informational` |
| `configurations` | SIEM-specific detection configuration | See Step 4 |

#### Optional But Recommended Fields

| Field | Description |
|-------|-------------|
| `response.procedure.analysis` | Step-by-step analysis guidance for SOC analysts |
| `response.procedure.containment` | Containment and remediation steps |
| `response.playbook` | URL to response playbook |
| `references` | Links to public/internal documentation |

> [!IMPORTANT]
> **Common Validation Errors to Avoid:**
> - `tlp` must be lowercase ( `amber`, not `AMBER`)
> - `detection_model` must be an **array** (use `[]`), even for single UUID
> - `metadata.author` is required in schema
> - `configurations` must use system identifier as key (e.g., `splunk:`)

---

### Step 4: Configure SIEM-Specific Detection (Splunk)

The `configurations` field uses a **system identifier** as the key to allow multi-platform deployment.

#### Structure

```yaml
configurations:
  splunk:    # System identifier key
    schema: splunk::2.1
    status: testing
    # ... Splunk-specific configuration
```

#### Splunk Configuration Fields

Reference: [Splunk Sub Schema](https://github.com/OpenTideHQ/CoreTide/blob/development/Framework/Meta%20Schemas/Sub%20Schemas/MDR%20Systems%20Deployment/Splunk%20Sub%20Schema.yaml)

##### Required Fields

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `schema` | string | Schema version | `splunk::2.1` |
| `status` | string | Development status | `testing`, `production`, `deprecated` |
| `query` | string (multiline) | SPL detection query | See SPL guidelines below |
| `scheduling.lookback` | string | Duration of logs to search | `15m`, `1h`, `24h` |
| `scheduling.frequency` OR `scheduling.cron` | string | Search interval | `5m` or `*/5 * * * *` |

##### Optional Fields (Include as Comments)

| Field | Description |
|-------|-------------|
| `threshold` | Event count before alert (default: 0) |
| `throttling.fields` | Fields to match for duplicate suppressionor suppression |
| `throttling.duration` | Throttle period (e.g., `1h`) |
| `contributors` | Email addresses of contributors |
| `notable` | Splunk ES Notable Event configuration |
| `risk` | Risk-Based Alerting configuration |

##### Splunk Template with Comments

Always include commented fields from the [Splunk Enterprise Template](https://github.com/OpenTideHQ/CoreTide/blob/development/Framework/Meta%20Schemas/Sub%20Schemas/MDR%20Systems%20Deployment/Templates/Splunk%20Enterprise%20Template.yaml):

```yaml
configurations:
  splunk:
    schema: splunk::2.1
    status: testing
    #contributors:
      #-
    threshold: 0
    
    #throttling:
      #fields:
        #-
      #duration: 1h
    
    scheduling:
      #cron: 
      frequency: 5m
      #custom_time: 
      lookback: 15m
    
    #notable:
      #event:
        #title: 
        #description: |
          #...
      #drilldown:
        #name: 
        #search: |
          #...
      #security_domain: 
    
    #risk:
      #message: 
      #risk_objects:
        #- field: 
          #type: 
          #score: 
      #threat_objects:
        #- field: 
          #type: 
    
    query: |
      ... SPL query here ...
```

---

### Step 5: Write SPL Query

Map the DOM signal's detection logic to Splunk SPL.

#### SPL Query Construction Guidelines

##### 1. **Data Source Selection**

Based on DOM signal's `data.requirements`:

| Entity Type | Splunk Index | Event Codes | Source Types |
|-------------|--------------|-------------|--------------|
| `host::Process` | `windows` | Sysmon: 1, Security: 4688 | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`, `WinEventLog:Security` |
| `host::File` | `windows` | Sysmon: 11, 2, 15 | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` |
| `network::Network Connection` | `windows`, `firewall` | Sysmon: 3 | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` |
| `cloud::*` | Platform-specific | N/A | `aws:cloudtrail`, `azure:aad:*`, `gcp:*` |

##### 2. **Field Normalization**

Handle variations between data sources:

```spl
| eval process_name=coalesce(Image, NewProcessName, process)
| eval parent_process=coalesce(ParentImage, ParentProcessName, parent_process)
| eval command_line=coalesce(CommandLine, ProcessCommandLine)
| eval user=coalesce(User, SubjectUserName, user)
```

##### 3. **Detection Logic**

Translate DOM signal description into filters:

**Example: LNK → mshta.exe → Remote HTA**

From DOM:
> "mshta.exe spawned by explorer.exe with command line containing http/https URLs"

To SPL:
```spl
(Image="*\\mshta.exe" OR NewProcessName="*\\mshta.exe")
(ParentImage="*\\explorer.exe" OR ParentProcessName="*\\explorer.exe")
(CommandLine="*http://*" OR CommandLine="*https://*")
```

##### 4. **Data Enrichment**

Extract key IOCs for analyst investigation:

```spl
| rex field=command_line "(?<url>https?://[^\\s\\\"']+)"
| rex field=command_line "(?<ip>\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b)"
```

##### 5. **Output Formatting**

Present relevant fields for analysis:

```spl
| table _time, computer, user, process_name, parent_process, command_line, url
| stats count by _time, computer, user, process_name, parent_process, command_line, url
```

#### Complete SPL Query Template

```spl
index=<index_name> sourcetype=<sourcetype>
EventCode=<event_codes>
<filter_logic>
| eval <field_normalization>
| rex field=<field> "<regex_extraction>"
| table _time, <output_fields>
| stats count by <deduplication_fields>
```

---

### Step 6: Write Response Procedures

Create detailed analyst guidance based on the DOM signal.

#### Analysis Procedure Structure

Minimum 3-5 steps following the investigation workflow:

1. **Verify** - Confirm the alert is valid (not false positive)
2. **Contextualize** - Understand the execution context
3. **Investigate** - Trace the attack chain
4. **Assess** - Determine scope and impact
5. **Escalate** - Define escalation criteria

**Template:**
```yaml
procedure:
  analysis: |
    1. **Verify [Initial Indicator]:**
       - Check X
       - Validate Y
       - Confirm Z
    
    2. **Contextualize [Event Context]:**
       - Review A
       - Examine B
    
    ... (continue for 3-5 steps)
```

#### Containment Procedure Structure

Minimum 4 phases:

1. **Immediate Actions** - Stop the threat
2. **Evidence Preservation** - Collect forensics
3. **Remediation** - Remove malicious artifacts
4. **Prevention** - Block future recurrence

---

### Step 7: Validate MDR Against Schema

Before finalizing, ensure schema compliance:

#### Required Validation Checks

1. ✅ YAML syntax is valid
2. ✅ All required fields present
3. ✅ `tlp` value is lowercase
4. ✅ `detection_model` is array format
5. ✅ `configurations` uses system identifier key
6. ✅ Splunk `schema` matches `splunk::2.1`
7. ✅ SPL query is syntactically valid

#### Expected Validation Warnings (Safe to Ignore)

- ⚠️ `detection_model` UUID validation errors - These will resolve once you complete Step 8 below

---

### Step 8: Update Schema Enums

After creating the MDR, run the schema update script to populate the `detection_model` enum in `MDR Schema.json` with all DOM signal UUIDs. This ensures that MDR files can reference DOM signals without validation errors.

**Run the script:**

```bash
python .agent/skills/mdr-generation/scripts/update_detection_model_enum.py
```

Or specify a custom repo root:

```bash
python .agent/skills/mdr-generation/scripts/update_detection_model_enum.py --repo-root /path/to/InitTide
```

The script will:
1. Scan all DOM files in `Objects/Detection Objectives/`
2. Extract each signal's `uuid` and `name`, along with the parent DOM name
3. Update the `detection_model.enum` array in `Schemas/MDR Schema.json`
4. Populate `markdownEnumDescriptions` with signal names and parent DOM names for editor autocomplete

> [!IMPORTANT]
> **Why This Step is Necessary**
>
> The MDR schema validates the `detection_model` field using an enum list that acts as a registry of all valid DOM signal UUIDs. This ensures referential integrity — MDRs can only reference DOM signals that actually exist in the framework.
>
> Without registration, the schema will show validation errors even though your MDR correctly references a valid DOM signal UUID.

**When to Run**:
- ✅ Run immediately after creating a new DOM or MDR
- ✅ Run whenever new DOM files with signals are added to the repository
- ✅ Safe to re-run — it rebuilds the full enum list from all existing DOM signals

**Expected Result**:
- The `detection_model` field validation errors will disappear
- Editor autocomplete will show signal names alongside their UUIDs
- Schema maintains a complete registry of all available detection signals



## Naming Conventions

- **File Name**: `MDR - [Signal Name].yaml`
  - Example: `MDR - LNK File Execution Invoking MSHTA.yaml`
- **Location**: `Objects/Detection Rules/`

---

## Complete MDR Example

See complete example: `Objects/Detection Rules/MDR - LNK File Execution Invoking MSHTA.yaml`

Key features:
- ✅ Schema-compliant `mdr::2.1` structure
- ✅ Splunk configuration with `splunk::2.1` schema
- ✅ All commented template fields included
- ✅ SPL query with field normalization
- ✅ Comprehensive analysis and containment procedures
- ✅ Links to source DOM signal via `detection_model`

---

## Quick Reference: Field Mapping

### DOM Signal → MDR Core

| DOM Field | MDR Field | Transformation |
|-----------|-----------|----------------|
| `signal.name` | `name` | Direct copy |
| `signal.uuid` | `detection_model[0]` | Wrap in array |
| `signal.severity` | `response.alert_severity` | Direct copy |
| `signal.description` | `description` | Expand with detection logic details |
| `signal.effort` | N/A | Referenced in scheduling decisions |
| `signal.methodology` | N/A | Informational, influences SPL approach |
| `signal.data.requirements` | `configurations.splunk.query` | Transform to SPL data source selection |
| `signal.entities` | `configurations.splunk.query` | Influences field extraction |

### Splunk API Parameter Mapping

| Splunk Config Field | REST API Parameter | Notes |
|---------------------|-------------------|-------|
| `scheduling.frequency` | `cron_schedule` | Converted to cron |
| `scheduling.cron` | `cron_schedule` | Used directly |
| `scheduling.lookback` | `dispatch.earliest_time` | Format: `-15m` |
| `threshold` | `alert_threshold` | Default: 0 |
| `throttling.fields` | `alert.suppress.fields` | Array of field names |
| `throttling.duration` | `alert.suppress.period` | Format: `1h` |
| `notable.*` | `action.notable.param.*` | Notable event config |
| `risk.*` | `action.risk.param.*` | RBA config |

---

## Common Pitfalls

### ❌ Don't Do This

1. **TLP in UPPERCASE** - Schema requires lowercase
   ```yaml
   tlp: AMBER  # Wrong!
   tlp: amber  # Correct
   ```

2. **detection_model as string** - Must be array
   ```yaml
   detection_model: uuid-string  # Wrong!
   detection_model: [uuid-string]  # Correct
   ```

3. **configurations without system key**
   ```yaml
   configurations:
     schema: splunk::2.1  # Wrong!
   
   configurations:
     splunk:
       schema: splunk::2.1  # Correct
   ```

4. **Missing commented template fields** - Always include for documentation
   ```yaml
   # Bad: Only active fields
   configurations:
     splunk:
       schema: splunk::2.1
       query: |
         ...
   
   # Good: Include commented optional fields
   configurations:
     splunk:
       schema: splunk::2.1
       #contributors:
         #-
       #throttling:
         #duration: 1h
       query: |
         ...
   ```

---

## Best Practices

1. **Start Simple** - Begin with core required fields, add optional later
2. **Test Incrementally** - Validate SPL query in Splunk before finalizing MDR
3. **Document Decisions** - Use commented fields to show available options
4. **Prioritize Usability** - Write procedures for analysts, not just detection logic
5. **Link to DOM** - Always include `detection_model` array with source signal UUID
6. **Version Control** - Increment `metadata.version` on significant changes
7. **Schema Compliance** - Validate after each edit to catch errors early

---

## Troubleshooting

### Validation Error: "Property X is not allowed"

**Cause**: Configurations field is missing system identifier key

**Fix**: Nest Splunk config under `splunk:` key
```yaml
configurations:
  splunk:  # Add this key!
    schema: splunk::2.1
    ...
```

### Validation Error: "Value is not accepted. Valid values: """

**Cause**: `detection_model` UUID not found in repository (expected during development)

**Fix**: Ignore this error until source DOM is committed. Ensure UUID is correct and in array format.

### SPL Query Not Matching Events

**Checklist**:
1. Verify index and sourcetype are correct
2. Check EventCode values match data source
3. Test field names in your Splunk environment (they may vary)
4. Add field normalization with `coalesce()`
5. Use `| head 10` to test incrementally

---

## Next Steps After MDR Creation

1. **Schema Validation** - Run MDR through validation (if available)
2. **SPL Testing** - Test query in Splunk with limited time range
3. **Tuning** - Adjust scheduling and lookback based on data volume
4. **Deployment** - Deploy via Splunk REST API or UI
5. **Monitoring** - Track false positive rate and adjust threshold
6. **Documentation** - Update runbooks with new detection procedures

---

## Additional Resources

- [MDR Schema](file:///d:/Detection%20Engineering/InitTide/Schemas/MDR%20Schema.json)
- [MDR Template](file:///d:/Detection%20Engineering/InitTide/Schemas/Templates/MDR%20TEMPLATE.yaml)
- [Splunk Sub Schema](https://github.com/OpenTideHQ/CoreTide/blob/development/Framework/Meta%20Schemas/Sub%20Schemas/MDR%20Systems%20Deployment/Splunk%20Sub%20Schema.yaml)
- [Splunk Enterprise Template](https://github.com/OpenTideHQ/CoreTide/blob/development/Framework/Meta%20Schemas/Sub%20Schemas/MDR%20Systems%20Deployment/Templates/Splunk%20Enterprise%20Template.yaml)
- [DOM Generation Skill](file:///d:/Detection%20Engineering/InitTide/.agent/skills/dom-generation/SKILL.md)
