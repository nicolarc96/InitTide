---
name: TVM Generation
description: Comprehensive workflow for generating OpenTide Threat Vector Model (TVM) YAML files from threat intelligence with schema compliance
---

# TVM Generation Skill

This skill provides a complete workflow for generating OpenTide Threat Vector Model (TVM) files from threat intelligence reports while ensuring schema compliance.

## Quick Reference

### Required Fields & Valid Values

#### Criticality
Valid values: `Baseline - Negligible`, `Baseline - Minor`, `Low`, `Medium`, `High`, `Severe`, `Emergency`

**Common choices**:
- `Medium` - Moderate impact threats
- `High` - Significant threats with substantial impact
- `Severe` - Critical threats requiring immediate attention

#### TLP (Traffic Light Protocol)
Valid values: `clear`, `green`, `amber`, `amber+strict`, `red`

**Default**: `clear` (for most threat intelligence)

#### Domains
Valid values: `Public Cloud`, `Private Cloud`, `Enterprise`, `Mobile`, `SaaS`, `Networking`, `OSINT`, `Embedded`, `IoT`, `Industrial`

**Common choice**: `Enterprise` (for most corporate/government threats)

#### Severity
Valid values: `Localised incident`, `Moderate incident`, `Substantial incident`, `Significant incident`, `Highly significant incident`, `National cyber emergency`

**Common choices**:
- `Moderate incident` - Standard threats
- `Substantial incident` - Serious targeted attacks
- `Significant incident` - APT campaigns

#### Leverage (STRIDE Threat Classification)
Valid values: `Spoofing`, `Tampering`, `Repudiation`, `Infrastructure Compromise`, `Information Disclosure`, `Dwelling`, `Denial of Service`, `Elevation of privilege`, `New Accounts`, `Hardware tampering`, `Alter behavior`, `Fraudulent transaction`, `Log tampering`, `Modify configuration`, `Modify privileges`, `Modify data`, `Software installation`, `Information Gathering`, `Process Manipulation`, `Safety Bypass`

**Common choices for phishing/malware**:
- `Spoofing` - Social engineering
- `Software installation` - Malware deployment
- `Information Disclosure` - Data theft capability
- `Elevation of privilege` - Privilege escalation

#### Impact
Valid values: `Nuisance`, `Impairement`, `Data Breach`, `IP Loss`, `Reputational Damages`, `Identity Theft`, `Monetary Loss`, `Lose Capabilities`, `Catastrophic Loss`, `National Security`, `Asset and fraud`, `Business disruption`, `Operating costs`, `Legal and regulatory`, `Competitive disadvantage`, `Loss of Safety`, `Loss of Control`, `Loss of View`, `Physical Damage`

**Common choices for APT/RAT**:
- `Data Breach` - Data exfiltration
- `Business disruption` - Operational impact
- `Lose Capabilities` - System compromise
- `Identity Theft` - Credential theft

#### Viability
Valid values: `Environment dependent`, `Almost no chance`, `Very Unlikely`, `Unlikely`, `Roughly even chance`, `Likely`, `Very Likely`, `Almost certain`

**Common choices**:
- `Likely` - Standard threat likelihood
- `Very Likely` - Well-documented, active threats

#### Targets (Asset Types)
Valid values: `Critical Documents`, `Personal Information`, `Cloud Storage Accounts`, `Key Store`, `Archival Database`, `Production Database`, `Identity Services`, `Compute Cluster`, `Workstations`, `Public-Facing Servers`, `Network Equipment`, `VPN Client`, `Virtual Machines`, `Serverless`, `Email Platform`, `Web Application Servers`, `API Endpoints`, `Cloud Portal`, `Firmware`, `Production Software`, `Development Pipelines`, `Software Containers`, `IaaS`, `Relational Database`, `NoSQL Database`, `Microservices`, `SAML-Joined Applications`, `Software Development Tools`, `Code Repositories`, `CI/CD Pipelines`, `Server Authentication`, `Server Backup`, `DHCP`, `Directory`, `DNS`, `Server Logs`, `Mainframe`, `Payment switch`, `POS controller`, `Print`, `Proxy`, `Remote access`, `Virtual Machines Host`, `Access reader`, `Camera`, `Firewall`, `HSM`, `IDS`, `Broadband`, `PBX`, `Private WAN`, `Public WAN`, `RTU`, `Router or switch`, `SAN`, `Telephone`, `VoIP adapter`, `LAN`, `WLAN`, `Auth token`, `Desktop`, `Laptop`, `Media`, `Mobile phone`, `Peripheral`, `POS terminal`, `Tablet`, `VoIP phone`, `ATM`, `PED pad`, `Gas terminal`, `Kiosk`, `Tapes`, `Disk media`, `Documents`, `Flash drive`, `Disk drive`, `Smart card`, `Payment card`, `Other`, `System admin`, `Auditor`, `Call center`, `Cashier`, `Customer`, `Developer`, `End-user`, `Executive`, `Finance`, `Former employee`, `Guard`, `Helpdesk`, `Human resources`, `Maintenance`, `Manager`, `Partner`, `Control Server`, `Data Historian`, `Engineering Workstation`, `Field Controller/RTU/PLC/IED`, `Human-Machine Interface`, `Input/Output Server`, `Safety Instrumented System/Protection Relay`, `Function-as-a-Service`, `Business Communication Tools`, `Windows API`, `OT Network Segment`, `Serial Communication Link`, `OT Historian`, `SCADA Master Station`

**Common choices for phishing/malware**:
- `End-user` - Human targets
- `Workstations` - Desktop/laptop systems
- `Email Platform` - Email infrastructure

---

## Workflow: Generate TVM from Threat Intelligence

### Step 1: Analyze Threat Intelligence

1. **Read the threat intelligence** report thoroughly
2. **Identify atomic TTPs** - Break down the attack into distinct, atomic techniques
3. **Extract key information**:
   - Threat actor names
   - MITRE ATT&CK techniques
   - Target organizations/sectors
   - Platforms (Windows, Linux, macOS, etc.)
   - Technical details for terrain description

### Step 2: Map Threat Actors to ATT&CK Group IDs

Use the helper script to map threat actor names to ATT&CK group identifiers:

```bash
python .agent/skills/tvm-generation/scripts/map_actors.py "APT36" "SideCopy"
```

**Output format**: `att&ck::G####`

**Important**: Always use the ATT&CK group identifier format in the `actors.name` field, NOT the common name.

### Step 3: Generate UUID

```powershell
[guid]::NewGuid().ToString()
```

### Step 4: Create TVM File

Use this template structure:

```yaml
name: [Concise descriptive name of the TTP]
criticality: [High|Medium|Severe]
references:
  public:
    1: [URL to threat intelligence source]

metadata:
  uuid: [Generated UUID]
  schema: tvm::2.1
  version: 1.0
  created: YYYY-MM-DD
  modified: YYYY-MM-DD
  tlp: clear
  author: Detection Engineering Team

threat:
  actors:
    - name: att&ck::G#### 
      sighting: |
        [Description of how this actor used the technique]
      references:
        - [URL]
  att&ck:
    - T#### # [Technique name]
  domains:
    - Enterprise
  terrain: |
    [Detailed technical description - keep concise but comprehensive]
  targets:
    - End-user
    - Workstations
    - Email Platform
  platforms:
    - Windows
  severity: Moderate incident
  leverage:
    - Spoofing
    - Software installation
    - Information Disclosure
  impact:
    - Data Breach
    - Business disruption
    - Lose Capabilities
  viability: Very Likely
  description: |
    [High-level summary of the threat vector]
```

### Step 5: Field-by-Field Guidance

#### Name
- Format: `[Action] via [Method] to [Outcome]`
- Example: `Phishing Delivery via LNK File Executing MSHTA to Deploy HTA-Embedded DLL Payload`
- Keep concise but descriptive

#### Criticality
- **High**: For well-documented APT techniques
- **Medium**: For standard malware techniques
- **Severe**: For zero-day or highly critical threats

#### Actors
- **ALWAYS** use `att&ck::G####` format from mapping script
- Include detailed `sighting` with context from threat intelligence
- Add references supporting the attribution

#### ATT&CK Techniques
- Map all relevant techniques in the attack chain
- Use format: `T#### # Comment explaining the technique`
- Include sub-techniques: `T####.### # Sub-technique name`

#### Terrain
- **Be concise** (per OpenTide guidelines) - avoid extremely long sections
- Focus on technical implementation details
- Explain the attack flow
- Highlight detection opportunities
- Use British English

#### Leverage
- Choose 3-5 relevant STRIDE classifications
- Match the attack characteristics

#### Impact
- Choose 3-5 impacts that represent consequences
- Focus on business/security outcomes

---

## Helper Scripts

### Actor Mapping Script

Location: `.agent/skills/tvm-generation/scripts/map_actors.py`

**Usage**:
```bash
python .agent/skills/tvm-generation/scripts/map_actors.py "Threat Actor Name"
```

**Output**: Returns ATT&CK group identifier or suggests close matches

---

## Common Patterns

### Phishing/Malware Delivery TVM
```yaml
criticality: High
domains: [Enterprise]
severity: Moderate incident
leverage: [Spoofing, Software installation, Information Disclosure]
impact: [Data Breach, Business disruption, Lose Capabilities]
viability: Very Likely
targets: [End-user, Workstations, Email Platform]
```

### RAT/Backdoor TVM
```yaml
criticality: High
domains: [Enterprise]
severity: Substantial incident
leverage: [Software installation, Information Disclosure, Elevation of privilege]
impact: [Data Breach, Lose Capabilities, Identity Theft]
viability: Very Likely
targets: [Workstations, Production Database, Critical Documents]
```

### Credential Harvesting TVM
```yaml
criticality: Medium
domains: [Enterprise]
severity: Moderate incident
leverage: [Spoofing, Information Disclosure]
impact: [Identity Theft, Data Breach]
viability: Likely
targets: [End-user, Identity Services]
```

---

## Validation Checklist

Before finalizing the TVM:

- [ ] UUID is unique and generated
- [ ] `criticality` uses capitalized value (High, not high)
- [ ] `tlp` is lowercase (`clear`, not `Clear`)
- [ ] `author` field is present in metadata
- [ ] Actor names use `att&ck::G####` format
- [ ] All `leverage` values are from STRIDE list
- [ ] All `impact` values are from impact enumeration
- [ ] `severity` matches incident classification format
- [ ] `viability` matches probability format
- [ ] `domains` uses valid domain values
- [ ] `targets` uses valid asset types
- [ ] Terrain section is concise and well-documented
- [ ] British English used consistently

---

## Tips

1. **One TTP per TVM**: Focus on atomic techniques, not entire campaigns
2. **Use the mapping script**: Saves time and ensures accuracy for actor IDs
3. **Keep terrain concise**: Comprehensive but not overly long
4. **Map all ATT&CK techniques**: Include the full attack chain
5. **Reference properly**: Always cite threat intelligence sources
6. **Validate early**: Check schema compliance as you build
