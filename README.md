# az-policy-enum

Azure Policy enumeration script for red team and security assessment engagements. Walks the full Management Group → Subscription → Resource Group scope hierarchy and surfaces policy misconfigurations, DINE MSI blast radius, exemptions, and non-compliant resources.

Uses the current `az` CLI session.

## What it enumerates

- **Management group hierarchy** - all MGs visible to the current identity
- **Policy assignments** - at MG, subscription, and RG scope, including enforcement mode and notScopes
- **Custom policy definitions** - effect, defined-at scope, DINE/Modify flag
- **Custom initiatives** - constituent policies with effect overrides
- **Exemptions** - category, expiry, scope
- **DINE MSI blast radius** - role assignments held by each DeployIfNotExists/Modify managed identity
- **Non-compliant resources** - per policy, collapsed to `rg/type/name` format

## Findings

The script uses three severity levels:

| Prefix | Colour | Meaning |
|--------|--------|---------|
| `[+]` | Red | High - direct attack path or significant misconfiguration |
| `[+]` | Yellow | Medium - worth investigating, context-dependent |
| `[-]` | Cyan | Info - enumeration output, no immediate risk |
| `[!]` | Yellow | Warning - command failed or data unavailable |

Key findings surfaced:

- `DoNotEnforce` assignments - policy is evaluating but not blocking; findings exist in the compliance API even though resource creation is not denied
- `notScopes` - scopes excluded from policy enforcement; common source of unintended gaps
- DINE MSI with role assignments - the MSI's ARM permissions define the blast radius if the policy definition is poisoned or a remediation is triggered by an attacker
- DINE MSI with no role assignments - identity exists but is inoperative; could be granted roles by an attacker with sufficient ARM permissions

## Prerequisites

- `az` CLI installed and authenticated (`az login`)
- Python 3.6+
- Sufficient permissions to read policy state - Reader at the relevant scope is enough for most enumeration; DINE blast radius enumeration requires the ability to query role assignments at tenant scope

## Usage

```bash
python3 az_policy_enum.py
```

The script uses whichever subscription and identity is active in the current `az` CLI session. To target a specific subscription:

```bash
az account set --subscription <subscription-id>
python3 az_policy_enum.py
```

To target a different tenant:

```bash
az login --tenant <tenant-id>
python3 az_policy_enum.py
```

## Example output

```
════════════════════════════════════════════════════════════
  Current Identity
════════════════════════════════════════════════════════════
    [-] User:           dodgy.dave@example.com
    [-] Tenant:         52318b96-87fc-4231-8f87-uu6c5cb64323
    [-] Subscription:   dodgy-sub-prod (a7f3c291-84de-4b32-9f1e-8a2d657e3c10)

  ▸ Assignments @ Sub:dodgy-sub-prod
    [-] AKS-Compliance
    [-]   - Kubernetes cluster containers should only use allowed images (effect: Deny)
    [-]   - AKS naming convention (effect: Audit)
    [-]   - Azure Policy add-on for Kubernetes (effect: DeployIfNotExists)
    [+] notScopes (1): /subscriptions/.../rg-prod-shared
    [+] DINE MSI detected - principalId: b3d82f14-6c91-4a27-8e05-d1f749c23a87

════════════════════════════════════════════════════════════
  DINE MSI Blast Radius
════════════════════════════════════════════════════════════
  ▸ MSI: AKS-Compliance (b3d82f14-6c91-4a27-8e05-d1f749c23a87)
    [+] Azure Kubernetes Service Contributor Role @ /subscriptions/.../rg-prod-workloads
```

## Attack surface interpretation

**DINE MSI abuse path**: If an identity with `policyDefinitions/write` modifies the DINE policy definition to execute attacker-controlled ARM operations, and then triggers a remediation task, the MSI executes those operations. The MSI's role assignments define the blast radius. This does not require the MSI token to be directly accessible - the escalation path is through definition poisoning followed by remediation trigger.

**notScopes**: A resource group in notScopes is entirely exempt from the initiative. Resources deployed there are not subject to the Deny effect. Useful for identifying where policy enforcement gaps exist that could be used to deploy out-of-policy resources.

## Notes

- Defender for Cloud subscription-scope non-compliance is collapsed to a single summary line rather than listing individual plan findings
