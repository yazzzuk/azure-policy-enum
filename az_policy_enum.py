#!/usr/bin/env python3
"""
Azure Policy Enumerator
Walks MG → Subscription → Resource Group and enumerates:
  - Policy assignments (including DINE MSIs and notScopes)
  - Custom policy definitions
  - Custom initiatives (policy sets)
  - Exemptions
  - DINE MSI role assignments (blast radius)

Uses current az CLI session. No additional auth required.
"""

import subprocess
import json
import sys
from collections import defaultdict

# ── Colour helpers ────────────────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def banner(text):
    print(f"\n{BOLD}{CYAN}{'═' * 60}{RESET}")
    print(f"{BOLD}{CYAN}  {text}{RESET}")
    print(f"{BOLD}{CYAN}{'═' * 60}{RESET}")

def section(text):
    print(f"\n{BOLD}{YELLOW}  ▸ {text}{RESET}")

def finding(text, level="info"):
    colour = RED if level == "high" else YELLOW if level == "med" else GREEN
    print(f"    {colour}[+]{RESET} {text}")

def warn(text):
    print(f"    {YELLOW}[!]{RESET} {text}")

def info(text):
    print(f"    {CYAN}[-]{RESET} {text}")

# ── az CLI helpers ────────────────────────────────────────────────────────────
def az(args, ignore_errors=False):
    """Run an az CLI command, return parsed JSON or None on failure."""
    cmd = ["az"] + args + ["--output", "json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            if not ignore_errors:
                warn(f"Command failed: az {' '.join(args)}")
                warn(f"  {result.stderr.strip()[:200]}")
            return None
        return json.loads(result.stdout) if result.stdout.strip() else None
    except subprocess.TimeoutExpired:
        warn(f"Timeout: az {' '.join(args)}")
        return None
    except json.JSONDecodeError:
        warn(f"Could not parse JSON from: az {' '.join(args)}")
        return None

def az_rest(url):
    """Call az rest GET, return parsed JSON or None."""
    result = subprocess.run(
        ["az", "rest", "--method", "GET", "--url", url],
        capture_output=True, text=True, timeout=30
    )
    if result.returncode != 0:
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None

# ── Scope enumeration ─────────────────────────────────────────────────────────
def get_current_identity():
    banner("Current Identity")
    account = az(["account", "show"])
    if not account:
        print(f"{RED}Could not determine current identity. Is az login done?{RESET}")
        sys.exit(1)
    info(f"User:           {account.get('user', {}).get('name', 'unknown')}")
    info(f"Tenant:         {account.get('tenantId', 'unknown')}")
    info(f"Subscription:   {account.get('name', 'unknown')} ({account.get('id', 'unknown')})")
    return account

def get_management_groups():
    banner("Management Group Hierarchy")
    mgs = az(["account", "management-group", "list", "--no-register"], ignore_errors=True)
    if not mgs:
        warn("No management group visibility from this identity (sub-level only)")
        return []
    for mg in mgs:
        info(f"MG: {mg.get('displayName', '?')} ({mg.get('name', '?')})")
    return mgs

def get_subscriptions():
    subs = az(["account", "list"])
    return subs or []

def get_resource_groups(sub_id):
    rgs = az(["group", "list", "--subscription", sub_id], ignore_errors=True)
    return rgs or []

# ── Policy enumeration ────────────────────────────────────────────────────────
def enum_assignments(scope, scope_label, initiative_map=None):
    section(f"Assignments @ {scope_label}")
    assignments = az(["policy", "assignment", "list", "--scope", scope], ignore_errors=True)
    if not assignments:
        info("No assignments visible at this scope")
        return []

    dine_identities = []

    for a in assignments:
        name = a.get("displayName") or a.get("name", "unnamed")
        not_scopes = a.get("notScopes", [])
        identity = a.get("identity")
        enforcement = a.get("enforcementMode", "Default")
        policy_def_id = a.get("policyDefinitionId", "")

        info(f"{name}")

        # If backed by an initiative, expand constituent policies
        if "/policySetDefinitions/" in policy_def_id:
            initiative_guid = policy_def_id.split("/")[-1]
            policies = initiative_map.get(initiative_guid, []) if initiative_map else []
            for p in policies:
                info(f"  - {p}")

        if enforcement == "DoNotEnforce":
            finding(f"enforcementMode: DoNotEnforce - policy is audit-only, not enforced", "med")

        if not_scopes:
            finding(f"notScopes ({len(not_scopes)}): {', '.join(not_scopes)}", "med")

        if identity and identity.get("type") in ("SystemAssigned", "UserAssigned"):
            principal_id = identity.get("principalId", "unknown")
            finding(f"DINE MSI detected - principalId: {principal_id}", "high")
            dine_identities.append({"name": name, "principalId": principal_id})

    return dine_identities

def resolve_scope_name(scope, sub_map=None):
    """Convert a raw scope path to a human-readable label."""
    if not scope or scope == "unknown scope":
        return scope
    parts = scope.split("/")
    lower = [p.lower() for p in parts]
    if "subscriptions" in lower:
        idx = lower.index("subscriptions")
        sub_id = parts[idx + 1] if idx + 1 < len(parts) else None
        if sub_id and sub_map and sub_id in sub_map:
            return f"{sub_map[sub_id]} ({sub_id})"
        return scope
    if "managementgroups" in lower:
        idx = lower.index("managementgroups")
        mg_id = parts[idx + 1] if idx + 1 < len(parts) else scope
        return f"MG:{mg_id}"
    return scope

def enum_custom_definitions_and_initiatives(sub_map=None):
    """Enumerate custom definitions and initiatives once - not per scope. Returns initiative_map."""
    initiative_map = {}  # guid -> [policy display names]

    banner("Custom Policy Definitions")
    defs = az(["policy", "definition", "list",
               "--query", "[?policyType=='Custom']"], ignore_errors=True)
    if not defs:
        info("No custom definitions found")
    else:
        for d in defs:
            name = d.get("displayName") or d.get("name", "unnamed")
            # Effect may be hardcoded or parameterised
            effect = (d.get("policyRule", {})
                       .get("then", {})
                       .get("effect", "unknown"))
            # If effect is a parameter reference, note it
            if isinstance(effect, str) and effect.startswith("[parameters("):
                effect = "parameterised"
            raw_scope = d.get("id", "").split("/providers/")[0] or "unknown scope"
            defined_at = resolve_scope_name(raw_scope, sub_map)
            info(f"{name} - effect: {effect} - defined at: {defined_at}")
            if effect.lower() in ("deployifnotexists", "modify"):
                finding(f"DINE/Modify definition: '{name}' - check if assigned with MSI", "med")

    banner("Custom Initiatives")
    initiatives = az(["policy", "set-definition", "list",
                      "--query", "[?policyType=='Custom']"], ignore_errors=True)
    if not initiatives:
        info("No custom initiatives found")
    else:
        for i in initiatives:
            name = i.get("displayName") or i.get("name", "unnamed")
            policy_defs = i.get("policyDefinitions", [])
            count = len(policy_defs)
            raw_scope = i.get("id", "").split("/providers/")[0] or "unknown scope"
            defined_at = resolve_scope_name(raw_scope, sub_map)
            info(f"{name} - {count} policies - defined at: {defined_at}")
            resolved_policies = []
            for pd in policy_defs:
                pd_id = pd.get("policyDefinitionId", "")
                pd_guid = pd_id.split("/")[-1] if pd_id else "unknown"
                pd_name = resolve_policy_name(pd_guid)
                # Prefer explicit effect override in initiative, fall back to definition's own effect
                params = pd.get("parameters") or {}
                effect_override = (params.get("effect") or {}).get("value", "")
                effect = effect_override if effect_override else resolve_policy_effect(pd_guid)
                info(f"  - {pd_name} (effect: {effect})")
                resolved_policies.append(f"{pd_name} (effect: {effect})")
            # Store by initiative GUID for use in assignment expansion
            initiative_guid = i.get("id", "").split("/")[-1]
            initiative_map[initiative_guid] = resolved_policies

    return initiative_map

def enum_exemptions(scope, scope_label):
    section(f"Exemptions @ {scope_label}")
    exemptions = az(["policy", "exemption", "list", "--scope", scope], ignore_errors=True)
    if not exemptions:
        info("No exemptions found")
        return

    for e in exemptions:
        name = e.get("displayName") or e.get("name", "unnamed")
        category = e.get("exemptionCategory", "unknown")
        expires = e.get("expiresOn", "no expiry")
        finding(f"Exemption: '{name}' - category: {category}, expires: {expires}", "med")

def resolve_role_name(role_definition_id):
    """Resolve a role definition GUID to a friendly name via az rest."""
    result = az_rest(f"https://management.azure.com{role_definition_id}?api-version=2022-04-01")
    if result:
        return result.get("properties", {}).get("roleName", role_definition_id)
    return role_definition_id

def enum_dine_blast_radius(dine_identities):
    if not dine_identities:
        return
    banner("DINE MSI Blast Radius")
    for d in dine_identities:
        section(f"MSI: {d['name']} ({d['principalId']})")
        # az CLI --assignee flag is unreliable for MSIs - use az rest at tenant scope
        result = az_rest(
            f"https://management.azure.com/providers/Microsoft.Authorization/roleAssignments"
            f"?api-version=2022-04-01&$filter=principalId eq '{d['principalId']}'"
        )
        if result is None:
            warn("Could not query role assignments - insufficient permissions")
            continue
        if not result.get("value"):
            finding("MSI exists but has no role assignments - DINE remediation inoperative; identity could be granted roles by attacker", "high")
            continue
        for r in result["value"]:
            props = r.get("properties", {})
            role_def_id = props.get("roleDefinitionId", "")
            scope = props.get("scope", "unknown")
            role_name = resolve_role_name(role_def_id) if role_def_id else "unknown"
            finding(f"{role_name} @ {scope}", "high")

def friendly_resource(resource_id):
    """Return a readable resource label from a full resource ID."""
    if not resource_id or resource_id == "unknown":
        return "unknown"
    parts = resource_id.split("/")
    # Check if it looks like a bare subscription GUID (no resourceGroups segment)
    lower_parts = [p.lower() for p in parts]
    if "resourcegroups" not in lower_parts:
        return "[subscription scope]"
    try:
        rg_idx = lower_parts.index("resourcegroups")
        rg = parts[rg_idx + 1]
        name = parts[-1]
        rtype = parts[-2] if len(parts) > 2 else ""
        return f"{rg}/{rtype}/{name}"
    except (ValueError, IndexError):
        return parts[-1] or resource_id

_policy_cache = {}  # guid -> {"name": ..., "effect": ...}

def _fetch_policy(policy_guid):
    """Fetch and cache policy definition name and effect."""
    if policy_guid in _policy_cache:
        return _policy_cache[policy_guid]
    # Try built-in scope first
    result = az_rest(
        f"https://management.azure.com/providers/Microsoft.Authorization/policyDefinitions"
        f"/{policy_guid}?api-version=2023-04-01"
    )
    if not result:
        # Try subscription-scoped custom definitions across all known subscriptions
        subs = az(["account", "list", "--query", "[].id", "--output", "json"], ignore_errors=True) or []
        for sub_id in subs:
            result = az_rest(
                f"https://management.azure.com/subscriptions/{sub_id}/providers/Microsoft.Authorization"
                f"/policyDefinitions/{policy_guid}?api-version=2023-04-01"
            )
            if result:
                break
    entry = {"name": policy_guid, "effect": "unknown"}
    if result:
        props = result.get("properties", {})
        entry["name"] = props.get("displayName", policy_guid)
        effect = (props.get("policyRule", {})
                      .get("then", {})
                      .get("effect", "unknown"))
        if isinstance(effect, str) and effect.startswith("[parameters("):
            # Effect is parameterised — read the default value
            effect = (props.get("parameters", {})
                          .get("effect", {})
                          .get("defaultValue", "parameterised"))
        entry["effect"] = effect
    _policy_cache[policy_guid] = entry
    return entry

def resolve_policy_name(policy_guid):
    """Resolve a policy definition GUID to a friendly display name."""
    return _fetch_policy(policy_guid)["name"]

def resolve_policy_effect(policy_guid):
    """Resolve a policy definition GUID to its effect."""
    return _fetch_policy(policy_guid)["effect"]

def enum_compliance(sub_id):
    section(f"Non-compliant Resources (subscription)")
    states = az(["policy", "state", "list",
                 "--subscription", sub_id,
                 "--filter", "complianceState eq 'NonCompliant'",
                 "--top", "50"], ignore_errors=True)
    if not states:
        info("No non-compliant resources found (or no access)")
        return

    by_policy = defaultdict(list)
    sub_scope_count = 0

    for s in states:
        policy_guid = s.get("policyDefinitionName", "unknown")
        resource = friendly_resource(s.get("resourceId", "unknown"))
        if resource == "[subscription scope]":
            sub_scope_count += 1
        else:
            by_policy[policy_guid].append(resource)

    # Summarise Defender/ASC subscription-scope findings as a single line
    if sub_scope_count > 0:
        warn(f"Defender for Cloud: {sub_scope_count} plan(s) not enabled at subscription scope - run 'az security pricing list' for details")

    # Resolve policy GUIDs and print resource-level findings
    for policy_guid, resources in by_policy.items():
        policy_name = resolve_policy_name(policy_guid)
        finding(f"{policy_name} - {len(resources)} non-compliant resource(s)", "med")
        # Deduplicate resources
        seen = set()
        for r in resources:
            if r not in seen:
                seen.add(r)
                info(f"  {r}")

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    all_dine = []

    # Identity
    account = get_current_identity()

    # Fetch subscriptions early so sub_map is available for definitions
    subs = get_subscriptions()
    sub_map = {sub.get("id"): sub.get("name") for sub in subs}

    # Custom definitions and initiatives - once only, not per scope
    initiative_map = enum_custom_definitions_and_initiatives(sub_map)

    # Management groups
    mgs = get_management_groups()
    for mg in mgs:
        mg_id = mg.get("name")
        mg_name = mg.get("displayName", mg_id)
        mg_scope = f"/providers/Microsoft.Management/managementGroups/{mg_id}"
        banner(f"Management Group: {mg_name}")
        dine = enum_assignments(mg_scope, f"MG:{mg_name}", initiative_map)
        all_dine.extend(dine)
        enum_exemptions(mg_scope, f"MG:{mg_name}")

    # Subscriptions
    for sub in subs:
        sub_id = sub.get("id")
        sub_name = sub.get("name", sub_id)
        sub_scope = f"/subscriptions/{sub_id}"

        banner(f"Subscription: {sub_name}")
        dine = enum_assignments(sub_scope, f"Sub:{sub_name}", initiative_map)
        all_dine.extend(dine)
        enum_exemptions(sub_scope, f"Sub:{sub_name}")
        enum_compliance(sub_id)

        # Resource groups
        rgs = get_resource_groups(sub_id)
        for rg in rgs:
            rg_name = rg.get("name")
            rg_scope = f"{sub_scope}/resourceGroups/{rg_name}"
            section(f"Resource Group: {rg_name}")
            dine = enum_assignments(rg_scope, f"RG:{rg_name}", initiative_map)
            all_dine.extend(dine)
            enum_exemptions(rg_scope, f"RG:{rg_name}")

    # DINE blast radius - deduplicated
    seen = set()
    unique_dine = []
    for d in all_dine:
        if d["principalId"] not in seen:
            seen.add(d["principalId"])
            unique_dine.append(d)

    enum_dine_blast_radius(unique_dine)

    banner("Enumeration Complete")

if __name__ == "__main__":
    main()
