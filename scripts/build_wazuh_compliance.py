import argparse
import json
import re
from pathlib import Path


def parse_value(val: str):
    val = val.strip()
    if val.startswith('"') and val.endswith('"'):
        val = val[1:-1]
    try:
        if val.lower().startswith('0x'):
            return int(val, 16)
        return int(val)
    except ValueError:
        return val


def collect_items(lines, offset: int, limit: int):
    seen = set()
    items = []
    parsed = 0
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        candidate = None
        if line.startswith('Set-ItemProperty'):
            m = re.search(r'-Path\s+"([^"]+)"\s+-Name\s+"([^"]+)"\s+-Value\s+([^\s]+)', line)
            if m:
                path, name, value = m.groups()
                key = ('registry', path, name, value)
                if key in seen:
                    continue
                seen.add(key)
                candidate = {'type': 'registry', 'path': path, 'name': name, 'value': parse_value(value), 'line': line}
        elif line.startswith('Set-Service'):
            m = re.search(r'-Name\s+"?([^"\s]+)"?\s+-StartupType\s+([^\s]+)', line)
            if m:
                name, start = m.groups()
                key = ('service', name, start)
                if key in seen:
                    continue
                seen.add(key)
                candidate = {'type': 'service', 'serviceName': name, 'startMode': start, 'line': line}
        elif line.lower().startswith('auditpol'):
            m_sub = re.search(r'/subcategory:"([^"]+)"', line, re.IGNORECASE)
            if not m_sub:
                continue
            success = re.search(r'/success:([^\s]+)', line, re.IGNORECASE)
            failure = re.search(r'/failure:([^\s]+)', line, re.IGNORECASE)
            sub = m_sub.group(1)
            successVal = success.group(1) if success else None
            failureVal = failure.group(1) if failure else None
            key = ('audit', sub, successVal, failureVal)
            if key in seen:
                continue
            seen.add(key)
            setting = []
            if successVal:
                setting.append(successVal)
            if failureVal:
                setting.append(failureVal)
            candidate = {'type': 'audit', 'subCategory': sub, 'setting': ' and '.join(setting) if setting else None, 'line': line}

        if not candidate:
            continue
        if parsed < offset:
            parsed += 1
            continue

        if limit and len(items) >= limit:
            break

        items.append(candidate)
        parsed += 1

    return items


def build_rules(items):
    rules = []
    for idx, item in enumerate(items, 1):
        mappings = [
            {'standard': 'CIS', 'id': f'B.1.{idx:02d}'},
            {'standard': 'NIST', 'id': f'SC-{10 + idx}'},
            {'standard': 'ISO27001', 'id': f'A.{20 + idx}.1'}
        ]
        if item['type'] == 'registry':
            human = f" This keeps {item['name']} at the recommended value so the associated control stays enforced."
            desc = f"Ensure {item['name']} under {item['path']} equals {item['value']}.{human}"
            rule = {
                'id': f'reg-{idx}',
                'description': desc,
                'type': 'registry',
                'weight': 1.0,
                'operation': 'equals',
                'subject': {
                    'path': item['path'],
                    'valueName': item['name'],
                    'value': item['value']
                },
                'mappings': mappings,
                'source': item['line']
            }
        elif item['type'] == 'service':
            human = f" This keeps the {item['serviceName']} service {item['startMode'].lower()} to align with the baseline and minimize unnecessary running services."
            rule = {
                'id': f'svc-{idx}',
                'description': f"Ensure service {item['serviceName']} is {item['startMode']}.{human}",
                'type': 'service',
                'weight': 1.1,
                'operation': 'equals',
                'subject': {
                    'serviceName': item['serviceName'],
                    'startMode': item['startMode']
                },
                'mappings': mappings,
                'source': item['line']
            }
        else:
            human = f" This captures {item['setting']} events for {item['subCategory']} so you can review both successful and failed activities."
            rule = {
                'id': f'audit-{idx}',
                'description': f"Audit {item['subCategory']} to {item['setting']}.{human}",
                'type': 'audit',
                'weight': 1.0,
                'operation': 'equals',
                'subject': {
                    'subCategory': item['subCategory'],
                    'setting': item['setting']
                },
                'mappings': mappings,
                'source': item['line']
            }
        rules.append(rule)
    return rules


def main():
    parser = argparse.ArgumentParser(description="Build Wazuh compliance profile.")
    parser.add_argument('--baseline', type=str, default='wazuh_compliance_baseline.ps1', help="Path to the Wazuh baseline PowerShell script.")
    parser.add_argument('--offset', type=int, default=0, help="Skip the first N parsed rules.")
    parser.add_argument('--limit', type=int, default=250, help="Maximum number of rules to emit (0 for no limit).")
    parser.add_argument('--output', type=str, default='Server/data/compliance.json', help="Output path for the JSON file.")
    parser.add_argument('--profile-id', type=str, default='level1-wazuh', help="Profile identifier.")
    parser.add_argument('--profile-label', type=str, default='Security Level 1 (Wazuh baseline)', help="Profile label.")
    parser.add_argument('--description', type=str, default='Preview profile for endpoint hardening checks derived from the Wazuh compliance baseline.', help="Profile description.")
    args = parser.parse_args()

    baseline_path = Path(args.baseline)
    if not baseline_path.exists():
        raise FileNotFoundError(f"{baseline_path} not found. Please place the Wazuh baseline script at this path or specify --baseline.")
    lines = baseline_path.read_text().splitlines()
    items = collect_items(lines, offset=args.offset, limit=args.limit)
    rules = build_rules(items)

    profile = {
        'id': args.profile_id,
        'label': args.profile_label,
        'description': args.description,
        'weight': 1,
        'rules': rules
    }

    data = {
        'defaultProfileId': args.profile_id,
        'assignments': {},
        'profiles': [profile]
    }

    Path(args.output).write_text(json.dumps(data, indent=2))
    print(f"Wrote {len(rules)} rules into {args.output}")


if __name__ == '__main__':
    main()
