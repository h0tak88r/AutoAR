import yaml
import json

with open('/home/sallam/AutoAR/internal/tools/apkx/analyzer/regexes.yaml', 'r') as f:
    data = yaml.safe_load(f)

js_rules = []
for p in data.get('patterns', []):
    name = p.get('name', '').replace("'", "\\'")
    regex_str = p.get('regex', '')
    if regex_str:
        # We need to escape \ properly for JS regex, but in YAML they are strings.
        # So we can just use new RegExp(regex_str, 'gi')
        js_rules.append({
            'id': name.lower().replace(' ', '_').replace('-', '_'),
            'name': name,
            'severity': 'issue',
            'patterns': [regex_str],
            'description': f'Exposed {name} found.',
            'cwe': 'CWE-798',
            'owasp': 'M9',
            'masvs': 'STORAGE-14'
        })
    elif p.get('regexes'):
        for r in p['regexes']:
            js_rules.append({
                'id': name.lower().replace(' ', '_').replace('-', '_'),
                'name': name,
                'severity': 'issue',
                'patterns': [r],
                'description': f'Exposed {name} found.',
                'cwe': 'CWE-798',
                'owasp': 'M9',
                'masvs': 'STORAGE-14'
            })

with open('/home/sallam/AutoAR/internal/modules/gobot/ui/apkauditor/apk-secrets.js', 'w') as f:
    f.write('const SECRETS_RULES = [\n')
    for rule in js_rules:
        # Write patterns as strings so we can create RegExp objects later, or just string literals.
        # Actually, creating new RegExp is safer.
        patterns_js = '[' + ', '.join([f'new RegExp({json.dumps(pat)}, "gi")' for pat in rule['patterns']]) + ']'
        f.write(f"    {{ id: {json.dumps(rule['id'])}, name: {json.dumps(rule['name'])}, severity: '{rule['severity']}', description: {json.dumps(rule['description'])}, cwe: '{rule['cwe']}', owasp: '{rule['owasp']}', masvs: '{rule['masvs']}', patterns: {patterns_js} }},\n")
    f.write('];\n')

print(f"Generated {len(js_rules)} secret rules.")
