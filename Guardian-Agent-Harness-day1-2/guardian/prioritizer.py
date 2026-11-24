"""Explainable policy priority; inventory membership is not runtime reachability."""
def prioritize(finding, node):
    dev = node.get('dev')
    context = 'development-only inventory' if dev is True else 'production dependency inventory' if dev is False else 'unknown'
    level = finding['risk_level']
    if finding['rule'] in {'integrity-change', 'secret-exfiltration', 'obfuscated-execution'}:
        tier, reason = 'P0', 'Potential integrity or execution compromise requires immediate investigation; malicious intent is not established.'
    elif level == 'Critical':
        tier, reason = 'P1' if dev is True else 'P0', 'Critical advisory or policy signal; development tooling can also affect releases.'
    elif level == 'High':
        tier, reason = 'P2' if dev is True else 'P1', 'High severity signal prioritized conservatively where exposure is unknown.'
    elif level == 'Unknown':
        tier, reason = 'P1', 'Severity is unavailable; investigate before assigning a lower priority.'
    else:
        tier, reason = 'P3' if dev is True or level == 'Low' else 'P2', 'Lower policy severity; review in dependency context.'
    return dict(tier=tier, reason=reason, dependency_context=context, direct=node.get('direct'),
                reachability='unknown', exposure='unknown', exploit_availability='unknown',
                confidence=finding.get('confidence', 'Medium'))
