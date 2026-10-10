"""Versioned parameter registry plus the operator-resolved effective-value overlay.

Effective values are never reverse-engineered here: they come from `brain-replay -inspect`
on a recorded snapshot, i.e. from the exact operator code that decided that tick. A value
the inspection does not carry stays UNAVAILABLE, and source constants are labelled as
source-verified constants rather than observed state.
"""
from .common import REGISTRY_PATH, read_json

EXPERIMENT_KNOB = 'EXPERIMENT_KNOB'


def load_registry(path=REGISTRY_PATH):
    registry = read_json(path)
    if not registry or registry.get('schema_version') != 'math-lab.parameters.v1':
        raise ValueError('parameter registry missing or wrong schema')
    return registry


def _spec_lookup(spec, key):
    """Configured value at a CRD path like spec.slo.costCeiling (None when absent)."""
    if not key or not key.startswith('spec.') or not isinstance(spec, dict):
        return None, False
    node = spec
    for part in key[len('spec.'):].split('.'):
        if not isinstance(node, dict) or part not in node:
            return None, False
        node = node[part]
    return node, True


def effective_view(item, inspection):
    """Return {configured, effective, effective_source, status} for one registry item."""
    out = {'configured_value': None, 'configured_present': False, 'effective_value': None,
           'effective_source': None, 'effective_status': 'UNAVAILABLE'}
    resolver = item.get('effective_resolver') or {}
    kind, path = resolver.get('kind'), resolver.get('path') or ''
    key = item.get('config_key') or ''
    if inspection:
        configured, present = _spec_lookup(inspection.get('configured_spec'), key)
        out['configured_value'], out['configured_present'] = configured, present
        effective = inspection.get('effective') or {}
        if key in effective:
            out.update(effective_value=effective[key], effective_source='operator-resolved policy (snapshot ' + inspection.get('snapshot_digest', '')[:12] + ')',
                       effective_status='OBSERVED')
            return out
        learned = inspection.get('learned') or {}
        if kind == 'learned-state':
            for name in ('lambdaRuntime', 'rlsPrimed', 'conformalQuantile'):
                if name.lower() in path.lower() or name.lower() in (item.get('name') or '').lower():
                    if name in learned:
                        out.update(effective_value=learned[name], effective_source='learned state in snapshot', effective_status='OBSERVED')
                        return out
        manifest = (inspection.get('parameter_manifest') or {}).get('parameters') or []
        overrides = (inspection.get('policy_overrides') or {}).get('values') or []
        names = [p.strip() for p in path.replace(';', '/').split('/') if p.strip()]
        for name in names:
            for value in overrides:
                if value.get('name') == name:
                    out.update(effective_value=value.get('value') if value.get('present', True) else None,
                               effective_source='operator effective policy override ' + name, effective_status='OBSERVED')
                    return out
            for param in manifest:
                if param.get('name') == name:
                    out.update(effective_value=param.get('default'), effective_source='operator parameter manifest ' + name,
                               effective_status='SOURCE_CONSTANT')
                    return out
        flags = ((inspection.get('header') or {}).get('processConfig')) or {}
        if kind == 'operator-flag':
            flag = path.lstrip('-').split('=')[0].split(' ')[0]
            if flag in flags:
                out.update(effective_value=flags[flag], effective_source='operator flag (snapshot process config)', effective_status='OBSERVED')
                return out
    if kind == 'code-constant':
        out.update(effective_value=item.get('default_value'), effective_source='source constant at ' + str(item.get('source_verified_at_sha') or '')[:12],
                   effective_status='SOURCE_CONSTANT')
    return out


def overlay(registry, inspection):
    items = []
    for item in registry['items']:
        merged = dict(item)
        merged.update(effective_view(item, inspection))
        items.append(merged)
    return {**registry, 'items': items, 'inspection': None if not inspection else {
        'snapshot_digest': inspection.get('snapshot_digest'), 'captured_at': (inspection.get('header') or {}).get('capturedAt'),
        'git_sha': (inspection.get('header') or {}).get('gitSHA'), 'policy': (inspection.get('header') or {}).get('namespace', '') + '/' + (inspection.get('header') or {}).get('policyName', ''),
        'economics_mode': (inspection.get('header') or {}).get('economicsMode'), 'learned': inspection.get('learned'),
        'process_config_hash': (inspection.get('header') or {}).get('processConfigHash')}}


def knob(registry, param_id):
    for item in registry['items']:
        if item['param_id'] == param_id:
            return item
    return None
