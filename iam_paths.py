"""Offline group-inheritance and separation-of-duties review from normalized exports."""
import argparse
from collections import deque
from datetime import date
import json
from pathlib import Path
import sys


def reachable(start, graph):
    """Return shortest inheritance witness paths, terminating on cycles."""
    paths = {start: [start]}
    queue = deque([start])
    while queue:
        current = queue.popleft()
        for parent in sorted(graph.get(current, [])):
            if parent not in paths:
                paths[parent] = paths[current] + [parent]
                queue.append(parent)
    return paths


def review(data, as_of):
    if data.get('schema') != 'iam-path-review/v1':
        raise ValueError('Unsupported export schema')
    principals = data['principals']
    ids = [item['id'] for item in principals]
    if len(ids) != len(set(ids)) or any(not isinstance(item, str) or not item for item in ids):
        raise ValueError('Principal IDs must be unique nonempty strings')
    known = set(ids)
    graph = {item: set() for item in ids}
    for edge in data['memberships']:
        if edge['member'] not in known or edge['group'] not in known:
            raise ValueError('Membership references an unknown principal')
        graph[edge['member']].add(edge['group'])
    for grant in data['grants']:
        if grant['principal'] not in known or not grant['action'] or not grant['resource']:
            raise ValueError('Invalid grant')
    rules = data['rules']
    rule_ids = [rule['id'] for rule in rules]
    if len(rule_ids) != len(set(rule_ids)):
        raise ValueError('Rule IDs must be unique')
    for rule in rules:
        if len(rule['all_actions']) < 2 or len(set(rule['all_actions'])) != len(rule['all_actions']):
            raise ValueError('Rules require at least two distinct exact actions')
    exceptions = {}
    for entry in data.get('exceptions', []):
        key = (entry['principal'], entry['rule'], entry['resource'])
        if key in exceptions or entry['principal'] not in known or entry['rule'] not in rule_ids or not entry['reason'] or not entry['approved_by']:
            raise ValueError('Invalid or duplicate exception')
        exceptions[key] = {**entry, 'expires_on': date.fromisoformat(entry['expires_on'])}
    findings = []
    for principal in sorted(principals, key=lambda item: item['id']):
        if principal['kind'] not in ('user', 'service', 'group'):
            raise ValueError('Principal kind must be user, service, or group')
        if principal['kind'] == 'group':
            continue
        paths = reachable(principal['id'], graph)
        by_resource = {}
        for grant in data['grants']:
            if grant['principal'] not in paths:
                continue
            actions = by_resource.setdefault(grant['resource'], {})
            witness = paths[grant['principal']]
            previous = actions.get(grant['action'])
            if previous is None or (len(witness), witness) < (len(previous), previous):
                actions[grant['action']] = witness
        for resource, actions in sorted(by_resource.items()):
            for rule in sorted(rules, key=lambda item: item['id']):
                if not set(rule['all_actions']) <= actions.keys():
                    continue
                exception = exceptions.get((principal['id'], rule['id'], resource))
                accepted = bool(exception and as_of <= exception['expires_on'])
                findings.append({'principal': principal['id'], 'resource': resource, 'rule': rule['id'],
                                 'status': 'accepted_exception' if accepted else 'open',
                                 'exception_expired': bool(exception and not accepted),
                                 'witnesses': {action: actions[action] for action in sorted(rule['all_actions'])}})
    return {'as_of': as_of.isoformat(), 'findings': findings,
            'model': 'Exact allow grants and exact resource IDs; not a cloud policy simulator.'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('export', type=Path)
    parser.add_argument('--as-of', required=True, type=date.fromisoformat)
    args = parser.parse_args(argv)
    try:
        report = review(json.loads(args.export.read_text(encoding='utf-8')), args.as_of)
        print(json.dumps(report, indent=2))
        return int(any(item['status'] == 'open' for item in report['findings']))
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        print(f'error: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
