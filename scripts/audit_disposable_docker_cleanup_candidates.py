#!/usr/bin/env python3
"""Audit and finish one exactly owned disposable Docker run.

The default command only inventories resources. Deletion requires a recorded
run, its exclusive owner lock, matching daemon/context and creation labels.
Historical evidence, tag prefixes and resource age never authorize deletion.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
FORMAT = 'openepm-owned-docker-run-v1'
REPORT = 'openepm-docker-cleanup-audit-v2'
KINDS = ('container', 'network', 'volume', 'image')
LABEL_PREFIX = 'openepm.cleanup.'
SAFE_NAME = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}\Z')


class CleanupError(RuntimeError):
    pass


class CleanupPending(CleanupError):
    pass


def docker(*arguments: str) -> str:
    result = subprocess.run(['docker', *arguments], text=True,
                            capture_output=True, check=False)
    if result.returncode:
        # Docker errors can repeat environment/command values containing secrets.
        raise CleanupError('Docker command failed (exit %d)' % result.returncode)
    return result.stdout.strip()


def retention_policy(root: Path = ROOT) -> dict:
    value = json.loads((root / 'docs/docker-artifact-retention-policy.json').read_text())
    if value.get('format') != 'openepm-docker-retention-policy-v2':
        raise CleanupError('unsupported Docker retention policy')
    limits = value.get('limits', {})
    if (set(limits) != {'activeReplacementPerService', 'runLeaseSeconds',
                       'stopTimeoutSeconds', 'buildCacheMaxBytes',
                       'buildCacheReservedBytes', 'buildCacheMaxUnusedHours',
                       'resolvedDiagnosticDays', 'failedOrIntermediateBuilds',
                       'stoppedDisposableContainers', 'unreferencedDisposableVolumes'}
            or any(type(item) is not int or item < 0 for item in limits.values())
            or not 0 < limits['runLeaseSeconds'] <= 86400
            or not 0 < limits['stopTimeoutSeconds'] <= 60
            or limits['buildCacheReservedBytes'] > limits['buildCacheMaxBytes']
            or value.get('historicalEvidenceRequiresPhysicalImage') is not False
            or 'retainedImages' in value or 'retainedVolumes' in value):
        raise CleanupError('invalid current-only Docker retention bounds')
    return value


def context_identity(command=docker) -> dict:
    context = command('context', 'show')
    return {'daemonId': command('--context', context, 'info', '--format', '{{.ID}}'),
            'context': context}


def bound_command(command, context: str):
    """Do not let a default-context switch retarget an inspected effect."""
    return lambda *arguments: command('--context', context, *arguments)


def inventory(command=docker) -> dict[str, list[dict]]:
    result = {}
    for kind in KINDS:
        args = ('ps', '-aq', '--no-trunc') if kind == 'container' else (
            (kind, 'ls', '-q') if kind == 'volume' else
            (kind, 'ls', '-q', '--no-trunc'))
        identities = list(dict.fromkeys(command(*args).splitlines()))
        result[kind] = json.loads(command(kind, 'inspect', *identities)) if identities else []
    return result


def identity(kind: str, value: dict) -> str:
    return value.get('Name', '') if kind == 'volume' else value.get('Id', value.get('ID', ''))


def labels(kind: str, value: dict) -> dict:
    return ((value.get('Config') or {}).get('Labels') if kind in ('container', 'image')
            else value.get('Labels')) or {}


def expected_labels(manifest: dict) -> dict:
    return {LABEL_PREFIX + 'project': 'openepm',
            LABEL_PREFIX + 'run': manifest['runId'],
            LABEL_PREFIX + 'disposable': 'true'}


def find_resource(resource: dict, snapshot: dict) -> dict | None:
    kind = resource['kind']
    for item in snapshot[kind]:
        if resource.get('id'):
            if identity(kind, item) == resource['id']:
                return item
        elif item.get('Name', '').lstrip('/') == resource['name']:
            return item
    return None


def references(kind: str, target: str, snapshot: dict) -> list[str]:
    found = []
    for container in snapshot['container']:
        container_id = identity('container', container)
        if kind == 'volume' and any(mount.get('Type') == 'volume' and
                mount.get('Name') == target for mount in container.get('Mounts', [])):
            found.append(container_id)
        elif kind == 'image' and container.get('Image') == target:
            found.append(container_id)
        elif kind == 'network' and any(network.get('NetworkID') == target
                for network in container.get('NetworkSettings', {}).get('Networks', {}).values()):
            found.append(container_id)
        elif kind == 'container' and container_id != target:
            for field in ('NetworkMode', 'PidMode', 'IpcMode'):
                mode = container.get('HostConfig', {}).get(field, '')
                if not isinstance(mode, str) or not mode.startswith('container:'):
                    continue
                donor = mode.removeprefix('container:')
                matches = {identity('container', item) for item in snapshot['container']
                           if donor and (identity('container', item).startswith(donor)
                              or item.get('Name', '').lstrip('/') == donor.lstrip('/'))}
                # A missing/ambiguous namespace donor cannot prove independence.
                if len(matches) != 1 or target in matches:
                    found.append(container_id)
                    break
    return sorted(found)


def classify(resource: dict, manifest: dict, snapshot: dict) -> dict:
    kind = resource['kind']
    item = find_resource(resource, snapshot)
    result = {'kind': kind, 'id': resource.get('id') or resource['name'],
              'candidate': False, 'reasons': []}
    if item is None:
        return dict(result, absent=True)
    exact_id = identity(kind, item)
    result['id'] = exact_id
    actual_labels = labels(kind, item)
    if any(actual_labels.get(key) != value for key, value in expected_labels(manifest).items()):
        result['reasons'].append('run_ownership_mismatch')
    created = item.get('CreatedAt') if kind == 'volume' else item.get('Created')
    if resource.get('createdAt') and resource['createdAt'] != created:
        result['reasons'].append('creation_identity_changed')
    if {'kind': kind, 'id': exact_id} in manifest['protectedResources']:
        result['reasons'].append('protected_current_resource')
    consumers = references(kind, exact_id, snapshot)
    if consumers:
        result['reasons'].append('referenced_by_container')
        result['references'] = consumers
    if kind == 'network' and item.get('Containers'):
        result['reasons'].append('network_has_endpoints')
    result['candidate'] = not result['reasons']
    if kind == 'container':
        result['running'] = bool(item.get('State', {}).get('Running') or
                                 item.get('State', {}).get('Paused') or
                                 item.get('State', {}).get('Restarting'))
    return result


def validate_manifest(value: dict, policy: dict) -> None:
    if (value.get('format') != FORMAT or value.get('project') != 'openepm'
            or not re.fullmatch(r'[0-9a-f]{32}', value.get('runId', ''))
            or not value.get('daemonId') or not value.get('context')
            or value.get('state') not in ('running', 'finishing', 'cleanup_pending')
            or not isinstance(value.get('resources'), list)
            or not isinstance(value.get('protectedResources'), list)
            or type(value.get('createdAt')) not in (int, float)
            or type(value.get('expiresAt')) not in (int, float)
            or not 0 < value['expiresAt'] - value['createdAt'] <= policy['limits']['runLeaseSeconds']):
        raise CleanupError('invalid owned-run manifest')
    seen = set()
    for resource in value['resources']:
        if (resource.get('kind') not in KINDS or
                not isinstance(resource.get('name'), str) or
                SAFE_NAME.fullmatch(resource['name']) is None or
                resource.get('phase') not in ('planned', 'created') or
                (resource['kind'], resource['name']) in seen or
                (resource.get('phase') == 'created' and
                 (not resource.get('id') or not resource.get('createdAt')))):
            raise CleanupError('invalid or duplicate run resource')
        seen.add((resource['kind'], resource['name']))
    for resource in value['protectedResources']:
        if set(resource) != {'kind', 'id'} or resource['kind'] not in KINDS or not resource['id']:
            raise CleanupError('invalid current resource protection')


def write_json(path: Path, value: dict) -> None:
    # The owner lock is separate so replacement cannot release the run fence.
    temporary = path.with_name('.' + path.name + '.' + uuid.uuid4().hex + '.partial')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(value, stream, sort_keys=True, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def summarize_build_cache(records: list[dict], *, builder: str,
                          policy: dict | None = None) -> dict:
    if SAFE_NAME.fullmatch(builder) is None:
        raise CleanupError('invalid selected builder identity')
    limits = (policy or retention_policy())['limits']
    return {'recordCount': len(records),
            'reclaimableRecordCount': sum(item.get('Reclaimable') is True for item in records),
            'automaticDeletion': False,
            'maxUsedBytes': limits['buildCacheMaxBytes'],
            'reservedBytes': limits['buildCacheReservedBytes'],
            'maxUnusedHours': limits['buildCacheMaxUnusedHours'],
            'requiredBoundary': 'verified idle selected builder; protect unrelated builds',
            'selectedBuilder': builder,
            'command': ['docker', 'buildx', 'prune', '--builder', builder, '--filter',
                        'until=%dh' % limits['buildCacheMaxUnusedHours'],
                        '--max-used-space', str(limits['buildCacheMaxBytes']),
                        '--reserved-space', str(limits['buildCacheReservedBytes'])]}


def audit(root: Path = ROOT, *, manifest: dict | None = None, command=docker) -> dict:
    policy = retention_policy(root)
    current = context_identity(command)
    snapshot = inventory(command)
    records = []
    if manifest is not None:
        validate_manifest(manifest, policy)
        if any(manifest[key] != current[key] for key in current):
            raise CleanupError('Docker context or daemon differs from run owner')
        records = [classify(resource, manifest, snapshot) for resource in manifest['resources']]
    return {'format': REPORT, 'readOnly': True, **current,
            'counts': {kind: len(values) for kind, values in snapshot.items()},
            'candidates': [item for item in records if item['candidate']],
            'refused': [item for item in records if not item['candidate'] and not item.get('absent')],
            'absent': [item for item in records if item.get('absent')],
            'unownedResourceCount': sum(len(values) for values in snapshot.values()) - len([
                item for item in records if not item.get('absent')]),
            'historicalEvidenceRequiresPhysicalImage': False,
            'retentionPolicy': policy, 'automaticDeletion': False,
            'buildCache': summarize_build_cache(
                [], builder=current['context'], policy=policy)}


def revalidate(report: dict, artifact_id: str) -> dict:
    matches = [item for item in report['candidates'] if item['id'] == artifact_id]
    return {'format': REPORT, 'readOnly': True, 'requestedExactId': artifact_id,
            'validated': len(matches) == 1,
            'candidate': matches[0] if len(matches) == 1 else None,
            'reason': None if len(matches) == 1 else 'exact_id_not_a_current_unambiguous_candidate'}


def revalidate_many(report: dict, artifact_ids: list[str]) -> dict:
    results = [revalidate(report, item) for item in artifact_ids]
    return {'format': REPORT, 'readOnly': True,
            'allValidated': bool(results) and all(item['validated'] for item in results),
            'results': results}


def cleanup(manifest: dict, *, execute: bool, command=docker, policy: dict | None = None) -> dict:
    """Called only while holding the run lock; each effect rechecks live state."""
    policy = policy or retention_policy()
    validate_manifest(manifest, policy)
    removed, absent, pending, candidates = [], [], [], []
    for kind in KINDS:
        # Helpers are registered after their parent; remove dependants first.
        for resource in reversed(manifest['resources']):
            if resource['kind'] != kind:
                continue
            try:
                current = context_identity(command)
                if any(manifest[key] != current[key] for key in current):
                    raise CleanupError('daemon_or_context_changed')
                selected = bound_command(command, manifest['context'])
                checked = classify(resource, manifest, inventory(selected))
                if checked.get('absent'):
                    absent.append(checked)
                    continue
                if not checked['candidate']:
                    pending.append(checked)
                    continue
                candidates.append(checked)
                if not execute:
                    continue
                exact_id = checked['id']
                if kind == 'container' and checked['running']:
                    selected('container', 'stop', '--time', str(policy['limits']['stopTimeoutSeconds']), exact_id)
                    checked = classify(resource, manifest, inventory(selected))
                    if not checked['candidate'] or checked.get('running'):
                        raise CleanupError('owned_container_not_quiesced')
                # Never --force, --volumes or global prune. Docker is the final
                # live-reference fence if an external process creates a new use.
                selected(kind, 'rm', exact_id)
                if find_resource(resource, inventory(selected)) is not None:
                    raise CleanupError('resource_still_present')
                removed.append({'kind': kind, 'id': exact_id})
            except Exception as failure:
                pending.append({'kind': kind, 'id': resource.get('id') or resource['name'],
                                'reasons': [str(failure) if isinstance(failure, CleanupError)
                                            else type(failure).__name__]})
    return {'format': REPORT, 'runId': manifest['runId'], 'readOnly': not execute,
            'status': ('cleanup_pending' if pending else 'complete' if execute else 'dry_run'),
            'cleanupVerified': execute and not pending, 'removed': removed,
            'absent': absent, 'pending': pending, 'candidates': candidates}


class OwnedDockerRun:
    """Small run boundary reused by existing qualification controllers."""
    def __init__(self, path: Path, *, purpose: str, command=docker, policy: dict | None = None):
        self.path, self.command = path, command
        self.policy = policy or retention_policy()
        self.report = None
        self._lock = None
        now = time.time()
        self.manifest = {'format': FORMAT, 'project': 'openepm', 'runId': uuid.uuid4().hex,
                         'purpose': purpose, 'createdAt': now,
                         'expiresAt': now + self.policy['limits']['runLeaseSeconds'],
                         'state': 'running', 'resources': [], 'protectedResources': [],
                         **context_identity(command)}

    def __enter__(self):
        if not self.path.is_absolute() or self.path.exists() or self.path.is_symlink():
            raise CleanupError('run manifest must be a new absolute path')
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = os.open(str(self.path) + '.lock', os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_RDWR, 0o600)
        try:
            fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            write_json(self.path, self.manifest)
        except BaseException:
            os.close(self._lock)
            self._lock = None
            Path(str(self.path) + '.lock').unlink(missing_ok=True)
            raise
        return self

    def _save(self):
        write_json(self.path, self.manifest)

    def protect_container(self, container: str):
        """Record current source identity/mounts as extra protection, not ownership."""
        selected = bound_command(self.command, self.manifest['context'])
        item = json.loads(selected('container', 'inspect', container))[0]
        protections = [{'kind': 'container', 'id': identity('container', item)},
                       {'kind': 'image', 'id': item['Image']}]
        protections += [{'kind': 'volume', 'id': mount['Name']} for mount in item.get('Mounts', [])
                        if mount.get('Type') == 'volume']
        self.manifest['protectedResources'] = [dict(items) for items in dict.fromkeys(
            tuple(sorted(item.items())) for item in [*self.manifest['protectedResources'], *protections])]
        self._save()

    def _create(self, kind: str, name: str, arguments: tuple[str, ...]) -> str:
        if SAFE_NAME.fullmatch(name) is None or any(item['name'] == name and item['kind'] == kind
                                                  for item in self.manifest['resources']):
            raise CleanupError('invalid or reused resource name')
        if time.time() >= self.manifest['expiresAt']:
            raise CleanupError('run lease expired')
        if any(self.manifest[key] != value for key, value in context_identity(self.command).items()):
            raise CleanupError('Docker context or daemon changed before creation')
        resource = {'kind': kind, 'name': name, 'id': None, 'createdAt': None, 'phase': 'planned'}
        self.manifest['resources'].append(resource)
        self._save()  # Intent exists before Docker creation, including an uncertain response.
        label_args = tuple(value for key, item in expected_labels(self.manifest).items()
                           for value in ('--label', key + '=' + item))
        args = ((kind, 'create', *label_args, name) if kind == 'volume' else
                (kind, 'create', '--name', name, *label_args, *arguments))
        selected = bound_command(self.command, self.manifest['context'])
        selected(*args)
        item = json.loads(selected(kind, 'inspect', name))[0]
        resource.update(id=identity(kind, item),
                        createdAt=item.get('CreatedAt') if kind == 'volume' else item.get('Created'),
                        phase='created')
        if any(labels(kind, item).get(key) != value for key, value in expected_labels(self.manifest).items()):
            raise CleanupError('created resource ownership differs')
        self._save()
        return resource['id']

    def volume(self, name: str) -> str:
        return self._create('volume', name, ())

    def container(self, name: str, *arguments: str, attach: bool = False) -> str:
        exact_id = self._create('container', name, arguments)
        selected = bound_command(self.command, self.manifest['context'])
        selected('container', 'start', *(['--attach'] if attach else []), exact_id)
        return exact_id

    def __exit__(self, error_type, error, traceback):
        try:
            self.manifest['state'] = 'finishing'
            try:
                self._save()
            except OSError:
                # A full disk must not skip Docker cleanup. The last durable
                # ownership manifest remains available for reconciliation.
                pass
            self.report = cleanup(self.manifest, execute=True, command=self.command, policy=self.policy)
            self.report['runOutcome'] = ('cancelled' if error_type in (KeyboardInterrupt, SystemExit)
                                         else 'failed' if error_type else 'succeeded')
            if self.report['cleanupVerified']:
                self.path.unlink()
            else:
                self.manifest.update(state='cleanup_pending', cleanup=self.report)
                try:
                    self._save()
                except OSError as failure:
                    self.report['manifestWriteError'] = type(failure).__name__
                if error is not None:
                    message = 'cleanup_pending: ' + str(self.path)
                    if hasattr(error, 'add_note'):
                        error.add_note(message)
                    else:
                        print(message, file=sys.stderr)
                    error.cleanup_report = self.report
                else:
                    raise CleanupPending('cleanup_pending: ' + str(self.path))
        finally:
            if self._lock is not None:
                os.close(self._lock)
            if not self.path.exists():
                Path(str(self.path) + '.lock').unlink(missing_ok=True)
        return False


def reconcile(path: Path, *, execute: bool = False, command=docker, now: float | None = None) -> dict:
    """Finish an abandoned run only after its lock and bounded lease permit it."""
    if path.is_symlink() or not path.is_file():
        raise CleanupError('run manifest is missing or unsafe')
    descriptor = os.open(str(path) + '.lock', os.O_RDWR | os.O_NOFOLLOW)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {'format': REPORT, 'status': 'cleanup_pending', 'readOnly': not execute,
                    'cleanupVerified': False, 'pending': [{'reasons': ['run_owner_active']}]}
        value = json.loads(path.read_text())
        policy = retention_policy()
        validate_manifest(value, policy)
        if value['state'] == 'running' and (time.time() if now is None else now) < value['expiresAt']:
            return {'format': REPORT, 'status': 'cleanup_pending', 'readOnly': not execute,
                    'cleanupVerified': False, 'pending': [{'reasons': ['run_lease_live']}]}
        result = cleanup(value, execute=execute, command=command, policy=policy)
        if execute:
            if result['cleanupVerified']:
                path.unlink()
            else:
                value.update(state='cleanup_pending', cleanup=result)
                write_json(path, value)
        return result
    finally:
        os.close(descriptor)
        if execute and not path.exists():
            Path(str(path) + '.lock').unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-manifest', type=Path)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--revalidate-id', action='append', default=[])
    args = parser.parse_args()
    if args.execute and not args.run_manifest:
        parser.error('--execute requires one exact --run-manifest')
    if args.revalidate_id and (args.execute or args.run_manifest):
        parser.error('use scoped dry-run output for run revalidation')
    if args.run_manifest:
        output = reconcile(args.run_manifest, execute=args.execute)
    else:
        output = audit()
    if args.revalidate_id:
        output = revalidate_many(output, args.revalidate_id)
    print(json.dumps(output, sort_keys=True, separators=(',', ':')))
    return 1 if output.get('status') == 'cleanup_pending' else 0


if __name__ == '__main__':
    raise SystemExit(main())
