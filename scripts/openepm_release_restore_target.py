"""Run release restore against a fresh, exactly owned Compose target."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
from shutil import rmtree
import stat
import subprocess
import sys
from tempfile import TemporaryDirectory
from uuid import uuid4

if __package__ in (None, ''):
    from openepm_release_status import CONTAINER_ID, MAX_INPUT_BYTES, read_local_command
    from openepm_release_upgrade import (ACTIVATION_STAGES, DATABASE_SERVICES, UpgradeObservationError, fingerprint,
        inspect_running_services, installed_service_names, observe_active_services,
        previous_activation_fingerprint, read_verified_compose_configuration, verify_browser_gateway_ready,
        verify_private_activation_model, verify_running_service_configuration)
else:
    from .openepm_release_status import CONTAINER_ID, MAX_INPUT_BYTES, read_local_command
    from .openepm_release_upgrade import (ACTIVATION_STAGES, DATABASE_SERVICES, UpgradeObservationError, fingerprint,
        inspect_running_services, installed_service_names, observe_active_services,
        previous_activation_fingerprint, read_verified_compose_configuration, verify_browser_gateway_ready,
        verify_private_activation_model, verify_running_service_configuration)


PROJECT_LABEL = 'com.docker.compose.project'
RUN_LABEL = 'openepm.restore.run'
PROTECTED_CONFIG = '/var/lib/openepm/protected-config'
READY_FORMAT = 'format=openepm-restored-target-v3'
VOLUME_FORMAT = ('[{{json .Name}},{{json .CreatedAt}},'
                 '{{json (index .Labels "com.docker.compose.project")}},'
                 '{{json (index .Labels "openepm.restore.run")}}]')
PROJECT_NAME = re.compile(r'[a-z0-9][a-z0-9_-]{0,62}')
RESOURCE_NAME = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,254}')
RESOURCE_FIELDS = {
    'container': ('{{json .ID}}', '{{json .Names}}'),
    'network': ('{{json .ID}}', '{{json .Name}}'),
    'volume': ('{{json .Name}}', '{{json .Name}}'),
}


class RestoreTargetError(RuntimeError):
    def __init__(self, message: str, exit_code: int = 69):
        super().__init__(message)
        self.exit_code = exit_code


def observe(command):
    result, raw = read_local_command(command, timeout=15, max_bytes=MAX_INPUT_BYTES)
    if result:
        raise RestoreTargetError('restore cannot verify the target Docker resources')
    return raw.decode('utf-8')


def effect(command):
    return subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, check=False).returncode == 0


def restore_namespace(model, project, run_id):
    """Resolve all project names and label only objects created by this run."""
    if not isinstance(model, dict) or model.get('name') != project:
        raise RestoreTargetError('restore cannot verify the selected Compose project', 78)
    service_labels = model.get('services')
    if (not isinstance(service_labels, dict)
            or not {'db', 'control-db', 'control-bootstrap', 'operations'} <= service_labels.keys()):
        raise RestoreTargetError('restore cannot verify its Compose service inventory', 78)
    label = {'labels': {RUN_LABEL: run_id}}
    overlay = {'services': {key: label for key in service_labels}}
    names = {'container': set(), 'network': set(), 'volume': set()}
    for key, service in service_labels.items():
        if not isinstance(service, dict) or 'container_name' in service:
            raise RestoreTargetError('restore requires project-scoped Compose service names', 78)
        names['container'].update((f'{project}-{key}-1', f'{project}_{key}_1'))
    for kind in ('network', 'volume'):
        definitions = model.get(kind + 's')
        if not isinstance(definitions, dict) or not definitions:
            raise RestoreTargetError('restore cannot verify its Compose networks and volumes', 78)
        for key, definition in definitions.items():
            name = f'{project}_{key}'
            if (not isinstance(definition, dict) or definition.get('external')
                    or definition.get('name') != name or not RESOURCE_NAME.fullmatch(name)):
                raise RestoreTargetError('restore requires project-scoped networks and volumes', 78)
            names[kind].add(name)
        overlay[kind + 's'] = {key: label for key in definitions}
    return names, overlay


def target_resources(project, run_id, names, daemon):
    if observe(['docker', 'info', '--format', '{{.ID}}']).strip() != daemon:
        raise RestoreTargetError('restore Docker daemon changed')
    for kind, fields in RESOURCE_FIELDS.items():
        flags = ['--all', '--no-trunc'] if kind == 'container' else (
            ['--no-trunc'] if kind == 'network' else [])
        template = '[' + ','.join((*fields, '{{json (.Label "' + PROJECT_LABEL + '")}}',
                                  '{{json (.Label "' + RUN_LABEL + '")}}')) + ']'
        raw = observe(['docker', kind, 'ls', *flags, '--format', template])
        for line in raw.splitlines():
            identity, name, compose_project, owner = json.loads(line)
            if not all(isinstance(value, str) for value in (identity, name, compose_project, owner)):
                raise RestoreTargetError('restore cannot verify a Docker resource identity')
            if compose_project != project and name not in names[kind]:
                continue
            valid_id = RESOURCE_NAME.fullmatch(identity) if kind == 'volume' else CONTAINER_ID.fullmatch(identity)
            if not valid_id:
                raise RestoreTargetError('restore cannot verify a Docker resource identity')
            owned = compose_project == project and owner == run_id and (
                kind == 'container' or name in names[kind])
            yield kind, identity, owned


def clean_owned_restore(resources):
    for kind, identity, owned in list(resources()):
        if not owned or (kind, identity, True) not in set(resources()):
            continue
        if kind == 'container':
            if not effect(['docker', 'container', 'stop', '--time', '10', identity]):
                continue
            if (kind, identity, True) not in set(resources()):
                continue
        effect(['docker', kind, 'rm', identity])
    return not list(resources())


def check_new_restore_output(marker, recovery):
    if marker.exists() or marker.is_symlink() or recovery.exists() or recovery.is_symlink():
        raise RestoreTargetError('restore output already exists. Use a fresh target.', 78)


def same_entry(path, expected):
    try:
        found = path.lstat()
    except FileNotFoundError:
        return False
    return (found.st_dev, found.st_ino) == (expected.st_dev, expected.st_ino)


def read_regular(path, maximum, *, private=False):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        details = os.fstat(stream.fileno())
        if (not stat.S_ISREG(details.st_mode) or details.st_size > maximum
                or private and (stat.S_IMODE(details.st_mode) != 0o600 or details.st_uid != os.geteuid())):
            raise RestoreTargetError('restore handoff file is unsafe', 78)
        data = stream.read(maximum + 1)
        if len(data) > maximum:
            raise RestoreTargetError('restore handoff file is too large', 78)
        return data


def observe_restored_services(project, model, required, *, database_only):
    try:
        active = observe_active_services(project, set(model['services']))
    except UpgradeObservationError as error:
        raise RestoreTargetError(str(error), 78) from error
    if active.keys() == required:
        return inspect_running_services(project, active)
    if database_only:
        raise RestoreTargetError('restored target must contain only its verified database services before activation', 78)
    raise RestoreTargetError('restored serving inventory differs from the selected profile', 78)


def database_snapshot(project, model, run_id, daemon, manifest, observed):
    # Preserve the existing v3 restore-ready identity. Startup times are bound
    # separately by the serving checks across the health probe.
    databases = {name: {key: value for key, value in observed[name].items() if key != 'startedAt'}
                 for name in DATABASE_SERVICES}
    volume_names = set()
    for name in DATABASE_SERVICES:
        expected = {mount['target']: model['volumes'][mount['source']]['name']
                    for mount in model['services'][name].get('volumes', []) if mount['type'] == 'volume'}
        if '/var/lib/postgresql' not in expected or expected != databases[name]['volumes']:
            raise RestoreTargetError('restored database volume bindings changed', 78)
        volume_names.update(expected.values())
    volumes = [json.loads(line) for line in observe(
        ['docker', 'volume', 'inspect', '--format', VOLUME_FORMAT, *sorted(volume_names)]).splitlines()]
    if (len(volumes) != len(volume_names)
            or any(not isinstance(row, list) or len(row) != 4 or not isinstance(row[1], str) or not row[1]
                   or row[2:] != [project, run_id] for row in volumes)
            or {row[0] for row in volumes} != volume_names
            or observe(['docker', 'info', '--format', '{{.ID}}']).strip() != daemon):
        raise RestoreTargetError('restored database volume ownership changed', 78)
    return fingerprint({'project': project, 'dockerDaemon': daemon, 'restoreRun': run_id,
                        'configuration': fingerprint(model), 'bundleManifest': manifest,
                        'databases': databases, 'volumes': sorted(volumes)})


def inputs(args):
    if not PROJECT_NAME.fullmatch(args.project):
        raise RestoreTargetError('restore target project name is invalid', 78)
    marker = args.marker
    if (marker.name != f'.{args.bundle}.{args.project}.restore-ready'
            or not marker.parent.is_absolute() or marker.parent.resolve() != marker.parent):
        raise RestoreTargetError('restore output location is invalid', 78)
    command = ['docker', 'compose'] if args.compose_frontend == 'docker' else ['docker-compose']
    command.extend(('--project-name', args.project, '--env-file', args.env_file,
                    '-f', args.compose_file, '-f', args.identity_compose_file))
    daemon = observe(['docker', 'info', '--format', '{{.ID}}']).strip()
    if not daemon or len(daemon) > 128:
        raise RestoreTargetError('restore cannot verify the Docker daemon')
    configuration = [*command, '--profile', '*', 'config']
    return command, configuration, daemon


def restore_configuration(args, command, *, expected_digest=None):
    try:
        return read_verified_compose_configuration(args, command, expected_digest=expected_digest)
    except UpgradeObservationError as error:
        raise RestoreTargetError(str(error), 78) from error


def bundle_manifest(args):
    root = args.marker.parent / args.bundle
    if not root.is_dir() or root.is_symlink():
        raise RestoreTargetError('restore bundle is unavailable', 78)
    digest = sha256(read_regular(root / 'manifest.json', 65536)).hexdigest()
    if args.expected_backup_manifest_sha256 and digest != args.expected_backup_manifest_sha256:
        raise RestoreTargetError('restore backup manifest differs from the expected digest', 78)
    return digest


def recovered_configuration_overlay(overlay, recovery, *, read_only=False):
    services = dict(overlay['services'])
    services['operations'] = {**services['operations'], 'volumes': [{
        'type': 'bind', 'source': str(recovery), 'target': PROTECTED_CONFIG, 'read_only': read_only,
        'bind': {'create_host_path': False},
    }]}
    return {**overlay, 'services': services}


def restore_verification_step(bundle, manifest):
    return ('--profile', 'operations', 'run', '--rm', '--no-deps', '-T',
            'operations', '/usr/local/bin/openepm-release-restore-verify', bundle,
            '--expected-manifest-sha256', manifest)


def reverify_staged_restore(args, command, overlay, manifest):
    recovery = args.marker.with_suffix('.recovered-config')
    paths = (recovery, recovery / 'restore')
    try:
        identities = [path.lstat() for path in paths]
    except OSError as error:
        raise RestoreTargetError('verified restore configuration is unavailable before activation', 78) from error
    if not all(stat.S_ISDIR(identity.st_mode) for identity in identities):
        raise RestoreTargetError('verified restore configuration is unavailable before activation', 78)
    with TemporaryDirectory(prefix='openepm-restore-recheck-') as work:
        overlay_path = Path(work) / 'ownership.json'
        overlay_path.write_text(json.dumps(recovered_configuration_overlay(overlay, recovery, read_only=True)))
        if not effect([*command, '-f', str(overlay_path), *restore_verification_step(args.bundle, manifest)]):
            raise RestoreTargetError('restored target verification failed before activation')
    if not all(same_entry(path, identity) for path, identity in zip(paths, identities)):
        raise RestoreTargetError('verified restore configuration changed during activation preflight', 78)


def verify_activation(args):
    if not args.marker.is_file() or args.marker.is_symlink():
        raise RestoreTargetError('verified restore-ready marker is unavailable', 78)
    marker = read_regular(args.marker, 8192, private=True).decode('utf-8')
    if marker.startswith('format=openepm-restored-target-v2\n'):
        raise RestoreTargetError('legacy restore record lacks database identity. Restore into a fresh project.', 78)
    expected = args.marker_content + '\n'
    if not marker.startswith(expected):
        raise RestoreTargetError('restore-ready marker differs from current release or modes', 78)
    fields = re.fullmatch(r'restore_run_id=([0-9a-f]{32})\ntarget_sha256=([0-9a-f]{64})\n',
                          marker[len(expected):])
    if fields is None:
        raise RestoreTargetError('restore-ready marker has an invalid target binding', 78)
    run_id, required = fields.groups()
    command, configuration, daemon = inputs(args)
    model, images = restore_configuration(args, configuration)
    try:
        verify_private_activation_model(model)
    except UpgradeObservationError as error:
        raise RestoreTargetError(str(error), 78) from error
    _, overlay = restore_namespace(model, args.project, run_id)
    database_only = args.check_activation == 'before'
    stage = getattr(args, 'activation_stage', None) or 'serving'
    required_services = (set(DATABASE_SERVICES) if database_only
                         else installed_service_names(images, args.activation_profile) - ACTIVATION_STAGES[stage])
    observed = observe_restored_services(args.project, model, required_services, database_only=database_only)
    manifest = bundle_manifest(args)
    current = database_snapshot(args.project, model, run_id, daemon, manifest, observed)
    if current != required:
        raise RestoreTargetError('restored database identity or effective configuration changed', 78)
    if database_only:
        reverify_staged_restore(args, command, overlay, manifest)
        if (marker != read_regular(args.marker, 8192, private=True).decode('utf-8')
                or manifest != bundle_manifest(args)):
            raise RestoreTargetError('restore-ready marker or backup manifest changed during activation preflight', 78)
        restore_configuration(args, configuration, expected_digest=fingerprint(model))
        checked = observe_restored_services(args.project, model, required_services, database_only=True)
        if (checked != observed
                or database_snapshot(args.project, model, run_id, daemon, manifest, checked) != required):
            raise RestoreTargetError('restored database identity changed during activation preflight', 78)
        return overlay, manifest
    with TemporaryDirectory(prefix='openepm-restore-activation-') as work:
        overlay_path = Path(work) / 'ownership.json'
        overlay_path.write_text(json.dumps(overlay))
        try:
            verify_running_service_configuration(observed, images, [*command, '-f', str(overlay_path),
                '--profile', '*', 'config'], args.host_architecture)
        except UpgradeObservationError as error:
            raise RestoreTargetError(str(error), 78) from error
    identity = {'target': current, 'release': args.verified_manifest_sha256,
                'profile': args.activation_profile, 'services': observed}
    previous = getattr(args, 'expected_previous_running_sha256', None)
    if previous and previous_activation_fingerprint(identity, stage) != previous:
        raise RestoreTargetError('previously verified restored services changed during activation', 78)
    runtime = fingerprint(identity)
    if args.check_activation == 'after' and runtime != args.expected_running_sha256:
        raise RestoreTargetError('restored serving instances changed during the health check', 78)
    if getattr(args, 'check_browser_gateway', False):
        try:
            verify_browser_gateway_ready(args.project, observed)
        except UpgradeObservationError as error:
            raise RestoreTargetError(str(error)) from error
        restore_configuration(args, configuration, expected_digest=fingerprint(model))
        checked = observe_restored_services(args.project, model, required_services, database_only=False)
        if (checked != observed
                or database_snapshot(args.project, model, run_id, daemon, manifest, checked) != required
                or marker != read_regular(args.marker, 8192, private=True).decode('utf-8')
                or manifest != bundle_manifest(args)):
            raise RestoreTargetError('restored runtime or recovery binding changed during Browser gateway verification', 78)
    return runtime, manifest


def restore(args):
    marker = args.marker
    recovery = marker.with_suffix('.recovered-config')
    check_new_restore_output(marker, recovery)
    command, configuration, daemon = inputs(args)
    model, _ = restore_configuration(args, configuration)
    configuration_digest = fingerprint(model)
    manifest = bundle_manifest(args)
    run_id = uuid4().hex
    names, overlay = restore_namespace(model, args.project, run_id)

    def resources():
        return target_resources(args.project, run_id, names, daemon)

    if list(resources()):
        raise RestoreTargetError('restore target already has Docker resources. A fresh target is required.', 78)
    if not effect([*command, '--profile', 'operations', 'pull', 'operations', 'control-bootstrap', 'db', 'control-db']):
        raise RestoreTargetError('restore target image pull failed')
    with TemporaryDirectory(prefix='.openepm-restore-target-', dir=marker.parent) as directory:
        temporary = Path(directory)
        ready = temporary / 'restore-ready'
        with ready.open('x', encoding='utf-8'):
            ready.chmod(0o600)
        ready_identity = ready.lstat()
        if list(resources()):
            raise RestoreTargetError('restore target changed before startup. A fresh target is required.', 78)
        check_new_restore_output(marker, recovery)
        recovery.mkdir(mode=0o700)
        recovery_identity = recovery.lstat()
        overlay = recovered_configuration_overlay(overlay, recovery)
        phases = (
            ('restore target databases did not become healthy',
             ('up', '-d', '--wait', '--wait-timeout', '300', 'db', 'control-db')),
            ('restore target identity database initialization failed',
             ('--profile', 'operations', 'run', '--rm', '--no-deps', '-T', 'control-bootstrap')),
            ('verified restore import failed', ('--profile', 'operations', 'run', '--rm', '--no-deps', '-T',
                                                'operations', '/usr/local/bin/openepm-release-restore', args.bundle,
                                                '--expected-manifest-sha256', manifest)),
            ('restored target verification failed', restore_verification_step(args.bundle, manifest)),
        )
        try:
            if not effect(['chown', '10001:10001', str(recovery)]):
                raise RestoreTargetError('cannot assign private restore configuration staging')
            label_override = temporary / 'ownership.json'
            label_override.write_text(json.dumps(overlay))
            command.extend(('-f', str(label_override)))
            for failure, step in phases:
                if not same_entry(recovery, recovery_identity):
                    raise RestoreTargetError('private restore configuration staging changed')
                restore_configuration(args, configuration, expected_digest=configuration_digest)
                if not effect([*command, *step]):
                    raise RestoreTargetError(failure)
                if any(not owned for _, _, owned in list(resources())):
                    raise RestoreTargetError('restore target contains resources outside this run')
            output = recovery / 'restore'
            if not same_entry(recovery, recovery_identity) or not output.is_dir() or output.is_symlink():
                raise RestoreTargetError('verified restore configuration is unavailable')
            if manifest != bundle_manifest(args):
                raise RestoreTargetError('restore bundle changed during verification')
            restore_configuration(args, configuration, expected_digest=configuration_digest)
            observed = observe_restored_services(args.project, model, set(DATABASE_SERVICES), database_only=True)
            snapshot = database_snapshot(args.project, model, run_id, daemon, manifest, observed)
            with ready.open('w', encoding='utf-8') as stream:
                stream.write(f'{args.marker_content}\nrestore_run_id={run_id}\ntarget_sha256={snapshot}\n')
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(ready, marker)
            except OSError as error:
                raise RestoreTargetError('cannot publish restore-ready marker') from error
        except (RestoreTargetError, OSError, ValueError, KeyboardInterrupt) as error:
            # Publication is authoritative if interrupted immediately after the link.
            if same_entry(marker, ready_identity):
                return manifest
            try:
                cleaned = clean_owned_restore(resources)
            except (RuntimeError, ValueError, OSError, TypeError):
                cleaned = False
            if cleaned:
                try:
                    if same_entry(recovery, recovery_identity):
                        rmtree(recovery)
                    cleaned = not (recovery.exists() or recovery.is_symlink())
                except OSError:
                    cleaned = False
            message = str(error) if isinstance(error, RestoreTargetError) else 'restore target was interrupted'
            detail = ('source unchanged and target cleaned' if cleaned else
                      f'target cleanup could not be verified for restore run {run_id}')
            raise RestoreTargetError(f'{message}. {detail}') from None
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', required=True, type=Path)
    parser.add_argument('--candidate-manifest', required=True, type=Path)
    parser.add_argument('--verified-manifest-sha256', required=True)
    parser.add_argument('--host-architecture', choices=('linux/amd64', 'linux/arm64'), required=True)
    parser.add_argument('--compose-frontend', choices=('docker', 'docker-compose'), required=True)
    parser.add_argument('--project', required=True)
    parser.add_argument('--env-file', required=True)
    parser.add_argument('--compose-file', required=True)
    parser.add_argument('--identity-compose-file', required=True)
    parser.add_argument('--bundle', required=True)
    parser.add_argument('--marker', required=True, type=Path)
    parser.add_argument('--marker-content', required=True)
    parser.add_argument('--check-activation', choices=('before', 'started', 'after'))
    parser.add_argument('--activation-profile', choices=('core', 'workspace'))
    parser.add_argument('--activation-stage', choices=ACTIVATION_STAGES)
    parser.add_argument('--check-browser-gateway', action='store_true')
    parser.add_argument('--expected-running-sha256')
    parser.add_argument('--expected-previous-running-sha256')
    parser.add_argument('--expected-backup-manifest-sha256', default='')
    try:
        args = parser.parse_args()
        if (not args.marker_content.startswith(READY_FORMAT + '\n')
                or 'release_manifest_sha256=' + args.verified_manifest_sha256 not in args.marker_content.splitlines()):
            raise RestoreTargetError('restore-ready release identity is invalid', 78)
        if args.expected_backup_manifest_sha256 and not re.fullmatch(r'[0-9a-f]{64}', args.expected_backup_manifest_sha256):
            raise RestoreTargetError('expected backup manifest digest is invalid', 78)
        if args.activation_stage and args.check_activation not in ('started', 'after'):
            parser.error('an activation stage requires a running target check')
        if args.check_browser_gateway and (args.check_activation != 'after' or args.activation_stage != 'internal'):
            parser.error('Browser gateway readiness requires the completed internal health check')
        needs_previous = args.check_activation == 'started' and args.activation_stage in ('worker', 'serving')
        if (needs_previous != bool(args.expected_previous_running_sha256)
                or args.expected_previous_running_sha256
                and not re.fullmatch(r'[0-9a-f]{64}', args.expected_previous_running_sha256)):
            parser.error('the worker and serving stages require the preceding runtime digest')
        if args.check_activation:
            if not args.activation_profile or (args.check_activation == 'after') != bool(args.expected_running_sha256):
                parser.error('activation requires its profile and the after check requires the started runtime digest')
            result, manifest = verify_activation(args)
            if args.check_activation == 'before':
                print(json.dumps(result))
            elif args.check_activation == 'started':
                print(result)
            else:
                print(manifest)
        else:
            if args.activation_profile or args.expected_running_sha256:
                parser.error('activation arguments require an activation check')
            print(restore(args))
    except RestoreTargetError as error:
        print(f'epmctl: {error}', file=sys.stderr)
        return error.exit_code
    except (OSError, RuntimeError, ValueError, TypeError):
        print('epmctl: restore could not verify its target or Docker operation', file=sys.stderr)
        return 69
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
