"""Verify the source, quiescent and installed states of a release upgrade."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

if __package__ in (None, ''):
    from openepm_release_inventory import parse, resolve, resolve_inventory
    from openepm_release_status import (
        CONTAINER_ID, DOCKER_TIMESTAMP, IMAGE_ID, MAX_INPUT_BYTES, ObservationUnavailable, read_local_command,
        check_browser_gateway, release_image_references)
else:
    from .openepm_release_inventory import parse, resolve, resolve_inventory
    from .openepm_release_status import (
        CONTAINER_ID, DOCKER_TIMESTAMP, IMAGE_ID, MAX_INPUT_BYTES, ObservationUnavailable, read_local_command,
        check_browser_gateway, release_image_references)


DATABASE_SERVICES = ('db', 'control-db')
PERSISTENT_SERVICES = (*DATABASE_SERVICES, 'identity')
UPGRADE_TASK_SERVICES = ('builder', 'operations', 'control-bootstrap', 'keycloak-bootstrap')
ACTIVATION_STAGES = {
    'internal': frozenset({'worker', 'proxy'}),
    'worker': frozenset({'proxy'}),
    'serving': frozenset(),
}
SHA256 = re.compile(r'[0-9a-f]{64}')
DAEMON_ID = re.compile(r'[a-zA-Z0-9_.:-]{1,128}')
SERVICE_NAME = re.compile(r'[a-z][a-z0-9-]{0,127}')
OBSERVATION_FORMAT = (
    '[{{json (.Label "com.docker.compose.project")}},'
    '{{json (.Label "com.docker.compose.service")}},'
    '{{json .State}},{{json .ID}},'
    '{{json (.Label "com.docker.compose.oneoff")}}]'
)
WORKSPACE_SCOPE_FORMAT = (
    '{{range .Config.Env}}'
    '{{if eq (index (split . "=") 0) "EPM_PG_WORKSPACE_ID"}}{{json .}}{{end}}'
    '{{end}}'
)
RUNNING_FORMAT = (
    '[{{json .Id}},{{json .Image}},{{json .State.Status}},'
    '{{json (index .Config.Labels "com.docker.compose.project")}},'
    '{{json (index .Config.Labels "com.docker.compose.service")}},'
    '{{json (index .Config.Labels "com.docker.compose.oneoff")}},'
    '{{json (index .Config.Labels "com.docker.compose.config-hash")}},'
    '{{if .Mounts}}{{json .Mounts}}{{else}}[]{{end}},{{json .State.StartedAt}}]'
)
IMAGE_FORMAT = '[{{json .Id}},{{json .Os}},{{json .Architecture}}]'
VOLUME_FORMAT = ('[{{json .Name}},{{json .CreatedAt}},{{json .Driver}},'
                 '{{json .Scope}},{{json .Mountpoint}}]')
VOLUME_NAME = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_.-]*')
MOUNT_ROOT = re.compile(r'[0-9]+:[1-9][0-9]*')
DATABASE_ROOT = '/var/lib/postgresql'
PROXY_ROUTE_TARGET = '/var/lib/openepm/proxy'
PROXY_ROUTES_NAME = 'openepm-base.yaml'
RELEASE_ASSET_MOUNTS = {
    'proxy': ('proxy/traefik.yaml', '/etc/traefik/traefik.yaml'),
    'telemetry-collector': ('operations/otel-collector.yaml', '/etc/openepm/otel-collector.yaml'),
}
RELEASE_ASSETS = ('proxy/openepm-base.yaml.template',
                  *(source for source, _ in RELEASE_ASSET_MOUNTS.values()))


class UpgradeObservationError(ValueError):
    pass


def fingerprint(value) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                             allow_nan=False).encode('utf-8')).hexdigest()


def read_verified_compose_configuration(args, command: list,
                                        *, expected_digest=None,
                                        configuration_fingerprint=fingerprint) -> tuple[dict, dict[str, str]]:
    """Bind the resolved Compose model to an already authenticated release."""
    manifest_bytes = args.candidate_manifest.read_bytes()
    if sha256(manifest_bytes).hexdigest() != args.verified_manifest_sha256:
        raise UpgradeObservationError('candidate release manifest changed during verification')
    manifest = json.loads(manifest_bytes)
    if not isinstance(manifest, dict):
        raise UpgradeObservationError('candidate release manifest is invalid')
    artifacts = manifest.get('artifacts')
    inventory = artifacts.get('inventory') if isinstance(artifacts, dict) else None
    inventory_bytes = args.inventory.read_bytes()
    if (not isinstance(inventory, dict)
            or sha256(inventory_bytes).hexdigest() != inventory.get('sha256')):
        raise UpgradeObservationError('candidate release inventory differs from the authenticated manifest')
    scope = resolve_inventory(parse(inventory_bytes.decode('utf-8')), optional_profiles=('workspace',))
    services = scope['services']
    expected_services = [*services, *UPGRADE_TASK_SERVICES]
    expected_images = release_image_references(manifest, expected_services, args.host_architecture)
    if set(expected_images) != set(expected_services):
        raise UpgradeObservationError('candidate release does not bind each Compose service image')
    def render(environment=None):
        status, raw = read_local_command(
            [*command, '--format', 'json'], timeout=10, max_bytes=MAX_INPUT_BYTES,
            environment=environment)
        if status:
            raise UpgradeObservationError('candidate Compose configuration could not be resolved')
        value = json.loads(raw)
        if not isinstance(value, dict) or value.get('name') != args.project:
            raise UpgradeObservationError('candidate Compose configuration has the wrong project identity')
        return value

    model = render()
    actual = model.get('services')
    if not isinstance(actual, dict) or set(actual) != set(expected_services):
        raise UpgradeObservationError('candidate Compose service inventory differs from the release')
    for name, service in actual.items():
        if (not isinstance(service, dict) or 'build' in service
                or service.get('image') != expected_images[name]
                or service.get('platform') != args.host_architecture):
            raise UpgradeObservationError('candidate Compose service image or platform differs from the release')
    if expected_digest:
        if configuration_fingerprint(model) != expected_digest:
            raise UpgradeObservationError('candidate effective Compose configuration changed during maintenance')
    elif render({key: value for key, value in os.environ.items()
                 if key == 'EPM_RELEASE_ASSETS_DIR'
                 or not key.startswith(('EPM_', 'COMPOSE_'))}) != model:
        raise UpgradeObservationError('inherited shell settings override the candidate release configuration')
    return model, expected_images


def configuration_file_digest(path: Path, label: str) -> str:
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        with os.fdopen(os.open(path, flags), 'rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise UpgradeObservationError(label + ' must be a regular file')
            contents = stream.read(MAX_INPUT_BYTES + 1)
    except OSError as error:
        raise UpgradeObservationError(label + ' is unavailable') from error
    if not contents or len(contents) > MAX_INPUT_BYTES:
        raise UpgradeObservationError(label + ' must be nonempty and bounded')
    return sha256(contents).hexdigest()


def release_asset_digests(root: Path) -> dict[str, str]:
    """Read only the three static product configuration files."""
    return {name: configuration_file_digest(root / name, 'candidate release asset ' + name)
            for name in RELEASE_ASSETS}


def verify_release_config_mount(model: dict, service: str, source: Path, target: str) -> None:
    volumes = model['services'][service].get('volumes', ())
    error = UpgradeObservationError('candidate has a different release configuration mount: ' + service)
    if not isinstance(volumes, (list, tuple)):
        raise error
    mounts = [mount for mount in volumes if isinstance(mount, dict) and mount.get('target') == target]
    if len(mounts) != 1:
        raise error
    mount, = mounts
    bind = mount.get('bind', {})
    if (mount.get('type') != 'bind' or not isinstance(mount.get('source'), str)
            or os.path.normpath(mount['source']) != os.path.normpath(source)
            or mount.get('read_only') is not True or not isinstance(bind, dict)
            or bind.get('create_host_path', False) is not False):
        raise error


def verify_published_proxy_routes(path: Path, expected: str) -> None:
    if configuration_file_digest(path, 'published proxy routes file') != expected:
        raise UpgradeObservationError('published proxy routes changed during upgrade')


def candidate_configuration(args) -> tuple[str, dict[str, str], list]:
    command = ['docker', 'compose'] if args.compose_frontend == 'docker' else ['docker-compose']
    command.extend(('--project-name', args.project, '--env-file', args.env_file, '-f',
                    args.compose_file, '-f', args.identity_compose_file, '--profile', '*', 'config'))
    asset_root = Path(os.environ.get('EPM_RELEASE_ASSETS_DIR') or
                      Path(args.compose_file).absolute().parent.parent)
    assets = release_asset_digests(asset_root)
    routes = getattr(args, 'proxy_routes_file', None)
    routes_digest = getattr(args, 'expected_proxy_routes_sha256', None)
    if routes_digest:
        verify_published_proxy_routes(routes, routes_digest)

    def configuration_fingerprint(model):
        return fingerprint({'compose': model, 'releaseAssets': assets})

    model, expected_images = read_verified_compose_configuration(args, command,
        expected_digest=args.expected_configuration_sha256,
        configuration_fingerprint=configuration_fingerprint)
    verify_private_activation_model(model)
    for service, (source, target) in RELEASE_ASSET_MOUNTS.items():
        verify_release_config_mount(model, service, asset_root / source, target)
    if routes:
        verify_release_config_mount(model, 'proxy', routes.parent, PROXY_ROUTE_TARGET)
    if routes_digest:
        verify_published_proxy_routes(routes, routes_digest)
    if release_asset_digests(asset_root) != assets:
        raise UpgradeObservationError('candidate release asset changed while resolving configuration')
    return configuration_fingerprint(model), expected_images, command


def verify_private_activation_model(model):
    for name, service in model['services'].items():
        if name != 'proxy' and (service.get('ports') or service.get('network_mode') == 'host'):
            raise UpgradeObservationError('only the release proxy may publish host listeners during activation')


def project_containers(project: str):
    status, raw = read_local_command([
        'docker', 'container', 'ls', '--all', '--no-trunc',
        '--filter', 'label=com.docker.compose.project=' + project,
        '--format', OBSERVATION_FORMAT,
    ], timeout=10, max_bytes=256 * 1024)
    if status:
        raise ObservationUnavailable('QUERY_FAILED')

    for line in raw.decode('utf-8').splitlines():
        row = json.loads(line)
        if (not isinstance(row, list) or len(row) != 5
                or not all(isinstance(value, str) for value in row)):
            raise UpgradeObservationError('malformed project container observation')
        observed_project, service, state, identity, oneoff = row
        if observed_project != project or CONTAINER_ID.fullmatch(identity) is None:
            raise UpgradeObservationError('project container identity could not be verified')
        yield service, state, identity, oneoff


def observe_active_services(project: str, allowed_services: set[str]) -> dict[str, str]:
    active = {}
    for service, state, identity, oneoff in project_containers(project):
        if state in ('created', 'exited'):
            continue
        if state != 'running':
            raise UpgradeObservationError('project contains an interrupted or unstable container')
        if service not in allowed_services or oneoff.lower() != 'false':
            raise UpgradeObservationError('project contains an unexpected active container')
        if service in active or identity in active.values():
            raise UpgradeObservationError('project contains multiple active service instances')
        active[service] = identity
    return active


def pause_candidate(project: str, services: set[str], *, persistent=PERSISTENT_SERVICES, daemon=None) -> None:
    """Stop candidate workloads without reloading the possibly changed Compose model."""
    mutable = services - set(persistent)
    for targets in ({'proxy'}, mutable - {'proxy'}):
        if daemon is not None:
            require_daemon(daemon)
        ids = sorted({identity for service, state, identity, oneoff in project_containers(project)
                      if service in targets and state not in ('created', 'exited')
                      and oneoff.lower() == 'false'})
        if ids:
            if daemon is not None:
                require_daemon(daemon)
            try:
                read_local_command(['docker', 'container', 'stop', '--time', '15', *ids],
                                   timeout=35, max_bytes=16 * 1024)
            except ObservationUnavailable:
                # Continue with the next group. The final daemon read decides
                # whether all candidate services actually stopped.
                pass
    if daemon is not None:
        require_daemon(daemon)
    if any(service not in persistent and state not in ('created', 'exited')
           for service, state, _, _ in project_containers(project)):
        raise UpgradeObservationError('candidate workloads could not be confirmed stopped')


def inspect_running_services(project: str, active: dict[str, str], *, states=('running',),
                             proxy_route_directory: Path | None = None) -> dict[str, dict]:
    status, raw = read_local_command([
        'docker', 'container', 'inspect', '--format', RUNNING_FORMAT, *active.values(),
    ], timeout=10, max_bytes=MAX_INPUT_BYTES)
    if status:
        raise UpgradeObservationError('running release containers could not be inspected')
    observed = {}
    for line in raw.decode('utf-8').splitlines():
        row = json.loads(line)
        if (not isinstance(row, list) or len(row) != 9
                or not all(isinstance(value, str) for value in (*row[:7], row[8]))):
            raise UpgradeObservationError('running release container observation is invalid')
        identity, image, state, owner, service, oneoff, configuration, mounts, started_at = row
        if (service in observed or active.get(service) != identity or owner != project
                or state not in states or oneoff.lower() != 'false'
                or IMAGE_ID.fullmatch(image) is None or SHA256.fullmatch(configuration) is None
                or not isinstance(mounts, list) or DOCKER_TIMESTAMP.fullmatch(started_at) is None):
            raise UpgradeObservationError('running release container changed or lacks a Compose identity')
        volumes = {}
        for mount in mounts:
            if not isinstance(mount, dict):
                raise UpgradeObservationError('running release volume observation is invalid')
            if mount.get('Type') == 'volume':
                name, target = mount.get('Name'), mount.get('Destination')
                if (not isinstance(name, str) or not name or not isinstance(target, str)
                        or not target.startswith('/') or target in volumes):
                    raise UpgradeObservationError('running release volume binding is invalid')
                volumes[target] = name
        if service == 'proxy' and proxy_route_directory is not None:
            routes = [mount for mount in mounts if mount.get('Destination') == PROXY_ROUTE_TARGET]
            if (len(routes) != 1 or routes[0].get('Type') != 'bind'
                    or not isinstance(routes[0].get('Source'), str)
                    or os.path.normpath(routes[0]['Source']) != os.path.normpath(proxy_route_directory)
                    or routes[0].get('RW') is not False):
                raise UpgradeObservationError('running proxy route mount differs from the verified release')
        observed[service] = {'container': identity, 'image': image, 'configuration': configuration,
                             'volumes': volumes, 'startedAt': started_at}
    if set(observed) != set(active):
        raise UpgradeObservationError('running release container observation is incomplete')
    return observed


def docker_daemon_identity() -> str:
    status, raw = read_local_command(['docker', 'info', '--format', '{{.ID}}'],
                                     timeout=10, max_bytes=1024)
    identity = raw.decode('ascii').strip()
    if status or DAEMON_ID.fullmatch(identity) is None:
        raise UpgradeObservationError('Docker daemon identity could not be verified')
    return identity


def require_daemon(identity, *, captured='the prior release was captured'):
    if docker_daemon_identity() != identity:
        raise UpgradeObservationError(f'Docker daemon changed since {captured}')


def stable_runtime(observed):
    return {name: {key: value for key, value in row.items() if key != 'startedAt'}
            for name, row in observed.items()}


def verify_prior_private_services(active):
    private = {identity for service, identity in active.items() if service != 'proxy'}
    template = '[{{json .Id}},{{json .HostConfig.NetworkMode}},{{json .HostConfig.PortBindings}}]'
    status, raw = read_local_command(['docker', 'container', 'inspect', '--format', template, *sorted(private)],
                                     timeout=10, max_bytes=16 * 1024)
    rows = [json.loads(line) for line in raw.decode('utf-8').splitlines()]
    if (status or any(not isinstance(row, list) or len(row) != 3 for row in rows)
            or len(rows) != len(private) or {row[0] for row in rows} != private
            or any(not isinstance(mode, str) or mode == 'host' or bindings
                   for _, mode, bindings in rows)):
        raise UpgradeObservationError('the prior release has an unverified host listener outside its proxy')


def capture_prior_release(project, active, observed, dependencies, daemon):
    verify_prior_private_services(active)
    require_daemon(daemon)
    pending = set(active) - set(PERSISTENT_SERVICES) - ACTIVATION_STAGES['internal']
    batches = []
    while pending:
        next_batch = sorted(name for name in pending if not pending.intersection(dependencies[name]))
        if not next_batch:
            raise UpgradeObservationError('prior release dependency order could not be verified')
        batches.append(next_batch)
        pending.difference_update(next_batch)
    return {'project': project, 'daemon': daemon, 'services': stable_runtime(observed),
            'internalBatches': batches}


def read_prior_release(project):
    raw = sys.stdin.read(65537)
    if len(raw) > 65536:
        raise UpgradeObservationError('prior release observation is too large')
    receipt = json.loads(raw)
    if (not isinstance(receipt, dict) or set(receipt) != {'project', 'daemon', 'services', 'internalBatches'}
            or receipt['project'] != project or not isinstance(receipt['daemon'], str)
            or DAEMON_ID.fullmatch(receipt['daemon']) is None or not isinstance(receipt['services'], dict)
            or not isinstance(receipt['internalBatches'], list)):
        raise UpgradeObservationError('prior release observation is invalid')
    services = receipt['services']
    if any(not isinstance(batch, list) or not batch or any(not isinstance(name, str) for name in batch)
           for batch in receipt['internalBatches']):
        raise UpgradeObservationError('prior release restart order is invalid')
    batch_services = [name for batch in receipt['internalBatches'] for name in batch]
    if (not {*PERSISTENT_SERVICES, 'platform'} <= services.keys()
            or any(SERVICE_NAME.fullmatch(name) is None or not isinstance(row, dict)
                   or not isinstance(row.get('container'), str) or CONTAINER_ID.fullmatch(row['container']) is None
                   for name, row in services.items())
            or len({row['container'] for row in services.values()}) != len(services)
            or len(batch_services) != len(set(batch_services))
            or set(batch_services) != set(services) - set(PERSISTENT_SERVICES) - ACTIVATION_STAGES['internal']):
        raise UpgradeObservationError('prior release service observation is invalid')
    return receipt


def verify_prior_release(receipt, *, expected_running=None):
    require_daemon(receipt['daemon'])
    project, services = receipt['project'], receipt['services']
    identities = {name: row['container'] for name, row in services.items()}
    active = observe_active_services(project, set(services))
    if (any(identities[name] != container for name, container in active.items())
            or not set(PERSISTENT_SERVICES) <= active.keys()
            or expected_running is not None and active.keys() != expected_running):
        raise UpgradeObservationError('the captured prior release services changed')
    observed = inspect_running_services(project, identities, states=('running', 'exited'))
    if stable_runtime(observed) != services:
        raise UpgradeObservationError('the captured prior release identities, configuration or volumes changed')
    return set(active)


def prior_container_action(receipt, operation, services):
    if not services:
        return
    require_daemon(receipt['daemon'])
    timeout_flag = ('--time', '15') if operation == 'stop' else ()
    identities = [receipt['services'][name]['container'] for name in sorted(services)]
    status, _ = read_local_command(['docker', 'container', operation, *timeout_flag, *identities],
                                   timeout=35, max_bytes=16 * 1024)
    if status:
        raise UpgradeObservationError(f'could not {operation} the captured prior release containers')


def pause_prior_release(receipt):
    active = verify_prior_release(receipt, expected_running=set(receipt['services']))
    prior_container_action(receipt, 'stop', active & {'proxy'})
    prior_container_action(receipt, 'stop', active - set(PERSISTENT_SERVICES) - {'proxy'})
    verify_prior_release(receipt, expected_running=set(PERSISTENT_SERVICES))


def wait_prior_health(receipt, names):
    require_daemon(receipt['daemon'])
    template = ('[{{json .Id}},{{json .State.Status}},'
                '{{with index .State "Health"}}{{json .Status}}{{else}}null{{end}}]')
    identities = {receipt['services'][name]['container'] for name in names}
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        status, raw = read_local_command(['docker', 'container', 'inspect', '--format', template, *sorted(identities)],
                                         timeout=10, max_bytes=8192)
        if status:
            raise UpgradeObservationError('captured prior release container health could not be verified')
        rows = [json.loads(line) for line in raw.decode('utf-8').splitlines()]
        if (any(not isinstance(row, list) or len(row) != 3 for row in rows)
                or len(rows) != len(identities) or {row[0] for row in rows} != identities
                or any(state != 'running' or health not in (None, 'healthy', 'starting')
                       for _, state, health in rows)):
            raise UpgradeObservationError('captured prior release container health could not be verified')
        if all(health in (None, 'healthy') for _, _, health in rows):
            return
        time.sleep(1)
    raise UpgradeObservationError('captured prior release health check did not settle')


def restart_prior_release(receipt):
    active = verify_prior_release(receipt)
    persistent = set(PERSISTENT_SERVICES)
    mutable = set(receipt['services']) - persistent
    try:
        prior_container_action(receipt, 'stop', active & {'proxy'})
        active.discard('proxy')
        wait_prior_health(receipt, persistent)
        for batch in map(set, receipt['internalBatches']):
            prior_container_action(receipt, 'start', batch - active)
            wait_prior_health(receipt, batch)
            active.update(batch)
        verify_prior_release(receipt, expected_running=active)
        status, _ = read_local_command(['docker', 'container', 'exec',
            receipt['services']['platform']['container'], 'python', '-m', 'scripts.check_postgres_mcp_health'],
            timeout=20, max_bytes=4096)
        if status:
            raise UpgradeObservationError('captured prior release platform readiness check failed')
        for name in ('worker', 'proxy'):
            if name in mutable:
                verify_prior_release(receipt, expected_running=active)
                prior_container_action(receipt, 'start', {name} - active)
                wait_prior_health(receipt, {name})
                active.add(name)
        verify_prior_release(receipt, expected_running=set(receipt['services']))
    except (ObservationUnavailable, OSError, ValueError, TypeError):
        # Only the captured IDs are eligible for recovery effects. Closing the
        # prior ingress is still useful if another stop reports a failure.
        for targets in (mutable & {'proxy'}, mutable - {'proxy'}):
            try:
                prior_container_action(receipt, 'stop', targets)
            except (ObservationUnavailable, OSError, ValueError, TypeError):
                pass
        raise


def database_volume_bindings(observed: dict[str, dict]) -> dict[str, dict[str, str]]:
    volumes = {name: observed.get(name, {}).get('volumes', {}) for name in DATABASE_SERVICES}
    if any(DATABASE_ROOT not in bindings for bindings in volumes.values()):
        raise UpgradeObservationError('running release database storage could not be bound to named volumes')
    return volumes


def inspect_volume_generations(names: set[str]) -> dict[str, list[str]]:
    if any(VOLUME_NAME.fullmatch(name) is None for name in names):
        raise UpgradeObservationError('running release database volume name is invalid')
    status, raw = read_local_command(['docker', 'volume', 'inspect', '--format', VOLUME_FORMAT, *sorted(names)],
                                     timeout=10, max_bytes=MAX_INPUT_BYTES)
    if status:
        raise UpgradeObservationError('running release database volumes could not be inspected')
    volumes = {}
    for line in raw.decode('utf-8').splitlines():
        row = json.loads(line)
        if (not isinstance(row, list) or len(row) != 5
                or any(not isinstance(field, str) or not field for field in row)):
            raise UpgradeObservationError('running release database volume metadata is invalid')
        name, created_at, _, _, mountpoint = row
        if (name not in names or name in volumes or DOCKER_TIMESTAMP.fullmatch(created_at) is None
                or not mountpoint.startswith('/')):
            raise UpgradeObservationError('running release database volume metadata is invalid')
        volumes[name] = row[1:]
    if volumes.keys() != names:
        raise UpgradeObservationError('running release database volume observation is incomplete')
    return volumes


def database_volume_fingerprint(observed: dict[str, dict]) -> str:
    volumes = database_volume_bindings(observed)
    generations = inspect_volume_generations({name for mounts in volumes.values() for name in mounts.values()})
    mount_roots = {}
    for service, mounts in volumes.items():
        targets = sorted(mounts)
        # Docker can reuse volume names and reports creation time only to the second.
        # Read the actual backing directory from the running database's mount namespace.
        status, raw = read_local_command([
            'docker', 'container', 'exec', observed[service]['container'], 'stat', '-c', '%d:%i', '--', *targets,
        ], timeout=10, max_bytes=16 * 1024)
        roots = raw.decode('ascii').splitlines()
        if status or len(roots) != len(targets) or any(MOUNT_ROOT.fullmatch(root) is None for root in roots):
            raise UpgradeObservationError('running release database volume roots could not be verified')
        mount_roots[service] = dict(zip(targets, roots))
    if len({mount_roots[service][DATABASE_ROOT] for service in DATABASE_SERVICES}) != len(DATABASE_SERVICES):
        raise UpgradeObservationError('application and control databases share the same volume root')
    return fingerprint({'bindings': volumes, 'generations': generations, 'mountRoots': mount_roots})


def capture_restart_binding(project: str, services: set[str]) -> dict[str, str]:
    """Bind a complete running project and its database storage without exposing host details."""
    daemon = docker_daemon_identity()
    active = observe_active_services(project, services)
    if active.keys() != services:
        raise UpgradeObservationError('restart observation is missing active release services')
    observed = inspect_running_services(project, active)
    volumes = database_volume_fingerprint(observed)
    require_daemon(daemon, captured='the restart observation began')
    if (observe_active_services(project, services) != active
            or inspect_running_services(project, active) != observed):
        raise UpgradeObservationError('release changed during restart observation')
    return {'continuitySha256': fingerprint({'daemon': daemon, 'project': project,
                'runtime': stable_runtime(observed), 'databaseVolumes': volumes}),
            'runningSha256': fingerprint({name: row['startedAt'] for name, row in observed.items()})}


def source_observation(value: str) -> tuple[str, dict[str, str], str, str, str]:
    fields = value.split()
    if (len(fields) != 7 or fields[0] not in ('core', 'workspace')
            or any(SHA256.fullmatch(item) is None for item in fields[1:6])
            or DAEMON_ID.fullmatch(fields[6]) is None):
        raise UpgradeObservationError('upgrade source observation is invalid')
    return fields[0], dict(zip(PERSISTENT_SERVICES, fields[1:4])), fields[4], fields[5], fields[6]


def verify_running_service_configuration(observed: dict[str, dict], images: dict[str, str],
                                         compose_command: list, host_architecture: str) -> None:
    """Compare the current service instances with the authenticated Compose configuration."""
    status, raw = read_local_command([*compose_command, '--hash', '*'], timeout=10,
                                     max_bytes=MAX_INPUT_BYTES)
    hashes = {}
    if status:
        raise UpgradeObservationError('candidate Compose service fingerprints could not be resolved')
    for line in raw.decode('utf-8').splitlines():
        parts = line.split()
        if (len(parts) != 2 or parts[0] in hashes or SHA256.fullmatch(parts[1]) is None):
            raise UpgradeObservationError('candidate Compose service fingerprint is invalid')
        hashes[parts[0]] = parts[1]
    if set(hashes) != set(images):
        raise UpgradeObservationError('candidate Compose service fingerprints are incomplete')

    references = sorted({images[service] for service in observed})
    status, raw = read_local_command(['docker', 'image', 'inspect', '--format', IMAGE_FORMAT,
                                      *references], timeout=10, max_bytes=MAX_INPUT_BYTES)
    rows = [json.loads(line) for line in raw.decode('utf-8').splitlines()]
    if status or len(rows) != len(references):
        raise UpgradeObservationError('candidate release image identities could not be resolved locally')
    expected_ids = {}
    for reference, row in zip(references, rows):
        if (not isinstance(row, list) or len(row) != 3
                or not all(isinstance(item, str) for item in row)
                or IMAGE_ID.fullmatch(row[0]) is None
                or '/'.join(row[1:]) != host_architecture):
            raise UpgradeObservationError('candidate release image identity or platform is invalid')
        expected_ids[reference] = row[0]
    for service, actual in sorted(observed.items()):
        if actual['image'] != expected_ids[images[service]]:
            raise UpgradeObservationError(f'running {service} image differs from the candidate release')
        if actual['configuration'] != hashes[service]:
            raise UpgradeObservationError(f'running {service} configuration differs from the candidate release')


def installed_service_names(images: dict[str, str], profile: str) -> set[str]:
    required = set(images) - set(UPGRADE_TASK_SERVICES)
    if profile == 'core':
        required.discard('workspace')
    return required


def previous_activation_fingerprint(identity, stage):
    predecessor = 'internal' if stage == 'worker' else 'worker'
    prior = {service: row for service, row in identity['services'].items()
             if service not in ACTIVATION_STAGES[predecessor]}
    return fingerprint({**identity, 'services': prior})


def verify_browser_gateway_ready(project: str, observed: dict[str, dict]) -> None:
    result = check_browser_gateway(project, observed['web']['container'],
                                   observed['browser-gateway']['container'])
    if result == 'session-store-unavailable':
        raise UpgradeObservationError('Browser gateway session store is unavailable')
    if result != 'ready':
        raise UpgradeObservationError('Browser gateway readiness could not be confirmed through the verified web service')


def verify_running_candidate(args, digest: str, images: dict[str, str], compose_command: list) -> str:
    profile, _, source_digest, volumes, daemon = source_observation(args.verify_running_from)
    require_daemon(daemon, captured='the upgrade source was captured')
    installed = installed_service_names(images, profile)
    stage = args.activation_stage
    required = installed - ACTIVATION_STAGES[stage]
    active = observe_active_services(args.project, installed)
    if set(active) != required:
        raise UpgradeObservationError('restarted release service inventory is incomplete')
    routes = getattr(args, 'proxy_routes_file', None)
    routes_digest = getattr(args, 'expected_proxy_routes_sha256', None)
    route_directory = routes.parent if routes else None
    observed = inspect_running_services(args.project, active, proxy_route_directory=route_directory)
    if database_volume_fingerprint(observed) != volumes:
        raise UpgradeObservationError('restarted database volumes differ from the source release')
    verify_running_service_configuration(observed, images, compose_command, args.host_architecture)
    if args.check_browser_gateway:
        verify_browser_gateway_ready(args.project, observed)
        current = observe_active_services(args.project, installed)
        if current != active or inspect_running_services(
                args.project, current, proxy_route_directory=route_directory) != observed:
            raise UpgradeObservationError('restarted services changed during Browser gateway verification')
        candidate_configuration(args)
    require_daemon(daemon, captured='the upgrade source was captured')
    if routes_digest:
        verify_published_proxy_routes(routes, routes_digest)
    identity = {'daemon': daemon, 'project': args.project, 'sourceRuntime': source_digest,
                'manifest': args.verified_manifest_sha256, 'configuration': digest,
                'profile': profile, 'databaseVolumes': volumes, 'services': observed}
    if routes_digest:
        identity['proxyRoutes'] = routes_digest
    if args.expected_previous_running_sha256:
        if previous_activation_fingerprint(identity, stage) != args.expected_previous_running_sha256:
            raise UpgradeObservationError('previously verified upgrade services changed during activation')
    return fingerprint(identity)


def verify_workspace_scope(identity: str, candidate_scope: str) -> None:
    if not candidate_scope:
        raise UpgradeObservationError('running workspace listener requires EPM_PG_WORKSPACE_ID in the candidate environment')
    status, raw = read_local_command([
        'docker', 'container', 'inspect', '--format', WORKSPACE_SCOPE_FORMAT, identity,
    ], timeout=10, max_bytes=2048)
    if status or not raw.strip():
        raise UpgradeObservationError('running workspace listener scope could not be verified')
    if json.loads(raw) != 'EPM_PG_WORKSPACE_ID=' + candidate_scope:
        raise UpgradeObservationError('candidate workspace scope differs from the running listener')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--project', required=True)
    parser.add_argument('--workspace-id')
    parser.add_argument('--quiescent-from')
    parser.add_argument('--candidate-manifest', type=Path)
    parser.add_argument('--verified-manifest-sha256')
    parser.add_argument('--host-architecture', choices=('linux/amd64', 'linux/arm64'))
    parser.add_argument('--compose-frontend', choices=('docker', 'docker-compose'))
    parser.add_argument('--env-file', type=Path)
    parser.add_argument('--compose-file', type=Path)
    parser.add_argument('--identity-compose-file', type=Path)
    parser.add_argument('--expected-configuration-sha256')
    parser.add_argument('--proxy-routes-file', type=Path)
    parser.add_argument('--expected-proxy-routes-sha256')
    parser.add_argument('--verify-running-from')
    parser.add_argument('--activation-stage', choices=ACTIVATION_STAGES)
    parser.add_argument('--check-browser-gateway', action='store_true')
    parser.add_argument('--expected-previous-running-sha256')
    parser.add_argument('--pause-candidate', nargs='+', metavar='SERVICE')
    parser.add_argument('--pause-restored-target', action='store_true')
    parser.add_argument('--expected-docker-daemon')
    prior_action = parser.add_mutually_exclusive_group()
    prior_action.add_argument('--capture-prior-release', action='store_true')
    prior_action.add_argument('--pause-prior-release', action='store_true')
    prior_action.add_argument('--restart-prior-release', action='store_true')
    args = parser.parse_args()
    candidate_settings = (args.verified_manifest_sha256, args.host_architecture,
                          args.compose_frontend, args.env_file, args.compose_file,
                          args.identity_compose_file)
    candidate_config = args.candidate_manifest is not None
    if args.proxy_routes_file and (
            not candidate_config or not args.proxy_routes_file.is_absolute()
            or args.proxy_routes_file.name != PROXY_ROUTES_NAME or '..' in args.proxy_routes_file.parts):
        parser.error('proxy route verification requires the candidate route file')
    if args.expected_proxy_routes_sha256 and (
            args.proxy_routes_file is None or SHA256.fullmatch(args.expected_proxy_routes_sha256) is None):
        parser.error('invalid expected proxy route digest')
    prior = args.capture_prior_release or args.pause_prior_release or args.restart_prior_release
    daemon_check = args.expected_docker_daemon is not None and not args.pause_candidate
    if prior and (candidate_config or args.pause_candidate or args.quiescent_from is not None):
        parser.error('prior release actions require the source project')
    if args.expected_docker_daemon is not None and DAEMON_ID.fullmatch(args.expected_docker_daemon) is None:
        parser.error('invalid expected Docker daemon identity')
    if daemon_check and (candidate_config or prior or args.quiescent_from is not None):
        parser.error('checking the Docker daemon is a separate action')
    if candidate_config:
        if (not all(candidate_settings) or args.workspace_id is not None or args.quiescent_from is not None
                or args.pause_candidate):
            parser.error('candidate configuration requires the authenticated manifest and Compose inputs')
        if args.verify_running_from and not args.expected_configuration_sha256:
            parser.error('running verification requires the previously verified Compose fingerprint')
    elif args.workspace_id is None or any((*candidate_settings, args.expected_configuration_sha256,
                                           args.verify_running_from)):
        parser.error('source observation requires the candidate workspace scope')
    if args.activation_stage and not args.verify_running_from:
        parser.error('an activation stage requires a running release check')
    if args.check_browser_gateway and (not args.verify_running_from or args.activation_stage != 'internal'):
        parser.error('Browser gateway readiness requires the internal activation stage')
    if args.expected_previous_running_sha256 is not None and (
            args.activation_stage not in ('worker', 'serving')
            or SHA256.fullmatch(args.expected_previous_running_sha256) is None):
        parser.error('previous running identity requires a valid activation stage and digest')
    if args.activation_stage in ('worker', 'serving') and not args.expected_previous_running_sha256:
        parser.error('activation requires the verified preceding stage')
    if args.pause_candidate and args.quiescent_from is not None:
        parser.error('pausing and quiescence observation are separate actions')
    if args.pause_restored_target and not args.pause_candidate:
        parser.error('pausing a restored target requires its captured service inventory')
    if args.pause_candidate and (len(args.pause_candidate) != len(set(args.pause_candidate))
            or not {'worker', 'proxy'}.issubset(args.pause_candidate)
            or any(re.fullmatch(r'[a-z][a-z0-9-]{0,127}', service) is None
                   for service in args.pause_candidate)):
        parser.error('invalid previously captured upgrade service inventory')
    args.activation_stage = args.activation_stage or 'serving'
    try:
        if daemon_check:
            require_daemon(args.expected_docker_daemon, captured='the upgrade source was captured')
            return 0
        if candidate_config:
            digest, images, command = candidate_configuration(args)
            if args.verify_running_from:
                digest = verify_running_candidate(args, digest, images, command)
            print(digest)
            return 0
        if args.pause_candidate:
            persistent = DATABASE_SERVICES if args.pause_restored_target else PERSISTENT_SERVICES
            pause_candidate(args.project, set(args.pause_candidate), persistent=persistent,
                            daemon=args.expected_docker_daemon)
            return 0
        if args.pause_prior_release or args.restart_prior_release:
            receipt = read_prior_release(args.project)
            if args.pause_prior_release:
                pause_prior_release(receipt)
            else:
                restart_prior_release(receipt)
            return 0
        inventory = resolve(args.inventory, optional_profiles=('workspace',))
        stopped_source = source_observation(args.quiescent_from) if args.quiescent_from is not None else None
        daemon = stopped_source[-1] if stopped_source else docker_daemon_identity()
        if stopped_source:
            require_daemon(daemon, captured='the upgrade source was captured')
        active = observe_active_services(args.project, set(inventory['services']))
        if stopped_source is None:
            if not all(service in active for service in (*PERSISTENT_SERVICES, 'platform')):
                raise UpgradeObservationError('upgrade requires an existing running release with platform, databases and identity')
            if 'workspace' in active:
                verify_workspace_scope(active['workspace'], args.workspace_id)
            observed = inspect_running_services(args.project, active)
            profile = 'workspace' if 'workspace' in active else 'core'
            if args.capture_prior_release:
                database_volume_bindings(observed)
                receipt = capture_prior_release(args.project, active, observed, inventory['healthDependencies'], daemon)
                require_daemon(daemon)
                print(profile, receipt['daemon'], json.dumps(receipt, separators=(',', ':')))
            else:
                volumes = database_volume_fingerprint(observed)
                require_daemon(daemon, captured='the upgrade source was captured')
                print(profile, *(active[service] for service in PERSISTENT_SERVICES), fingerprint(observed), volumes, daemon)
        else:
            _, identities, _, volumes, _ = stopped_source
            if active != identities:
                raise UpgradeObservationError('project is not quiescent with its original databases and identity')
            observed = inspect_running_services(args.project, {service: active[service] for service in DATABASE_SERVICES})
            if database_volume_fingerprint(observed) != volumes:
                raise UpgradeObservationError('quiescent database volumes differ from the source release')
            require_daemon(daemon, captured='the upgrade source was captured')
    except UpgradeObservationError as error:
        print(f'epmctl: {error}; inspect the release configuration before continuing', file=sys.stderr)
        return (69 if daemon_check or args.quiescent_from is not None or args.expected_configuration_sha256
                or args.pause_prior_release or args.restart_prior_release else 78)
    except (ObservationUnavailable, OSError, ValueError, TypeError, RecursionError):
        subject = 'candidate Compose configuration' if candidate_config else 'source project container observation'
        print(f'epmctl: upgrade could not verify the {subject}', file=sys.stderr)
        return 69
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
