#!/usr/bin/env python3
"""Read-only, credential-free operator projection of the existing release inventory.

Compose supplies container observations, not business readiness or saturation.
No database, application grant, restart or recovery operation is performed.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
from ipaddress import IPv4Address
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time

if __package__ in (None, ''):
    from openepm_release_inventory import parse, resolve_inventory, InventoryError
else:
    from .openepm_release_inventory import parse, resolve_inventory, InventoryError


MAX_INPUT_BYTES = 1_048_576
COMPOSE_PREFLIGHT_SECONDS = 8
COMPOSE_QUERY_SECONDS = 8
LAUNCHER_QUERY_SECONDS = 3
PROBE_INSPECT_BYTES = 32_768
STATES = frozenset(('paused', 'restarting', 'removing', 'running', 'dead', 'created', 'exited'))
HEALTH = frozenset(('', 'healthy', 'unhealthy', 'starting'))
CONTAINER_ID = re.compile(r'[a-f0-9]{64}')
IMAGE_ID = re.compile(r'sha256:[a-f0-9]{64}')
IMAGE_REFERENCE = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9.:/_-]{0,300}@sha256:[a-f0-9]{64}')
DOCKER_TIMESTAMP = re.compile(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:\d\d)')
# Roles from the release manifest, not names/tags chosen by a running container.
SERVICE_IMAGE_ROLES = {
    'db': 'database', 'control-db': 'database',
    'platform': 'application', 'router': 'application', 'web': 'application',
    'worker': 'application', 'python-build-broker': 'application',
    'workspace': 'application', 'identity': 'identity', 'proxy': 'proxy',
    'telemetry-collector': 'telemetry_collector',
    'browser-gateway': 'browser_gateway',
    'browser-session-store': 'browser_session_store',
    'builder': 'builder', 'operations': 'operations',
    'control-bootstrap': 'operations', 'keycloak-bootstrap': 'operations',
}
COMPONENT_PURPOSES = {
    'db': 'Stores application models, facts, durable work and receipts.',
    'control-db': 'Stores the bundled identity provider database.',
    'proxy': 'Terminates HTTPS and routes application and identity traffic.',
    'browser-session-store': 'Stores browser sign-in sessions.',
    'telemetry-collector': 'Receives service telemetry and deployment metrics.',
    'platform': 'Serves platform operations such as identity and application discovery.',
    'router': 'Routes signed MCP work to the selected application scope.',
    'web': 'Serves the browser workspace and its governed operations.',
    'worker': 'Claims and processes durable application work.',
    'python-build-broker': 'Brokers authorized Python plan builds.',
    'identity': 'Signs in users and issues tokens for the bundled identity profile.',
    'browser-gateway': 'Checks the browser session before forwarding requests.',
    'workspace': 'Serves a dedicated workspace listener when its profile is enabled.',
}
SERVICE_CHECK_GUIDANCE = {
    'identity-jwks': 'Verify that the affected service can reach the identity signing-key endpoint.',
    'python-coordinator': 'Check the affected worker or broker logs for Python coordinator database role readiness.',
}
LAUNCHER_GUIDANCE = {
    'active': 'The launcher unit is active and its configured socket exists.',
    'inactive': 'Inspect the openepm-sandbox-launcher.service unit and its journal.',
    'socket-unavailable': 'The launcher unit is active. Check that its configured socket exists.',
    'unavailable': 'Check access to systemd from this shell before judging the launcher state.',
}
IMAGE_GUIDANCE = {
    'matched': 'The local container image IDs match the release image.',
    'different': 'Check which release started this service before any restart or retry.',
    'not-confirmed': 'Check local availability of the pinned release image and the service instance.',
}
COMPOSE_GUIDANCE = {
    'COMPOSE_QUERY_FAILED': 'Check the configured Docker context, daemon and access to the release project, then rerun diagnosis.',
    'COMPOSE_QUERY_TIMEOUT': 'Check for a stalled Docker daemon or Compose query, then rerun diagnosis.',
    'COMPOSE_OUTPUT_LIMIT': 'Inspect the release project locally. Compose exceeded the diagnostic output limit.',
    'COMPOSE_OBSERVATION_INVALID': 'Check the Compose version and the selected release project. The returned component state could not be interpreted.',
}
UNCLASSIFIED_CONTAINER_GUIDANCE = (
    'Check the selected Docker context and the Compose containers for this release project. '
    'Compare them with the signed release inventory and reconcile any pending work before changing services.'
)
COMPOSE_PREFLIGHT_GUIDANCE = {
    'DOCKER_QUERY_TIMEOUT': 'Docker daemon check timed out. Check the configured context and daemon, then rerun diagnosis.',
    'DOCKER_QUERY_FAILED': 'Docker daemon could not be checked. Check the configured context and daemon, then rerun diagnosis.',
    'DOCKER_OUTPUT_LIMIT': 'Docker daemon returned more than the diagnostic output limit. Check the daemon locally.',
    'COMPOSE_QUERY_TIMEOUT': 'Docker Compose version check timed out. Check the Compose plugin or standalone command.',
    'COMPOSE_QUERY_FAILED': 'Docker Compose v2 could not be checked. Check the Compose plugin or standalone command.',
    'COMPOSE_OUTPUT_LIMIT': 'Docker Compose returned more than the diagnostic output limit. Check its installation locally.',
}
WORKER_CHECK_PREFIX = 'openepm-worker-health-v1:'
WORKER_HEALTH_COMMAND = ['CMD', 'python', '-m', 'scripts.check_postgres_worker_health']
BROKER_HEALTH_COMMAND = ['CMD', 'python', '-m', 'scripts.serve_openepm_python_build_broker', '--healthcheck']
LISTENER_HEALTH_COMMAND = ['CMD', 'python', '-m', 'scripts.check_postgres_mcp_health']
# The packaged 10-second interval and 4-second timeout give a 14-second cycle.
# Allow two cycles and 2 seconds of scheduling margin before withholding readiness.
RELEASE_PROBE_MAX_AGE = timedelta(seconds=30)
WORKER_CHECK_GUIDANCE = {
    'ready': (0, 'The worker loop marker was fresh and the database role checks passed.'),
    'loop-check-not-configured': (0, 'The database role checks passed. Check the worker loop marker configuration.'),
    'loop-marker-unavailable': (1, 'Check worker startup and the configured loop marker. The probe did not check database roles.'),
    'loop-marker-stale': (1, 'Check worker logs and the current operation. The last loop signal was outside the readiness window.'),
    'configuration-unavailable': (1, 'Check the worker release configuration and readability of its mounted secrets.'),
    'database-role-check-unavailable': (1, 'Check database reachability and the configured worker and runtime roles.'),
}
BROKER_CHECK_GUIDANCE = {
    'ready': (0, 'The broker listener and its configured runtime and coordinator database roles passed.'),
    'listener-unavailable': (1, 'Check broker startup and the local listener in the verified container.'),
    'configuration-or-database-roles-unavailable': (1, 'Check the broker configuration, mounted secrets and current runtime and coordinator database roles.'),
}
LISTENER_CHECK_GUIDANCE = {
    'ready': (0, 'The listener responded, refused an unsigned request and passed its signing-key and database readiness checks.'),
    'LISTENER_CONFIGURATION_NOT_READY': (1, 'Check the listener health port and path in the release configuration.'),
    'LISTENER_NOT_REACHABLE': (1, 'Check service startup and the listener logs. The local probe received no HTTP response.'),
    'UNSIGNED_DENIAL_NOT_CONFIRMED': (1, 'Check the configured listener path and its authentication logs. Verify unsigned requests are refused.'),
    'OIDC_DEPENDENCY_NOT_READY': (1, 'Check the listener audience settings, access to the identity signing-key endpoint and the usable signing keys.'),
    'DATABASE_DEPENDENCY_NOT_READY': (1, 'Check database reachability, this listener’s configured database roles and its expected schema revision.'),
}
LISTENER_PROBE = {'field': 'lastListenerCheck', 'label': 'listener', 'command': LISTENER_HEALTH_COMMAND,
                  'prefix': '', 'guidance': LISTENER_CHECK_GUIDANCE}
RELEASE_HEALTH_PROBES = {
    'worker': {'field': 'lastWorkerCheck', 'label': 'worker', 'command': WORKER_HEALTH_COMMAND,
               'prefix': WORKER_CHECK_PREFIX, 'guidance': WORKER_CHECK_GUIDANCE},
    'python-build-broker': {'field': 'lastBrokerCheck', 'label': 'broker', 'command': BROKER_HEALTH_COMMAND,
                            'prefix': '', 'guidance': BROKER_CHECK_GUIDANCE},
    **dict.fromkeys(('platform', 'router', 'web', 'workspace'), LISTENER_PROBE),
}
GATEWAY_CHECK_GUIDANCE = {
    'ready': 'The browser gateway confirmed its current session-store connection.',
    'session-store-unavailable': 'Check the browser gateway connection to the session store and its configured credentials.',
    'not-confirmed': 'Check the browser gateway and web containers on the release application network, then rerun diagnosis.',
}
GATEWAY_PROBE = """
from contextlib import closing
from http.client import HTTPConnection, HTTPException
import sys

try:
    with closing(HTTPConnection(sys.argv[1], 4180, timeout=1.5)) as connection:
        connection.request('GET', '/ready')
        response = connection.getresponse()
        if response.status == 200 and response.read(3) == b'OK':
            print('ready')
        elif response.status == 500:
            print('session-store-unavailable')
except (OSError, HTTPException):
    pass
"""


class ObservationUnavailable(Exception):
    """A local read ended without a usable result."""


class InvalidComposeObservation(ValueError):
    """A Compose response could not be bound to the selected project."""


def read_local_command(arguments, *, timeout: float, max_bytes: int,
                       environment: dict[str, str] | None = None) -> tuple[int, bytes]:
    """Bound the complete read and reap the owned command even if a child holds stdout."""
    deadline = time.monotonic() + timeout
    try:
        with subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, start_new_session=True,
                              env=environment) as process:
            try:
                output = bytearray()
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    while True:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0 or not selector.select(remaining):
                            raise ObservationUnavailable('QUERY_TIMEOUT')
                        chunk = os.read(process.stdout.fileno(), min(65_536, max_bytes + 1 - len(output)))
                        if not chunk:
                            break
                        output.extend(chunk)
                        if len(output) > max_bytes:
                            raise ObservationUnavailable('OUTPUT_LIMIT')
                return process.wait(timeout=max(0, deadline - time.monotonic())), bytes(output)
            except BaseException:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                raise
    except subprocess.TimeoutExpired as error:
        raise ObservationUnavailable('QUERY_TIMEOUT') from error
    except OSError as error:
        raise ObservationUnavailable('QUERY_FAILED') from error


def local_compose_frontend() -> str:
    """Find the diagnostic Compose frontend within one local read budget."""
    deadline = time.monotonic() + COMPOSE_PREFLIGHT_SECONDS

    def status(arguments):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ObservationUnavailable('QUERY_TIMEOUT')
        result, _ = read_local_command(arguments, timeout=remaining, max_bytes=4096)
        return result

    try:
        if status(['docker', 'info', '--format', '{{.ServerVersion}}']) != 0:
            raise ObservationUnavailable('QUERY_FAILED')
    except ObservationUnavailable as error:
        raise ObservationUnavailable('DOCKER_' + str(error)) from error

    for name, command in (('docker', ['docker', 'compose', 'version']),
                          ('docker-compose', ['docker-compose', 'version'])):
        try:
            if status(command) == 0:
                return name
        except ObservationUnavailable as error:
            # A frontend may be absent. A timeout or oversized output is an
            # observed problem, so retain that reason instead of masking it.
            if str(error) != 'QUERY_FAILED':
                raise ObservationUnavailable('COMPOSE_' + str(error)) from error
    raise ObservationUnavailable('COMPOSE_QUERY_FAILED')


def observe_launcher(socket_path: Path) -> str:
    try:
        status, output = read_local_command(
            ['systemctl', 'is-active', 'openepm-sandbox-launcher.service'],
            timeout=LAUNCHER_QUERY_SECONDS, max_bytes=1024)
    except ObservationUnavailable:
        return 'unavailable'
    state = output.strip()
    if status != 0 and state in (b'inactive', b'failed'):
        return 'inactive'
    if status != 0 or state not in (b'active', b'reloading', b'refreshing'):
        return 'unavailable'
    try:
        if stat.S_ISSOCK(socket_path.stat().st_mode):
            return 'active'
    except OSError:
        pass
    return 'socket-unavailable'


def release_image_references(manifest: dict, services: list[str], architecture: str) -> dict[str, str]:
    """Derive each expected immutable reference from the selected release."""
    images = manifest.get('images')
    if not isinstance(images, dict):
        return {}
    result = {}
    for service in services:
        image = images.get(SERVICE_IMAGE_ROLES.get(service), {})
        if not isinstance(image, dict):
            continue
        reference, digests = image.get('reference'), image.get('digests')
        digest = digests.get(architecture) if isinstance(digests, dict) else None
        if isinstance(reference, str) and isinstance(digest, str):
            pinned = reference + '@' + digest
            if IMAGE_REFERENCE.fullmatch(pinned):
                result[service] = pinned
    return result


def _docker_timestamp(value):
    if not isinstance(value, str) or not DOCKER_TIMESTAMP.fullmatch(value):
        raise ValueError('WORKER_PROBE_TIMESTAMP_INVALID')
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def _retained_check(probe, payload, *, now):
    """Observe a fixed current-start probe and expire its readiness evidence."""
    try:
        started, command, raw = payload.split(' ', 2)
        started_at = _docker_timestamp(json.loads(started))
        if json.loads(command) != probe['command']:
            return None
        health = json.loads(raw)
        if not isinstance(health, dict) or health.get('Status') not in HEALTH:
            return None
        history = health.get('Log')
        if not isinstance(history, list) or not 1 <= len(history) <= 5:
            return None
        last = history[-1]
        if not isinstance(last, dict):
            return None
        begin, end = (_docker_timestamp(last.get(field)) for field in ('Start', 'End'))
    except (ValueError, TypeError, RecursionError):
        return None
    if not started_at <= begin <= end <= now:
        return None
    output = last.get('Output')
    if not isinstance(output, str) or not 1 <= len(output) <= 128:
        return None
    line = output.removesuffix('\n')
    if not line.startswith(probe['prefix']):
        return None
    reason = line[len(probe['prefix']):]
    check = probe['guidance'].get(reason)
    if check is None or type(last.get('ExitCode')) is not int or last['ExitCode'] != check[0]:
        return None
    ended_at = end.astimezone(timezone.utc).isoformat()
    if now - end > RELEASE_PROBE_MAX_AGE:
        return {'status': 'stale', 'endedAt': ended_at,
                'nextAction': f"Check whether the {probe['label']} health probe is still running, then rerun diagnosis."}
    return {'status': 'observed', 'result': reason, 'endedAt': ended_at, 'nextAction': check[1]}


def local_component_probe(architecture: str):
    """Bind local status evidence to the signed image and the exact Compose service."""
    deadline = time.monotonic() + 8
    expected_ids = {}

    def inspect(*arguments, max_bytes=1024):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return ''
        try:
            status, output = read_local_command(['docker', *arguments], timeout=remaining, max_bytes=max_bytes)
        except ObservationUnavailable:
            return ''
        return output.decode('ascii', errors='replace').strip() if status == 0 else ''

    def observe(service, container, project_name, reference):
        result = {'releaseImageCheck': 'not-confirmed'}
        if not isinstance(container, str) or not CONTAINER_ID.fullmatch(container):
            return result
        if reference and reference not in expected_ids:
            parts = inspect('image', 'inspect', '--format',
                '{{.Id}} {{.Os}}/{{.Architecture}}', reference).split()
            expected_ids[reference] = parts[0] if len(parts) == 2 and parts[1] == architecture else ''
        fields = ('{{.Id}} {{.Image}} {{index .Config.Labels "com.docker.compose.project"}} '
                  '{{index .Config.Labels "com.docker.compose.service"}} '
                  '{{index .Config.Labels "com.docker.compose.oneoff"}} '
                  '{{.State.Status}} {{.State.ExitCode}} '
                  '{{with index .State "Health"}}{{.Status}}{{else}}not-reported{{end}}')
        probe = RELEASE_HEALTH_PROBES.get(service)
        if probe:
            fields += (' {{if .State.Running}}{{json .State.StartedAt}} '
                       '{{with index .Config "Healthcheck"}}{{json .Test}}{{else}}null{{end}} '
                       '{{json (index .State "Health")}}{{end}}')
        observed = inspect('container', 'inspect', '--format', fields, container,
                           max_bytes=PROBE_INSPECT_BYTES if probe else 1024).split(maxsplit=8)
        if (len(observed) < 8 or observed[0] != container
                or observed[2:4] != [project_name, service] or not IMAGE_ID.fullmatch(observed[1])):
            return result
        one_off, state, exit_code, health = observed[4:8]
        if (one_off not in ('True', 'False') or
                state not in STATES or health not in HEALTH | {'not-reported'} or
                not re.fullmatch(r'[0-9]{1,3}', exit_code) or int(exit_code) > 255):
            return result
        result.update(state=state, health=health if state == 'running' else 'not-reported',
                      exitCode=int(exit_code), instanceObservation='container-inspect',
                      oneOff=one_off == 'True')
        expected = expected_ids.get(reference, '')
        if IMAGE_ID.fullmatch(expected):
            result['releaseImageCheck'] = 'matched' if observed[1] == expected else 'different'
        if (probe and not result['oneOff'] and state == 'running'
                and result['releaseImageCheck'] == 'matched' and len(observed) == 9):
            check = _retained_check(probe, observed[8], now=datetime.now(timezone.utc))
            if check:
                result[probe['field']] = check
        return result

    return observe


def combined_image_check(statuses) -> str:
    observed = set(statuses)
    if 'different' in observed:
        return 'different'
    return 'matched' if observed == {'matched'} else 'not-confirmed'


def check_browser_gateway(project_name: str, web_id: str, gateway_id: str) -> str:
    """Read the gateway's fixed readiness signal through its verified release peer."""
    unavailable = 'not-confirmed'
    if (not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,127}', project_name)
            or not all(isinstance(value, str) and CONTAINER_ID.fullmatch(value)
                       for value in (web_id, gateway_id))):
        return unavailable
    deadline = time.monotonic() + 5

    def read(*arguments):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return ''
        try:
            status, output = read_local_command(['docker', *arguments],
                                                timeout=remaining, max_bytes=1024)
        except ObservationUnavailable:
            return ''
        return output.decode('ascii', errors='replace').strip() if status == 0 else ''

    network_name = json.dumps(project_name + '_application')
    fields = ('{{.Id}} {{.State.Status}} {{.State.StartedAt}} '
              '{{range $name, $network := .NetworkSettings.Networks}}'
              '{{if eq $name ' + network_name + '}}'
              '{{$network.NetworkID}} {{$network.IPAddress}}{{end}}{{end}}')

    def endpoint(container):
        values = read('container', 'inspect', '--format', fields, container).split()
        if (len(values) != 5 or values[:2] != [container, 'running']
                or not DOCKER_TIMESTAMP.fullmatch(values[2])
                or not CONTAINER_ID.fullmatch(values[3])):
            return None
        try:
            host = IPv4Address(values[4])
        except ValueError:
            return None
        if host.is_unspecified or host.is_loopback or host.is_multicast:
            return None
        return values[2], values[3], str(host)

    web, gateway = endpoint(web_id), endpoint(gateway_id)
    if web is None or gateway is None or web[1] != gateway[1] or web[2] == gateway[2]:
        return unavailable
    network = web[1]
    labels = ('{{.Id}} {{.Internal}} {{index .Labels "com.docker.compose.project"}} '
              '{{index .Labels "com.docker.compose.network"}}')
    if read('network', 'inspect', '--format', labels, network).split() != [
            network, 'true', project_name, 'application']:
        return unavailable
    check = read('exec', web_id, 'python', '-I', '-c', GATEWAY_PROBE, gateway[2])
    if (check in ('ready', 'session-store-unavailable')
            and endpoint(gateway_id) == gateway and endpoint(web_id) == web):
        return check
    return unavailable


def _observed_health(instance):
    gateway = instance.get('browserGatewayCheck', {}).get('result')
    return {'ready': 'healthy', 'session-store-unavailable': 'unhealthy'}.get(
        gateway, instance['health'])


def _probe_incomplete(service, instances):
    probe = RELEASE_HEALTH_PROBES.get(service)
    return bool(probe and any(instance['releaseImageCheck'] == 'matched'
        and instance[probe['field']].get('result') != 'ready' for instance in instances))


def project(inventory: dict, observations: str, *, project_name: str,
            launcher: str, inventory_digest: str, manifest_digest: str,
            expected_images=None, inspect_component=None, probe_browser_gateway=None,
            compose_failure: str | None = None) -> dict:
    """Project only allowlisted state fields; never echo command, ports or logs."""
    if len(observations.encode('utf-8')) > MAX_INPUT_BYTES:
        raise InvalidComposeObservation('STATUS_OBSERVATION_LIMIT')
    try:
        rows = (json.loads(observations) if observations.lstrip().startswith('[')
                else [json.loads(line) for line in observations.splitlines() if line.strip()])
    except (ValueError, TypeError, RecursionError) as error:
        raise InvalidComposeObservation('STATUS_OBSERVATION_INVALID') from error
    if not isinstance(rows, list) or len(rows) > 1000:
        raise InvalidComposeObservation('STATUS_OBSERVATION_INVALID')
    if launcher not in LAUNCHER_GUIDANCE:
        raise ValueError('STATUS_LAUNCHER_INVALID')
    seen_services = set()
    for row in rows:
        if (not isinstance(row, dict) or row.get('Project') != project_name
                or not isinstance(row.get('Service'), str)):
            raise InvalidComposeObservation('STATUS_PROJECT_OBSERVATION_MISMATCH')
        seen_services.add(row['Service'])
    observed_profiles = tuple(name for name, extension in inventory['optionalProfiles'].items()
                              if seen_services.intersection(extension['services']))
    profile = resolve_inventory(inventory, optional_profiles=observed_profiles)
    services = profile['services']
    grouped = {name: [] for name in services}
    instance_ids = {}
    unclassified = 0
    for row in rows:
        name = row['Service']
        if name not in grouped:
            unclassified += 1
            continue
        instance_ids[name] = row.get('ID')
        state, health, code = row.get('State'), row.get('Health'), row.get('ExitCode')
        if (not isinstance(state, str) or not isinstance(health, str)
                or state not in STATES or health not in HEALTH
                or type(code) is not int or not 0 <= code <= 255):
            raise InvalidComposeObservation('STATUS_COMPONENT_OBSERVATION_INVALID')
        instance = {'state': state, 'health': health or 'not-reported', 'exitCode': code,
                    'releaseImageCheck': 'not-confirmed', 'instanceObservation': 'compose-only'}
        if inspect_component:
            instance.update(inspect_component(name, row.get('ID'), project_name,
                                              (expected_images or {}).get(name)))
        probe = RELEASE_HEALTH_PROBES.get(name)
        if probe and (instance['state'] != 'running' or probe['field'] not in instance):
            instance[probe['field']] = {
                'status': 'not-observed',
                'nextAction': f"Check the verified {probe['label']} instance and its current health probe.",
            }
        grouped[name].append(instance)
    gateways, web = grouped.get('browser-gateway', []), grouped.get('web', [])
    if (probe_browser_gateway and len(gateways) == 1
            and gateways[0]['health'] == 'not-reported'
            and gateways[0]['state'] == 'running'
            and gateways[0]['instanceObservation'] == 'container-inspect'
            and not gateways[0].get('oneOff')):
        result = 'not-confirmed'
        if (len(web) == 1 and all(item['state'] == 'running' and not item.get('oneOff')
                and item['instanceObservation'] == 'container-inspect'
                and item['releaseImageCheck'] == 'matched' for item in (*web, *gateways))):
            result = probe_browser_gateway(
                project_name, instance_ids['web'], instance_ids['browser-gateway'])
        gateways[0]['browserGatewayCheck'] = {
            'result': result, 'nextAction': GATEWAY_CHECK_GUIDANCE[result]}
    components = []
    for name in services:
        instances = grouped[name]
        if compose_failure:
            readiness = 'not-observed'
        elif not instances:
            readiness = 'missing'
        # The packaged Compose baseline declares one regular instance per service.
        elif len(instances) > 1 or instances[0].get('oneOff'):
            readiness = 'unexpected-instances'
        elif any(item['state'] != 'running' or _observed_health(item) == 'unhealthy' for item in instances):
            readiness = 'unavailable'
        elif (_probe_incomplete(name, instances) or any(_observed_health(item) != 'healthy'
                or (inspect_component and item['instanceObservation'] == 'compose-only') for item in instances)):
            readiness = 'not-confirmed'
        else:
            readiness = 'checks-passed'
        image_check = combined_image_check(item['releaseImageCheck'] for item in instances)
        components.append({'service': name, 'readiness': readiness,
            'purpose': COMPONENT_PURPOSES.get(name, 'Service declared by this release.'),
            'releaseImageCheck': image_check, 'releaseImageNextAction': IMAGE_GUIDANCE[image_check],
            'instances': instances, 'dependencies': profile['healthDependencies'][name]})
    component_states = {item['service']: item['readiness'] for item in components}
    for item in components:
        dependencies = []
        investigate = []
        listener_check = (item['instances'][0].get('lastListenerCheck', {})
                          if len(item['instances']) == 1 and item['releaseImageCheck'] == 'matched' else {})
        listener_result = listener_check.get('result')
        for name in item['dependencies']:
            if name == 'sandbox-launcher':
                signal = {'dependency': name, 'source': 'host', 'status': launcher}
                if launcher != 'active':
                    investigate.append(name)
            elif name in component_states:
                state = component_states[name]
                signal = {'dependency': name, 'source': 'container', 'status': state}
                if state in ('missing', 'unavailable', 'unexpected-instances'):
                    investigate.append(name)
            elif (name == 'python-coordinator' and item['service'] == 'python-build-broker'
                    and item['readiness'] == 'checks-passed' and item['releaseImageCheck'] == 'matched'
                    and item['instances'][0]['lastBrokerCheck'].get('result') == 'ready'):
                signal = {'dependency': name, 'source': 'service-check', 'status': 'checks-passed'}
            elif name == 'identity-jwks' and listener_result in ('ready', 'DATABASE_DEPENDENCY_NOT_READY'):
                signal = {'dependency': name, 'source': 'service-check', 'status': 'checks-passed'}
            elif name == 'identity-jwks' and listener_result == 'OIDC_DEPENDENCY_NOT_READY':
                signal = {'dependency': name, 'source': 'service-check', 'status': 'unavailable',
                          'nextAction': listener_check['nextAction']}
            else:
                signal = {'dependency': name, 'source': 'service-check', 'status': 'not-observed',
                    'nextAction': SERVICE_CHECK_GUIDANCE[name]}
            dependencies.append(signal)
        item['dependencyObservations'] = dependencies
        service = item['service']
        if item['readiness'] == 'not-observed':
            item['nextAction'] = 'Recollect the Compose observations before judging this service.'
        elif item['readiness'] == 'unexpected-instances':
            item['nextAction'] = (
                f'The release expects one regular {service} instance. Check for extra replicas or '
                'one-off containers in the release project. Reconcile original work before changing services.')
        elif investigate:
            item['nextAction'] = (f"Check {', '.join(investigate)} first, then inspect {service} logs "
                                  'and reconcile pending tasks before any retry.')
        elif listener_result is not None and listener_result != 'ready':
            item['nextAction'] = listener_check['nextAction']
        elif (len(item['instances']) == 1
              and (gateway_check := item['instances'][0].get('browserGatewayCheck'))
              and gateway_check['result'] != 'ready'):
            item['nextAction'] = gateway_check['nextAction']
        elif item['readiness'] == 'missing':
            item['nextAction'] = f'Check whether {service} was started with the declared release profiles.'
        elif item['readiness'] == 'not-confirmed':
            if inspect_component and any(instance['instanceObservation'] == 'compose-only'
                                         for instance in item['instances']):
                item['nextAction'] = 'The container could not be inspected after the Compose listing. Recheck the service instance.'
            elif _probe_incomplete(service, item['instances']):
                label = RELEASE_HEALTH_PROBES[service]['label']
                item['nextAction'] = f'Review the latest {label} check below and reconcile outstanding work before retrying it.'
            elif any(instance['health'] == 'starting' for instance in item['instances']):
                item['nextAction'] = f'The {service} health check is still starting. Recheck its state.'
            else:
                item['nextAction'] = f'{service} is running and no health check was reported. Inspect its service logs.'
        elif item['readiness'] == 'unavailable':
            item['nextAction'] = f'Inspect {service} state and logs and reconcile pending tasks before any retry.'
        else:
            item['nextAction'] = 'No failed container check observed.'
    compose_observation = {'status': 'observed'}
    if compose_failure:
        compose_observation = {'status': 'unavailable', 'reason': compose_failure,
                               'nextAction': COMPOSE_GUIDANCE[compose_failure]}
    return {'format': 'openepm-operator-status-v1',
        'observedAt': datetime.now(timezone.utc).isoformat(),
        'project': project_name, 'inventorySha256': inventory_digest,
        'releaseManifestSha256': manifest_digest,
        'releaseImageCheck': combined_image_check(item['releaseImageCheck'] for item in components),
        'componentChecksPassed': not compose_failure and launcher == 'active' and unclassified == 0
            and all(item['readiness'] == 'checks-passed' for item in components),
        'launcher': {'status': launcher, 'nextAction': LAUNCHER_GUIDANCE[launcher]},
        'composeObservation': compose_observation,
        'observedOptionalProfiles': None if compose_failure else list(observed_profiles),
        'components': components, 'unclassifiedContainerCount': None if compose_failure else unclassified,
        'unclassifiedContainerNextAction': UNCLASSIFIED_CONTAINER_GUIDANCE if unclassified and not compose_failure else None,
        'notMeasured': ['application-specific availability', 'queue saturation',
                        'throughput', 'business outcomes', 'recovery objectives'],
        'verification': 'Signed-release verification uses the installed operations image in an ephemeral read-only container with networking and image pulls disabled. Diagnosis does not persist the trust-policy sequence.',
        'authority': 'Host operator reading the configured release; no application data or grants requested.',
        'interpretation': 'Container checks describe component readiness only. A running container without a reported health check is not confirmed ready. Reconcile original task/receipt identities before retrying uncertain work.'}


def main() -> int:
    if sys.argv[1:] == ['--probe-compose-frontend']:
        try:
            print(local_compose_frontend())
        except ObservationUnavailable as error:
            print('Operator preflight unavailable. ' + COMPOSE_PREFLIGHT_GUIDANCE[str(error)],
                  file=sys.stderr)
            return 69
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', required=True, type=Path)
    parser.add_argument('--manifest', required=True, type=Path)
    parser.add_argument('--project', required=True)
    launcher = parser.add_mutually_exclusive_group(required=True)
    launcher.add_argument('--launcher', choices=tuple(LAUNCHER_GUIDANCE))
    launcher.add_argument('--launcher-socket', type=Path)
    parser.add_argument('--compose-frontend', choices=('docker', 'docker-compose'))
    parser.add_argument('--compose-file', type=Path)
    parser.add_argument('--identity-compose-file', type=Path)
    parser.add_argument('--env-file', type=Path)
    parser.add_argument('--host-architecture', choices=('linux/amd64', 'linux/arm64'))
    parser.add_argument('--verified-manifest-sha256')
    parser.add_argument('--output', choices=('text', 'json'), default='text')
    args = parser.parse_args()
    compose_settings = (args.compose_file, args.identity_compose_file, args.env_file)
    if args.compose_frontend:
        if not all((*compose_settings, args.launcher_socket, args.host_architecture)):
            parser.error('Compose observation requires verified release configuration and a launcher socket')
    elif any((*compose_settings, args.launcher_socket)):
        parser.error('Compose observation settings require a Compose frontend')
    try:
        inventory_bytes = args.inventory.read_bytes()
        inventory_digest = hashlib.sha256(inventory_bytes).hexdigest()
        inventory = parse(inventory_bytes.decode('utf-8'))
        manifest_bytes = args.manifest.read_bytes()
        manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
        expected_images = None
        if args.host_architecture:
            if manifest_digest != args.verified_manifest_sha256:
                raise ValueError('STATUS_VERIFIED_MANIFEST_CHANGED')
            manifest = json.loads(manifest_bytes)
            if not isinstance(manifest, dict):
                raise ValueError('STATUS_MANIFEST_INVALID')
            artifacts = manifest.get('artifacts')
            inventory_artifact = artifacts.get('inventory') if isinstance(artifacts, dict) else None
            if not isinstance(inventory_artifact, dict) or inventory_artifact.get('sha256') != inventory_digest:
                raise ValueError('STATUS_VERIFIED_INVENTORY_CHANGED')
            declared = resolve_inventory(inventory, optional_profiles=tuple(inventory['optionalProfiles']))
            expected_images = release_image_references(manifest, declared['services'], args.host_architecture)
        context = dict(project_name=args.project, inventory_digest=inventory_digest,
                       manifest_digest=manifest_digest, expected_images=expected_images)
        if args.compose_frontend:
            context['launcher'] = observe_launcher(args.launcher_socket)
            command = ['docker', 'compose'] if args.compose_frontend == 'docker' else ['docker-compose']
            command.extend(('--project-name', args.project, '--env-file', args.env_file, '-f',
                            args.compose_file, '-f', args.identity_compose_file,
                            'ps', '--all', '--no-trunc', '--format', 'json'))
            try:
                status, raw = read_local_command(command, timeout=COMPOSE_QUERY_SECONDS, max_bytes=MAX_INPUT_BYTES)
                if status != 0:
                    raise ObservationUnavailable('QUERY_FAILED')
                result = project(inventory, raw.decode('utf-8'), **context,
                                 inspect_component=local_component_probe(args.host_architecture),
                                 probe_browser_gateway=check_browser_gateway)
            except ObservationUnavailable as error:
                result = project(inventory, '', **context, compose_failure='COMPOSE_' + str(error))
            except (InvalidComposeObservation, UnicodeDecodeError):
                result = project(inventory, '', **context, compose_failure='COMPOSE_OBSERVATION_INVALID')
        else:
            raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
            if len(raw) > MAX_INPUT_BYTES:
                raise InvalidComposeObservation('STATUS_OBSERVATION_LIMIT')
            inspect_component = local_component_probe(args.host_architecture) if args.host_architecture else None
            result = project(inventory, raw.decode('utf-8'), **context, launcher=args.launcher,
                             inspect_component=inspect_component)
    except (OSError, ValueError, InventoryError):
        # Do not include raw parser contents, paths, payloads or provider logs.
        print('Operator status unavailable: verify release inventory and current component observations.', file=sys.stderr)
        return 69
    if args.output == 'json':
        print(json.dumps(result, sort_keys=True))
    else:
        print('Open EPM component status — ' + result['project'])
        print('Release manifest SHA-256: ' + result['releaseManifestSha256'])
        print('Release images: ' + result['releaseImageCheck'])
        print('Sandbox launcher: ' + result['launcher']['status'])
        print('  ' + result['launcher']['nextAction'])
        compose_observation = result['composeObservation']
        print('Compose observation: ' + compose_observation['status'])
        if 'nextAction' in compose_observation:
            print('  ' + compose_observation['nextAction'])
        if result['observedOptionalProfiles']:
            print('Observed optional profiles: ' + ', '.join(result['observedOptionalProfiles']))
        for item in result['components']:
            print(item['service'] + ': ' + item['readiness'])
            print('  ' + item['purpose'])
            print('  ' + item['nextAction'])
            print('  Release image: ' + item['releaseImageCheck'])
            print('    ' + item['releaseImageNextAction'])
            release_probe = RELEASE_HEALTH_PROBES.get(item['service'])
            for instance in item['instances']:
                print(f"  Instance state: {instance['state']} ({instance['instanceObservation']}), "
                      f"health {instance['health']}, exit code {instance['exitCode']}")
                if instance.get('oneOff'):
                    print('  One-off Compose container')
                gateway_check = instance.get('browserGatewayCheck')
                if gateway_check:
                    print('  Browser gateway check: ' + gateway_check['result'])
                    print('    ' + gateway_check['nextAction'])
                if release_probe:
                    probe = instance[release_probe['field']]
                    detail = 'not observed'
                    if probe['status'] == 'observed':
                        detail = f"{probe['result']} at {probe['endedAt']}"
                    elif probe['status'] == 'stale':
                        detail = f"stale (completed at {probe['endedAt']})"
                    print(f"  Last {release_probe['label']} check: " + detail)
                    print('    ' + probe['nextAction'])
            for dependency in item['dependencyObservations']:
                print(f"  {dependency['dependency']} ({dependency['source']}: {dependency['status']})")
                if 'nextAction' in dependency:
                    print('    ' + dependency['nextAction'])
        if result['unclassifiedContainerCount']:
            print('Unclassified containers: ' + str(result['unclassifiedContainerCount']))
            print('  ' + result['unclassifiedContainerNextAction'])
        print(result['interpretation'])
        print('Not measured: ' + ', '.join(result['notMeasured']))
    return 0 if result['componentChecksPassed'] and result['releaseImageCheck'] == 'matched' else 69


if __name__ == '__main__':
    raise SystemExit(main())
