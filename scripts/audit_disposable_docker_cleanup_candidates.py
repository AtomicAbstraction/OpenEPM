#!/usr/bin/env python3
"""Read-only audit of Docker artifacts left by disposable Open EPM runs.

The report never deletes artifacts.  A candidate must have unambiguous Open EPM
qualification provenance, no reference from any container (including stopped
containers), and no exact identifier/name in repository evidence files.
BuildKit cache is a separate non-runtime class.  Docker does not provide a
reliable exact-record deletion contract, so the report exposes only a bounded
BuildKit garbage-collection plan with explicit retained-space floors.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
RETENTION_POLICY = ROOT / 'docs' / 'docker-artifact-retention-policy.json'
QUALIFIED_TAG_PREFIXES = (
    'openepm-postgres-v2:qualified-',
    'openepm-postgres-db:qualified-',
    'openepm-cleanup-qualified:',
)


def docker_json(*arguments: str) -> object:
    return json.loads(subprocess.check_output(
        ['docker', *arguments], text=True))


def docker_lines(*arguments: str) -> list[str]:
    value = subprocess.check_output(['docker', *arguments], text=True)
    return [line for line in value.splitlines() if line]


def docker_json_lines(*arguments: str) -> list[dict]:
    return [json.loads(line) for line in docker_lines(*arguments)]


def evidence_bytes(root: Path = ROOT) -> bytes:
    chunks = []
    for path in root.rglob('*'):
        if (not path.is_file() or '.git' in path.parts
                or path.stat().st_size > 10_000_000):
            continue
        relative = path.relative_to(root)
        if not (relative.parts[:2] == ('docs', 'qualifications')
                or 'manifest' in path.name.lower()
                or 'acceptance' in path.name.lower()):
            continue
        try: chunks.append(path.read_bytes())
        except OSError: pass
    return b'\n'.join(chunks)


def retention_policy(root: Path = ROOT) -> dict:
    path = root / 'docs' / RETENTION_POLICY.name
    value = json.loads(path.read_text(encoding='utf-8'))
    if value.get('format') != 'openepm-docker-retention-policy-v1':
        raise ValueError('Unsupported Docker retention policy')
    retained = value.get('retainedImages')
    if not isinstance(retained, list) or not retained:
        raise ValueError('Docker retention policy has no retained images')
    identities = [item.get('imageId') for item in retained]
    if (len(identities) != len(set(identities))
            or any(not isinstance(item, str) or not item.startswith('sha256:')
                   or len(item) != 71 for item in identities)):
        raise ValueError('Docker retention image identities are invalid')
    volumes = value.get('retainedVolumes')
    if not isinstance(volumes, list) or not volumes:
        raise ValueError('Docker retention policy has no retained volumes')
    names = [item.get('name') for item in volumes]
    roles = [item.get('role') for item in volumes]
    if (len(names) != len(set(names)) or len(roles) != len(set(roles))
            or any(not isinstance(item, str) or not item
                   for item in [*names, *roles])):
        raise ValueError('Docker retention volume identities are invalid')
    return value


def _mentioned(evidence: bytes, values: Iterable[str]) -> bool:
    return any(value and value.encode() in evidence for value in values)


def classify_volume(volume: dict, *, referenced: set[str],
                    evidence: bytes) -> dict:
    name = volume.get('Name', '')
    labels = volume.get('Labels') or {}
    project = labels.get('com.docker.compose.project', '')
    provenance = (project.startswith('epm-signed-')
                  or labels.get('openepm.qualification') is not None)
    reasons = []
    if not provenance: reasons.append('qualification_provenance_ambiguous')
    if name in referenced: reasons.append('referenced_by_container')
    if _mentioned(evidence, (name,)): reasons.append('referenced_by_evidence')
    return {'kind': 'volume', 'id': name, 'candidate': not reasons,
            'reasons': reasons, 'composeProject': project,
            'labels': labels}


def classify_image(image: dict, *, referenced: set[str],
                   evidence: bytes) -> dict:
    image_id = image.get('Id', '')
    tags = image.get('RepoTags') or []
    provenance = bool(tags) and all(any(tag.startswith(prefix)
        for prefix in QUALIFIED_TAG_PREFIXES) for tag in tags)
    reasons = []
    if not provenance: reasons.append('qualification_provenance_ambiguous')
    if image_id in referenced: reasons.append('referenced_by_container')
    short_id = image_id.removeprefix('sha256:')
    if _mentioned(evidence, (image_id, short_id, *tags)):
        reasons.append('referenced_by_evidence')
    return {'kind': 'image', 'id': image_id, 'repoTags': tags,
            'candidate': not reasons, 'reasons': reasons}


def summarize_build_cache(records: list[dict]) -> dict:
    reclaimable = [item for item in records
                   if item.get('Reclaimable') is True]
    conservative = [item for item in reclaimable
                    if item.get('Mutable') is False
                    and item.get('Shared') is False]
    return {
        'recordCount': len(records),
        'reclaimableRecordCount': len(reclaimable),
        'immutableNonSharedReclaimableCount': len(conservative),
        'pruneSupported': True,
        'selectionRule': 'BuildKit garbage collection only; never image, container or volume deletion',
        'command': ['docker', 'buildx', 'prune', '--max-used-space', '2GB',
                    '--reserved-space', '1GB', '--force'],
        'requiredBoundary': 'no Open EPM or unrelated Docker build is active'}


def audit(root: Path = ROOT) -> dict:
    evidence = evidence_bytes(root)
    policy = retention_policy(root)
    retained = {item['imageId']: item for item in policy['retainedImages']}
    retained_volumes = {item['name']: item
                        for item in policy['retainedVolumes']}
    container_ids = docker_lines('ps', '-aq', '--no-trunc')
    containers = (docker_json('container', 'inspect', *container_ids)
                  if container_ids else [])
    referenced_volumes = {mount.get('Name', '') for item in containers
                          for mount in item.get('Mounts', [])
                          if mount.get('Type') == 'volume'}
    referenced_images = {item.get('Image', '') for item in containers}

    volume_names = docker_lines('volume', 'ls', '-q')
    volumes = (docker_json('volume', 'inspect', *volume_names)
               if volume_names else [])
    image_ids = docker_lines('image', 'ls', '-aq', '--no-trunc')
    image_ids = list(dict.fromkeys(image_ids))
    images = docker_json('image', 'inspect', *image_ids) if image_ids else []
    cache_records = docker_json_lines('buildx', 'du', '--format', 'json')
    records = [classify_volume(item, referenced=referenced_volumes,
                               evidence=evidence) for item in volumes]
    records += [classify_image(item, referenced=referenced_images,
                               evidence=evidence) for item in images]
    candidates = [item for item in records if item['candidate']]
    project_prefixes = tuple(policy['projectRepositoryPrefixes'])
    policy_retirement = []
    for item in volumes:
        name = item.get('Name', '')
        labels = item.get('Labels') or {}
        project = labels.get('com.docker.compose.project', '')
        logical_name = labels.get('com.docker.compose.volume', '')
        exact_compose_name = bool(project and logical_name
                                  and name == f'{project}_{logical_name}')
        project_volume = exact_compose_name and project.startswith(
            project_prefixes)
        if (project_volume and name not in retained_volumes
                and name not in referenced_volumes):
            policy_retirement.append({'kind': 'volume', 'id': name,
                'composeProject': project, 'logicalName': logical_name,
                'historicalEvidenceMentioned': _mentioned(evidence, (name,))})
    for item in images:
        image_id = item.get('Id', '')
        tags = item.get('RepoTags') or []
        project_image = any(tag.startswith(project_prefixes) for tag in tags)
        if (project_image and image_id not in retained
                and image_id not in referenced_images):
            policy_retirement.append({'kind': 'image', 'id': image_id,
                'repoTags': tags,
                'historicalEvidenceMentioned': _mentioned(
                    evidence, (image_id, image_id.removeprefix('sha256:'), *tags))})
    return {'format': 'openepm-docker-cleanup-audit-v1',
            'readOnly': True, 'deletionSupported': False,
            'containerCount': len(containers),
            'volumeCount': len(volumes), 'imageCount': len(images),
            'candidates': candidates,
            'refused': [item for item in records if not item['candidate']],
            'buildCache': summarize_build_cache(cache_records),
            'retentionPolicy': {
                'format': policy['format'],
                'historicalEvidenceRequiresPhysicalImage':
                    policy['historicalEvidenceRequiresPhysicalImage'],
                'retainedImages': policy['retainedImages'],
                'retainedVolumes': policy['retainedVolumes'],
                'missingRetainedImageIds': sorted(set(retained) - {
                    item.get('Id', '') for item in images}),
                'missingRetainedVolumeNames': sorted(
                    set(retained_volumes) - set(volume_names)),
                'policyRetirementCandidates': policy_retirement,
                'automaticDeletion': False},
            'revalidation': {
                'requiredBeforeAnySeparateDeletion': [
                    'rerun this audit immediately before deletion',
                    'require the same exact artifact ID in candidates',
                    'confirm no running or stopped container reference',
                    'confirm no repository evidence reference'],
                'thisProgramDeletesArtifacts': False}}


def revalidate(report: dict, artifact_id: str) -> dict:
    """Require one exact, currently unambiguous candidate identifier."""
    strict_matches = [item for item in report['candidates']
                      if item['id'] == artifact_id]
    retirement_matches = [item for item in report.get('retentionPolicy', {}).get(
        'policyRetirementCandidates', []) if item['id'] == artifact_id]
    matches = [*strict_matches, *retirement_matches]
    return {'format': report['format'], 'readOnly': True,
            'requestedExactId': artifact_id,
            'validated': len(matches) == 1,
            'candidate': matches[0] if len(matches) == 1 else None,
            'candidateClass': (
                'strict_cleanup_candidate' if len(strict_matches) == 1
                and not retirement_matches else
                'policy_retirement_candidate' if len(retirement_matches) == 1
                and not strict_matches else None),
            'reason': (None if len(matches) == 1
                       else 'exact_id_not_a_current_unambiguous_candidate')}


def revalidate_many(report: dict, artifact_ids: list[str]) -> dict:
    """Revalidate several exact identifiers against one atomic audit snapshot."""
    results = [revalidate(report, artifact_id) for artifact_id in artifact_ids]
    return {'format': report['format'], 'readOnly': True,
            'allValidated': bool(results) and all(
                item['validated'] for item in results),
            'results': results}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--revalidate-id', action='append', default=[])
    args = parser.parse_args()
    current = audit()
    output = (revalidate_many(current, args.revalidate_id)
              if args.revalidate_id else current)
    print(json.dumps(output, sort_keys=True, separators=(',', ':')))

