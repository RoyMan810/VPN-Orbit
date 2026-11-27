"""Scoped, bounded read model over registered resources and completed probes."""

from collections import defaultdict
import json
import re
import time

from .adoption import adoption_ready, assess_profiles, daemon_identity, resource_claims
from .auth import AuthService, Role, check_etag, etag
from .errors import Denied
from .queue import JobQueue
from .runtime.protocol import COMPOSE_PROJECT, SHA256, ULID, checksum, observation_summary


_SELECT = """
WITH page AS MATERIALIZED (
    SELECT r.* FROM resources r
    WHERE r.id>? AND (? IS NULL OR r.id=?)
    AND (? OR EXISTS (SELECT 1 FROM grants g WHERE g.user_id=?
                     AND g.permission='vps:read' AND g.resource_id IN (r.id,'*')))
    ORDER BY r.id LIMIT ?
), latest AS (
    SELECT r.id,
        max(CASE WHEN candidate.status IN ('SUCCEEDED','FAILED','UNKNOWN_OUTCOME','CANCELLED_SAFE')
                 AND (a.event='job.finished' OR (a.event='job.accepted' AND candidate.reason='RESTORE_QUARANTINE'))
                 THEN a.seq END) AS latest_seq,
        max(CASE WHEN a.event='job.finished' AND candidate.status='SUCCEEDED'
                 AND candidate.scope_digest=r.scope_digest AND candidate.policy_revision=r.policy_revision
                 THEN a.seq END) AS success_seq
    FROM page r
    LEFT JOIN audit a ON a.target_id=r.id AND a.event IN ('job.finished','job.accepted')
    LEFT JOIN jobs candidate ON candidate.id=a.correlation_id AND candidate.resource_id=r.id AND candidate.action='host.probe'
    GROUP BY r.id
)
SELECT r.*, j.id AS observation_id, j.status AS job_status, j.reason AS job_reason, j.updated_at AS checked_at,
       j.scope_digest AS job_scope, j.policy_revision AS job_policy, j.result AS job_result,
       s.result AS success_result
FROM page r
JOIN latest l ON l.id=r.id
LEFT JOIN audit ja ON ja.seq=l.latest_seq
LEFT JOIN jobs j ON j.id=ja.correlation_id
LEFT JOIN audit sa ON sa.seq=l.success_seq
LEFT JOIN jobs s ON s.id=sa.correlation_id
ORDER BY r.id
"""


def _sample(raw):
    if raw is None:
        return None
    try:
        return observation_summary(json.loads(raw))
    except (ValueError, TypeError, Denied):
        return None


class Inventory:
    def __init__(self, store, *, clock=time.time):
        self.store, self.clock = store, clock

    def _public(self, row, now, actor, db):
        success = _sample(row['success_result'])
        status, reason = 'NOT_CHECKED', 'NO_COMPLETED_OBSERVATION'
        if row['job_status'] is not None:
            status = 'UNKNOWN'
            if row['job_scope'] != row['scope_digest'] or row['job_policy'] != row['policy_revision']:
                reason = 'OBSERVATION_SCOPE_CHANGED'
            elif row['job_status'] != 'SUCCEEDED':
                reason = row['job_reason']
            else:
                sample = _sample(row['job_result'])
                if sample is None:
                    reason = 'OBSERVATION_INVALID'
                elif sample['observed_at'] > now or row['checked_at'] > now:
                    reason = 'OBSERVATION_TIME_INVALID'
                elif now - sample['observed_at'] > 300:
                    reason = 'OBSERVATION_STALE'
                else:
                    status, reason = 'REACHABLE', 'PROBE_SUCCEEDED'
        if not row['enabled']:
            status, reason = 'UNKNOWN', 'RESOURCE_DISABLED'
        permissions = {}
        for name, permission in (('probe', 'vps:probe'), ('restart', 'vps:restart'), ('firewall', 'vps:firewall'),
                                 ('applications', 'vps:apps')):
            try:
                AuthService.require(db, actor, permission, row['id'])
            except Denied:
                permissions[name] = False
            else:
                permissions[name] = True
        return {**{k: row[k] for k in ('id', 'revision', 'policy_revision', 'created_at', 'updated_at')},
                'enabled': bool(row['enabled']), 'access_mode': 'READ_ONLY',
                'permissions': permissions,
                'observation': {'status': status, 'reason': reason,
                                'last_checked_at': row['checked_at'], 'last_success': success}}

    def _rows(self, auth, token, *, after='', identity=None, limit=51, permission=None):
        with self.store.read() as db:
            JobQueue._schema(db)
            actor = auth._session(db, token)
            return self._rows_in(db, actor, after=after, identity=identity, limit=limit, permission=permission)

    def _rows_in(self, db, actor, *, after='', identity=None, limit=1, permission=None, include_observation_id=False):
        rows = db.execute(_SELECT, (after, identity, identity, actor['role'] == Role.OWNER, actor['id'], limit)).fetchall()
        now = int(self.clock())
        values = []
        for row in rows:
            AuthService.require(db, actor, 'vps:read', row['id'])
            if permission is not None:
                AuthService.require(db, actor, permission, row['id'])
            value = self._public(row, now, actor, db)
            if include_observation_id:
                value['observation_id'] = row['observation_id']
            values.append(value)
        return values

    def list(self, auth, token, *, after='', limit=50):
        if type(limit) is not int or not 1 <= limit <= 100 or (after and re.fullmatch(ULID, after) is None):
            raise Denied('INVENTORY_CURSOR_INVALID', 422)
        rows = self._rows(auth, token, after=after, limit=limit + 1)
        value = {'items': rows[:limit], 'next_after': rows[limit - 1]['id'] if len(rows) > limit else None}
        return value, etag(value, 0)

    def _resource(self, auth, token, identity, *, permission=None):
        if re.fullmatch(ULID, identity) is None:
            raise Denied('RESOURCE_NOT_FOUND', 404)
        rows = self._rows(auth, token, identity=identity, limit=1, permission=permission)
        if not rows:
            raise Denied('RESOURCE_NOT_FOUND', 404)
        return rows[0]

    def get(self, auth, token, identity):
        value = self._resource(auth, token, identity)
        return value, etag(value, value['revision'])

    def restart_preview(self, auth, token, identity, container_id):
        if re.fullmatch(SHA256, container_id) is None:
            raise Denied('CONTAINER_NOT_FOUND', 404)
        resource = self._resource(auth, token, identity, permission='vps:restart')
        observation = resource['observation']
        if observation['status'] != 'REACHABLE':
            raise Denied('FRESH_OBSERVATION_REQUIRED', 409)
        sample = observation['last_success']
        docker = sample.get('docker') if sample else None
        if docker is None or docker['status'] != 'OBSERVED':
            raise Denied('DOCKER_OBSERVATION_REQUIRED', 409)
        container = next((item for item in docker['containers'] if item['id'] == container_id), None)
        if container is None:
            raise Denied('CONTAINER_NOT_FOUND', 404)
        if container['state'] != 'RUNNING':
            raise Denied('CONTAINER_NOT_RUNNING', 409)
        preview = {
            'version': 1,
            'action': 'docker.restart',
            'status': 'PREVIEW_ONLY',
            'target': {'resource_id': identity, **{key: container[key] for key in ("id", "project", "service", "state")}},
            'resource_revision': resource['revision'],
            'policy_revision': resource['policy_revision'],
            'observed_at': sample['observed_at'],
            'boot_id': sample['boot_id'],
            'risk': 'TEMPORARY_SERVICE_INTERRUPTION',
        }
        return {**preview, 'preview_digest': checksum(preview)}

    def adoption_preview(self, auth, token, identity, project, *, if_match=None):
        with self.store.read() as db:
            actor = auth._session(db, token)
            return self.adoption_preview_in(db, actor, identity, project, if_match=if_match)

    def adoption_preview_in(self, db, actor, identity, project, *, if_match=None):
        JobQueue._schema(db)
        if actor['role'] != Role.OWNER:
            raise Denied('FORBIDDEN')
        if re.fullmatch(COMPOSE_PROJECT, project) is None:
            raise Denied('COMPOSE_PROJECT_NOT_FOUND', 404)
        if re.fullmatch(ULID, identity) is None:
            raise Denied('RESOURCE_NOT_FOUND', 404)
        rows = self._rows_in(db, actor, identity=identity, include_observation_id=True)
        if not rows:
            raise Denied('RESOURCE_NOT_FOUND', 404)
        resource = rows[0]
        observation = resource['observation']
        if observation['status'] != 'REACHABLE':
            raise Denied('FRESH_OBSERVATION_REQUIRED', 409)
        sample = observation['last_success']
        compose = sample['compose']
        if compose['status'] != 'OBSERVED':
            raise Denied('COMPOSE_OBSERVATION_REQUIRED', 409)
        rows = compose['containers']
        containers = [row for row in rows if row['project'] == project]
        if not containers:
            raise Denied('COMPOSE_PROJECT_NOT_FOUND', 404)

        evidence = compose.get('adoption_evidence', {})
        definition = evidence.get('definition', {})
        observed_dependencies = definition.get('dependencies', {})
        observed_configuration = evidence.get('configuration', {})
        configuration = {
            row['id']: observed_configuration.get(row['id'], {'service_config': 'UNKNOWN', 'bind_mounts': 'UNKNOWN'})
            for row in containers
        }
        attachments = {}
        for kind in ('networks', 'volumes'):
            members = defaultdict(set)
            for row in rows:
                for name in row.get(kind) or ():
                    if kind == 'networks' and name in {'bridge', 'host', 'none'}:
                        continue
                    members[name].add(row['project'])
            attachments[kind] = {
                'coverage': 'PARTIAL' if any(row.get(kind) is None for row in rows) else 'OBSERVED_COMPOSE_ONLY',
                'claims': resource_claims(project, members, evidence.get(kind, {}),
                                          evidence.get('usage', {}).get(kind, {})),
                'shared': [
                    {'name': name, 'other_projects': sorted(projects - {project})}
                    for name, projects in sorted(members.items()) if project in projects and len(projects) > 1
                ],
            }

        preview = {
            'version': 1,
            'action': 'compose.adopt',
            'status': 'PREVIEW_ONLY',
            'target': {'resource_id': identity, 'project': project},
            'resource_revision': resource['revision'],
            'policy_revision': resource['policy_revision'],
            'observed_at': sample['observed_at'],
            'boot_id': sample['boot_id'],
            'observation_id': resource['observation_id'],
            'snapshot_digest': checksum(sample),
            'containers': containers,
            'compatibility': assess_profiles(containers, evidence.get('images', {})),
            'configuration': configuration,
            'source': definition.get('sources', {}).get(project, 'UNVERIFIED'),
            'dependencies': {row['id']: observed_dependencies.get(row['id']) for row in containers},
            'attachments': attachments,
        }
        preview['adoption_ready'] = adoption_ready(preview)
        preview['daemon_digest'] = daemon_identity(project, containers)
        value = {**preview, 'preview_digest': checksum(preview)}
        tag = etag(value, resource['revision'])
        if if_match is not None:
            check_etag(if_match, tag)
        return value, tag
