"""
Permission pre-flight for GCP-Hound.

Probes the permissions the collectors actually need via testIamPermissions
(no state change) before enumeration starts, and prints a per-scope
capability summary so missing grants surface up front instead of as
per-collector 403 noise mid-run. Also reports analysis quality lost when
optional integrations (Admin SDK Directory, Cloud Asset Inventory) are
unavailable.

testIamPermissions requires no special permission itself — it reports the
subset of the listed permissions the caller holds.
"""

from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from utils.auth import credentials_for_bootstrap

# permission -> what breaks without it
_PROJECT_PROBES = {
    'resourcemanager.projects.getIamPolicy': 'project IAM bindings',
    'iam.serviceAccounts.list': 'service account enumeration',
    'iam.serviceAccountKeys.list': 'service account key analysis',
    'iam.roles.list': 'custom role resolution',
    'serviceusage.services.list': 'API capability assessment',
}

_ORG_PROBES = {
    'resourcemanager.organizations.getIamPolicy': 'organization IAM bindings',
}

_FOLDER_PROBES = {
    'resourcemanager.folders.getIamPolicy': 'folder IAM bindings',
}

_DIRECTORY_NOTE = (
    'Directory (Admin SDK) access missing: users/groups/memberships come '
    'from IAM bindings only — group membership edges will be incomplete. '
    'Grant Users/Groups Read admin privileges for full identity mapping.')


def run_permission_preflight(creds, projects, orgs=None, folders=None, args=None):
    """Probe required permissions and print a capability summary."""
    if not creds or not projects:
        return

    try:
        crm = build('cloudresourcemanager', 'v1',
                    credentials=credentials_for_bootstrap(creds))
    except Exception as e:
        _debug(args, f'preflight CRM build failed: {e}')
        return

    project_id = None
    for project in projects:
        pid = (project.get('projectId') or '').lower()
        if pid:
            project_id = pid
            break
    if not project_id:
        return

    granted, missing = _probe(crm.projects(), project_id, _PROJECT_PROBES, args)
    _print_scope('project', project_id, granted, missing)

    for org in orgs or []:
        org_name = org.get('name') or ''
        if not org_name.startswith('organizations/'):
            continue
        granted, missing = _probe(crm.organizations(), org_name, _ORG_PROBES, args)
        _print_scope('organization', org_name, granted, missing)
        break

    for folder in folders or []:
        folder_name = folder.get('name') or ''
        if not folder_name.startswith('folders/'):
            continue
        try:
            crm_v2 = build('cloudresourcemanager', 'v2',
                           credentials=credentials_for_bootstrap(creds))
            granted, missing = _probe(crm_v2.folders(), folder_name, _FOLDER_PROBES, args)
            _print_scope('folder', folder_name, granted, missing)
        except Exception as e:
            _debug(args, f'preflight folder probe failed: {e}')
        break

    if args and getattr(args, 'use_cai', False):
        print('[i] Preflight: --use-cai needs cloudasset.assets.searchAllIamPolicies '
              '(roles/cloudasset.viewer); falls back to getIamPolicy when denied')

    print('[i] Preflight: Directory Users/Groups Read (Workspace admin privilege) '
          'is required for full identity mapping; IAM-derived principals are used otherwise')


def _probe(resource, resource_id, probes, args):
    granted, missing = [], []
    try:
        response = resource.testIamPermissions(
            resource=resource_id,
            body={'permissions': list(probes.keys())},
        ).execute()
        granted_set = set(response.get('permissions', []))
        for perm, impact in probes.items():
            if perm in granted_set:
                granted.append(impact)
            else:
                missing.append(impact)
    except HttpError as e:
        _debug(args, f'preflight probe on {resource_id} failed: {e}')
        # Unknown state: report everything as unverified rather than missing
        return [], list(probes.values())
    except Exception as e:
        _debug(args, f'preflight probe on {resource_id} failed: {e}')
        return [], list(probes.values())
    return granted, missing


def _print_scope(scope, resource_id, granted, missing):
    if granted:
        print(f"[i] Preflight {scope} {resource_id}: "
              + ", ".join(granted))
    if missing:
        print(f"[!] Preflight {scope} {resource_id} missing: "
              + ", ".join(missing))


def _debug(args, message):
    if args and args.debug:
        print(f"[DEBUG] Preflight: {message}")