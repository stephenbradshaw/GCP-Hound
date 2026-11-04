"""
IAM role resolution for GCP-Hound.

GCP-Hound historically classified privileges by role-name string matching,
which silently degrades for custom roles (organizations/*/roles/*,
projects/*/roles/*): they fall through to generic edges with no privilege
semantics.

This module enumerates role definitions (predefined + org/project custom)
with the IAM API (roles().list view=FULL) and exposes their
includedPermissions so edge building and privilege analysis can classify
custom roles by what they can actually do.

Requires only read access to the IAM roles API (roles.get / roles.list),
which roles/iam.securityReviewer and roles/iam.securityAuditor both include.
"""

from googleapiclient.discovery import build
from utils.auth import credentials_for_bootstrap

# module-level cache: role name -> list of included permissions
_ROLE_DEFINITIONS = {}

# Permissions that imply attack-relevant privilege when found in ANY role
# (predefined or custom). Used to classify roles whose name we do not match.
CRITICAL_PERMISSIONS = [
    'iam.serviceAccounts.actAs',
    'iam.serviceAccountKeys.create',
    'iam.serviceAccounts.setIamPolicy',
    'resourcemanager.projects.setIamPolicy',
    'resourcemanager.organizations.setIamPolicy',
    'resourcemanager.folders.setIamPolicy',
    'secretmanager.versions.access',
]

HIGH_PERMISSIONS = [
    'compute.instances.create',
    'compute.instances.setServiceAccount',
    'cloudfunctions.functions.create',
    'run.services.create',
    'iam.roles.create',
    'iam.roles.update',
    'storage.buckets.setIamPolicy',
    'iam.serviceAccounts.getAccessToken',
]


def collect_role_definitions(creds, orgs=None, projects=None, args=None):
    """Enumerate predefined + custom role definitions into the module cache.

    Returns {role_name: [permission, ...]}. Custom roles need the caller to
    have iam.roles.list on the org/project; failure there is non-fatal.
    """
    global _ROLE_DEFINITIONS
    roles = {}

    try:
        iam = build('iam', 'v1', credentials=credentials_for_bootstrap(creds))

        # Predefined (Google-managed) roles are global
        req = iam.roles().list(view='FULL', pageSize=1000)
        while req is not None:
            resp = req.execute()
            for role in resp.get('roles', []):
                roles[role.get('name', '')] = role.get('includedPermissions', [])
            req = iam.roles().list_next(req, resp)

        predefined_count = len(roles)

        # Custom roles at organization level
        org_custom = 0
        for org in orgs or []:
            parent = org.get('name') or ''
            if not parent.startswith('organizations/'):
                org_id = org.get('organizationId') or ''
                if not org_id:
                    continue
                parent = f'organizations/{org_id}'
            try:
                req = iam.organizations().roles().list(parent=parent, view='FULL')
                while req is not None:
                    resp = req.execute()
                    for role in resp.get('roles', []):
                        roles[role.get('name', '')] = role.get('includedPermissions', [])
                        org_custom += 1
                    req = iam.organizations().roles().list_next(req, resp)
            except Exception as e:
                if args and args.debug:
                    print(f"[DEBUG] Org custom roles unavailable for {parent}: {e}")

        # Custom roles at project level
        project_custom = 0
        for project in projects or []:
            project_id = (project.get('projectId') or '').lower()
            if not project_id:
                continue
            try:
                req = iam.projects().roles().list(
                    parent=f'projects/{project_id}', view='FULL')
                while req is not None:
                    resp = req.execute()
                    for role in resp.get('roles', []):
                        roles[role.get('name', '')] = role.get('includedPermissions', [])
                        project_custom += 1
                    req = iam.projects().roles().list_next(req, resp)
            except Exception as e:
                if args and args.debug:
                    print(f"[DEBUG] Project custom roles unavailable for {project_id}: {e}")

        _ROLE_DEFINITIONS = roles
        print(f"[+] Role resolver: {predefined_count} predefined roles, "
              f"{org_custom} org custom, {project_custom} project custom")
    except Exception as e:
        if args and args.debug:
            print(f"[DEBUG] Role definition collection failed: {e}")
        print(f"[!] Role resolver: could not enumerate role definitions ({e}); "
              f"custom roles will use name-based classification only")

    return _ROLE_DEFINITIONS


def set_role_definitions(roles):
    """Inject role definitions (used by offline tests)."""
    global _ROLE_DEFINITIONS
    _ROLE_DEFINITIONS = roles or {}


def permissions_for_role(role_name):
    """Return includedPermissions for a role, or [] when unknown."""
    return _ROLE_DEFINITIONS.get(role_name, [])


def is_custom_role(role_name):
    return role_name.startswith(('organizations/', 'projects/'))


def has_role_definitions():
    return bool(_ROLE_DEFINITIONS)


def classify_role_by_permissions(perms):
    """Classify a role by its permission list: CRITICAL / HIGH / MEDIUM / LOW."""
    perms = set(perms or [])
    if not perms:
        return None
    if any(p in perms for p in CRITICAL_PERMISSIONS):
        return 'CRITICAL'
    if any(p in perms for p in HIGH_PERMISSIONS):
        return 'HIGH'
    if any(p.endswith('.getIamPolicy') or p.endswith('.get') or p.endswith('.list')
           for p in perms):
        return 'LOW'
    return 'MEDIUM'