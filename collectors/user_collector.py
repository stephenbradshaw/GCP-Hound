from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from utils.auth import credentials_for_bootstrap

def collect_users(creds, projects, iam_data=None):
    """
    Enumerate users and groups from Google Workspace / Cloud Identity.

    Does not require Workspace Super Admin. Prefer least privilege:
      - Admin SDK Users Read + Groups Read (or custom Admin API privileges)
      - OAuth: admin.directory.user.readonly, admin.directory.group.readonly
      - Fallback: Cloud Identity Groups API (groups.readonly) for groups only
      - Always: principals still appear from IAM bindings without directory access
      - IAM-discovered group emails also get members.list expansion when Directory works
    """
    users = []
    groups = []
    group_memberships = []
    directory_source = None

    if not creds:
        print("[!] No credentials provided to user collector")
        return users, groups, group_memberships

    print("[*] User Collector: Enumerating directory users/groups (Admin SDK / Cloud Identity)...")

    admin_service = None
    try:
        # Admin SDK requires a quota project; use bootstrap fallback only.
        admin_service = build(
            'admin', 'directory_v1',
            credentials=credentials_for_bootstrap(creds),
        )
    except Exception as e:
        print(f"[!] Could not build Admin SDK client: {e}")

    if admin_service:
        try:
            users = collect_workspace_users(admin_service)
        except HttpError as e:
            _log_directory_http(e, "users")
        except Exception as e:
            print(f"[!] Error collecting users: {e}")

        try:
            groups = collect_workspace_groups(admin_service)
        except HttpError as e:
            _log_directory_http(e, "groups")
        except Exception as e:
            print(f"[!] Error collecting groups: {e}")

        if groups:
            try:
                group_memberships = collect_group_memberships(admin_service, groups)
            except Exception as e:
                print(f"[!] Error collecting group memberships: {e}")

        if users or groups:
            directory_source = "admin_sdk"

    if not groups:
        ci_groups, ci_memberships = collect_cloud_identity_groups(creds)
        if ci_groups:
            groups = ci_groups
            group_memberships = ci_memberships
            directory_source = directory_source or "cloud_identity"
            print(f"[+] Cloud Identity fallback: {len(groups)} groups, {len(group_memberships)} memberships")

    # Expand memberships for groups that appear in IAM even if groups.list missed them
    iam_group_emails = extract_group_emails_from_iam(iam_data)
    if iam_group_emails and admin_service:
        known = { (g.get('email') or '').lower() for g in groups }
        extra_groups = []
        for email in sorted(iam_group_emails):
            if email not in known:
                extra_groups.append({
                    'id': email,
                    'email': email,
                    'name': email,
                    'description': 'Discovered from IAM binding',
                    'directMembersCount': 0,
                    'aliases': [],
                    'nonEditableAliases': [],
                    'adminCreated': False,
                    'source': 'iam_binding',
                    'riskLevel': 'MEDIUM',
                })
                known.add(email)
        if extra_groups:
            print(f"[*] Expanding memberships for {len(extra_groups)} IAM-discovered groups "
                  f"not returned by directory groups.list")
            groups.extend(extra_groups)
            try:
                extra_memberships = collect_group_memberships(admin_service, extra_groups)
                group_memberships.extend(extra_memberships)
                if extra_memberships:
                    directory_source = directory_source or "admin_sdk_iam_groups"
            except Exception as e:
                print(f"[!] Error expanding IAM group memberships: {e}")
        else:
            # Still refresh memberships for IAM groups already in the directory list
            # when the initial membership pass was empty (e.g. groups.list worked,
            # members.list failed soft).
            if not group_memberships:
                iam_groups = [g for g in groups if (g.get('email') or '').lower() in iam_group_emails]
                if iam_groups:
                    try:
                        group_memberships = collect_group_memberships(admin_service, iam_groups)
                        if group_memberships:
                            directory_source = directory_source or "admin_sdk"
                    except Exception as e:
                        print(f"[!] Error collecting memberships for IAM groups: {e}")
    elif iam_group_emails and not admin_service:
        print(f"[!] {len(iam_group_emails)} groups seen in IAM but Admin SDK unavailable "
              f"for membership expansion")

    if directory_source:
        print(f"[+] User Collector ({directory_source}): "
              f"{len(users)} users, {len(groups)} groups, {len(group_memberships)} memberships")
    else:
        print("[!] No Directory / Cloud Identity group access - "
              "principals will still be inferred from IAM bindings where present")
        print("    Need: Users/Groups Read Admin API privileges (not Super Admin), "
              "or Cloud Identity groups.readonly, or roles that expose IAM members")

    return users, groups, group_memberships


def extract_group_emails_from_iam(iam_data):
    """Return lowercase group emails referenced in collected IAM bindings."""
    emails = set()
    for policy in iam_data or []:
        for binding in policy.get('bindings', []):
            for member in binding.get('members', []):
                if isinstance(member, str) and member.lower().startswith('group:'):
                    email = member.split(':', 1)[1].strip().lower()
                    if email:
                        emails.add(email)
    return emails


def _log_directory_http(error, label):
    if error.resp.status == 403:
        print(f"[!] No Admin SDK access for {label} - needs Directory Users/Groups Read "
              f"(custom admin role is enough; Super Admin not required)")
    elif error.resp.status == 404:
        print(f"[!] No Google Workspace organization found while listing {label}")
    else:
        print(f"[!] HTTP error collecting {label}: {error}")


def collect_workspace_users(admin_service):
    """Collect all users from Google Workspace"""
    users = []

    try:
        request = admin_service.users().list(customer='my_customer', maxResults=500)

        while request:
            response = request.execute()

            for user in response.get('users', []):
                user_data = {
                    'id': user.get('id'),
                    'email': user.get('primaryEmail'),
                    'name': user.get('name', {}).get('fullName', ''),
                    'firstName': user.get('name', {}).get('givenName', ''),
                    'lastName': user.get('name', {}).get('familyName', ''),
                    'suspended': user.get('suspended', False),
                    'isAdmin': user.get('isAdmin', False),
                    'isDelegatedAdmin': user.get('isDelegatedAdmin', False),
                    'lastLoginTime': user.get('lastLoginTime', ''),
                    'creationTime': user.get('creationTime', ''),
                    'orgUnitPath': user.get('orgUnitPath', '/'),
                    'isMailboxSetup': user.get('isMailboxSetup', True),
                    'includeInGlobalAddressList': user.get('includeInGlobalAddressList', True),
                    'ipWhitelisted': user.get('ipWhitelisted', False),
                    'recoveryEmail': user.get('recoveryEmail', ''),
                    'recoveryPhone': user.get('recoveryPhone', ''),
                    'changePasswordAtNextLogin': user.get('changePasswordAtNextLogin', False),
                    'agreedToTerms': user.get('agreedToTerms', False),
                    'aliases': user.get('aliases', []),
                    'nonEditableAliases': user.get('nonEditableAliases', [])
                }

                user_data['riskLevel'] = determine_user_risk_level(user_data)
                users.append(user_data)

            request = admin_service.users().list_next(request, response)

        print(f"[+] Collected {len(users)} Google Workspace users")

    except HttpError:
        raise
    except Exception as e:
        print(f"[!] Error collecting users: {e}")

    return users

def collect_workspace_groups(admin_service):
    """Collect all groups from Google Workspace"""
    groups = []

    try:
        request = admin_service.groups().list(customer='my_customer', maxResults=200)

        while request:
            response = request.execute()

            for group in response.get('groups', []):
                group_data = {
                    'id': group.get('id'),
                    'email': group.get('email'),
                    'name': group.get('name', ''),
                    'description': group.get('description', ''),
                    'directMembersCount': group.get('directMembersCount', 0),
                    'aliases': group.get('aliases', []),
                    'nonEditableAliases': group.get('nonEditableAliases', []),
                    'adminCreated': group.get('adminCreated', False)
                }

                group_data['riskLevel'] = determine_group_risk_level(group_data)
                groups.append(group_data)

            request = admin_service.groups().list_next(request, response)

        print(f"[+] Collected {len(groups)} Google Workspace groups")

    except HttpError:
        raise
    except Exception as e:
        print(f"[!] Error collecting groups: {e}")

    return groups

def collect_group_memberships(admin_service, groups):
    """Collect memberships for all groups"""
    memberships = []

    for group in groups:
        group_email = group.get('email')
        if not group_email:
            continue

        try:
            request = admin_service.members().list(groupKey=group_email)

            while request:
                response = request.execute()

                for member in response.get('members', []):
                    membership = {
                        'groupId': group.get('id'),
                        'groupEmail': group_email,
                        'memberId': member.get('id'),
                        'memberEmail': member.get('email'),
                        'role': member.get('role', 'MEMBER'),
                        'type': member.get('type', 'USER'),
                        'status': member.get('status', 'ACTIVE'),
                        'delivery_settings': member.get('delivery_settings', 'ALL_MAIL')
                    }

                    membership['riskLevel'] = determine_membership_risk_level(membership, group)
                    memberships.append(membership)

                request = admin_service.members().list_next(request, response)

        except HttpError as e:
            if e.resp.status != 403:
                print(f"[!] Error collecting memberships for {group_email}: {e}")
        except Exception as e:
            print(f"[!] Unexpected error for group {group_email}: {e}")

    print(f"[+] Collected {len(memberships)} group memberships")
    return memberships


def collect_cloud_identity_groups(creds):
    """
    Fallback group enumeration via Cloud Identity Groups API.
    Works with groups.readonly scope / Cloud Identity Group Viewer without
    full Workspace Admin SDK Users access.
    """
    groups = []
    memberships = []

    try:
        service = build(
            'cloudidentity', 'v1',
            credentials=credentials_for_bootstrap(creds),
        )
    except Exception as e:
        print(f"[!] Cloud Identity API unavailable: {e}")
        return groups, memberships

    # Try common customer parent forms. 'my_customer' works for Workspace-linked
    # Cloud Identity when the caller has groups visibility.
    parent_candidates = [
        "customers/my_customer",
    ]

    listed = []
    for parent in parent_candidates:
        try:
            request = service.groups().list(parent=parent, view='BASIC', pageSize=200)
            while request is not None:
                response = request.execute()
                listed.extend(response.get('groups', []))
                request = service.groups().list_next(request, response)
            if listed:
                break
        except HttpError as e:
            if e.resp.status not in (403, 400, 404):
                print(f"[!] Cloud Identity groups.list error: {e}")
        except Exception as e:
            print(f"[!] Cloud Identity groups.list unexpected error: {e}")

    if not listed:
        # Search API variant used by some Cloud Identity setups
        try:
            request = service.groups().search(
                query="parent == 'customers/my_customer'",
                view='BASIC',
                pageSize=200
            )
            while request is not None:
                response = request.execute()
                listed.extend(response.get('groups', []))
                request = service.groups().search_next(request, response)
        except Exception:
            pass

    for group in listed:
        group_name = group.get('name', '')  # groups/{id}
        email = group.get('groupKey', {}).get('id') or group.get('email', '')
        if not email:
            continue
        group_data = {
            'id': group_name.split('/')[-1] if group_name else email,
            'email': email,
            'name': group.get('displayName', email),
            'description': group.get('description', ''),
            'directMembersCount': int(group.get('directMemberCount', 0) or 0),
            'aliases': [],
            'nonEditableAliases': [],
            'adminCreated': False,
            'source': 'cloud_identity'
        }
        group_data['riskLevel'] = determine_group_risk_level(group_data)
        groups.append(group_data)

        # Memberships (best-effort)
        try:
            mreq = service.groups().memberships().list(parent=group_name, pageSize=200)
            while mreq is not None:
                mresp = mreq.execute()
                for member in mresp.get('memberships', []):
                    preferred = member.get('preferredMemberKey', {}) or {}
                    member_email = preferred.get('id', '')
                    roles = [r.get('name', '') for r in member.get('roles', [])]
                    role = 'OWNER' if 'OWNER' in roles else ('MANAGER' if 'MANAGER' in roles else 'MEMBER')
                    membership = {
                        'groupId': group_data['id'],
                        'groupEmail': email,
                        'memberId': member.get('name', ''),
                        'memberEmail': member_email,
                        'role': role,
                        'type': 'USER',
                        'status': 'ACTIVE',
                        'source': 'cloud_identity'
                    }
                    membership['riskLevel'] = determine_membership_risk_level(membership, group_data)
                    memberships.append(membership)
                mreq = service.groups().memberships().list_next(mreq, mresp)
        except HttpError:
            continue
        except Exception:
            continue

    return groups, memberships

def determine_user_risk_level(user_data):
    """Determine risk level for a user"""
    if user_data.get('isAdmin'):
        return 'CRITICAL'
    elif user_data.get('isDelegatedAdmin'):
        return 'HIGH'
    elif user_data.get('suspended'):
        return 'MEDIUM'  # Suspended accounts can be reactivated
    elif any(keyword in user_data.get('email', '').lower() for keyword in ['admin', 'root', 'service']):
        return 'HIGH'
    else:
        return 'LOW'

def determine_group_risk_level(group_data):
    """Determine risk level for a group"""
    group_name = group_data.get('name', '').lower()
    group_email = group_data.get('email', '').lower()

    high_risk_keywords = ['admin', 'owner', 'editor', 'manager', 'root', 'security']

    if any(keyword in group_name or keyword in group_email for keyword in high_risk_keywords):
        return 'HIGH'
    elif group_data.get('directMembersCount', 0) > 50:
        return 'MEDIUM'  # Large groups pose higher risk
    else:
        return 'LOW'

def determine_membership_risk_level(membership, group):
    """Determine risk level for a group membership"""
    role = membership.get('role', '').upper()
    group_risk = group.get('riskLevel', 'LOW')

    if role in ['OWNER', 'MANAGER'] and group_risk in ['HIGH', 'CRITICAL']:
        return 'CRITICAL'
    elif role in ['OWNER', 'MANAGER']:
        return 'HIGH'
    elif group_risk in ['HIGH', 'CRITICAL']:
        return 'MEDIUM'
    else:
        return 'LOW'

def analyze_user_privilege_escalation(users, groups, group_memberships):
    """Analyze privilege escalation opportunities through user/group relationships"""
    escalation_paths = []

    user_groups = {}
    for membership in group_memberships:
        user_email = membership.get('memberEmail', '')
        if user_email not in user_groups:
            user_groups[user_email] = []
        user_groups[user_email].append(membership)

    for user in users:
        user_email = user.get('email', '')
        user_memberships = user_groups.get(user_email, [])

        admin_groups = [m for m in user_memberships if m.get('riskLevel') in ['HIGH', 'CRITICAL']]

        if admin_groups:
            escalation_paths.append({
                'user': user_email,
                'escalationType': 'group_admin_access',
                'adminGroups': [g.get('groupEmail') for g in admin_groups],
                'riskLevel': 'HIGH',
                'description': f"User {user_email} has admin access through {len(admin_groups)} groups"
            })

    print(f"[+] Found {len(escalation_paths)} user privilege escalation paths")
    return escalation_paths

def build_user_group_edges(users, groups, group_memberships, current_user):
    """Build BloodHound edges for user/group relationships"""
    edges = []

    for membership in group_memberships:
        user_email = membership.get('memberEmail')
        group_email = membership.get('groupEmail')
        role = membership.get('role', 'MEMBER')

        if user_email and group_email:
            edge_kind = 'MemberOf' if role == 'MEMBER' else f'{role}Of'

            edge = {
                "start": {"value": user_email},
                "end": {"value": group_email},
                "kind": edge_kind,
                "properties": {
                    "source": "workspace_membership",
                    "role": role,
                    "riskLevel": membership.get('riskLevel', 'LOW'),
                    "memberType": membership.get('type', 'USER'),
                    "status": membership.get('status', 'ACTIVE'),
                    "description": f"{user_email} is {role} of {group_email}"
                }
            }
            edges.append(edge)

    for user in users:
        if user.get('isAdmin') or user.get('isDelegatedAdmin'):
            user_email = user.get('email')
            edge = {
                "start": {"value": user_email},
                "end": {"value": "Google Workspace"},
                "kind": "AdminTo",
                "properties": {
                    "source": "workspace_admin",
                    "adminType": "Super Admin" if user.get('isAdmin') else "Delegated Admin",
                    "riskLevel": "CRITICAL",
                    "description": f"{user_email} has admin access to Google Workspace"
                }
            }
            edges.append(edge)

    print(f"[+] Built {len(edges)} user/group relationship edges")
    return edges
