#!/usr/bin/env python3
from utils.id_utils import normalize_dataset_id
from collectors import role_resolver

def binding_condition(binding):
    """Return the IAM condition dict for a binding, or None when unconditional."""
    condition = binding.get('condition') or {}
    expression = condition.get('expression') or ''
    if not expression:
        return None
    return {
        "title": condition.get('title') or '',
        "expression": expression,
    }

def condition_properties(binding):
    """Edge properties describing an IAM condition (empty when unconditional)."""
    condition = binding_condition(binding)
    if not condition:
        return {}
    return {
        "hasCondition": True,
        "conditionTitle": condition["title"],
        "conditionExpression": condition["expression"],
    }

def safe_add_edge(edges, start_id, end_id, kind, properties):
    """
    Safely add an edge to edges list with validation of node IDs
    Prevents "Node ID cannot be empty" errors by validating before creation
    """
    # Validate start_id
    if not start_id:
        return False
    if not str(start_id).strip():
        return False
        
    # Validate end_id  
    if not end_id:
        return False
    if not str(end_id).strip():
        return False

    # Create validated edge
    edge = {
        "start": {"value": str(start_id).strip()},
        "end": {"value": str(end_id).strip()},
        "kind": kind,
        "properties": properties or {}
    }

    edges.append(edge)
    return True

def build_edges(projects, iam_data, users, service_accounts, buckets, secrets, bigquery_datasets=None, debug=False):
    """
    Build comprehensive attack path edges from collected GCP data.
    Returns list of edges for BloodHound visualization.
    """
    edges = []
    stats = {"created": 0, "skipped": 0}

    if not projects:
        print("[!] No projects provided to edge builder")
        return edges

    print(f"[*] Edge Builder: Processing {len(projects)} projects, {len(iam_data)} IAM policies")
    
    # Print BigQuery datasets info if available
    if bigquery_datasets:
        print(f"[*] Edge Builder: Including {len(bigquery_datasets)} BigQuery datasets")

    # Build edges from IAM bindings with validation
    iam_edges = build_iam_binding_edges(iam_data, projects, debug)
    edges.extend(iam_edges)
    stats["created"] += len(iam_edges)

    # Build service account containment and privilege analysis edges
    sa_edges = build_service_account_edges(service_accounts, projects, iam_data, debug)
    edges.extend(sa_edges)
    stats["created"] += len(sa_edges)

    # Build resource ownership edges (now includes BigQuery datasets)
    resource_edges = build_resource_ownership_edges(projects, buckets, secrets, service_accounts, bigquery_datasets, debug)
    edges.extend(resource_edges)
    stats["created"] += len(resource_edges)

    # Build privilege escalation edges with strict permission separation
    privesc_edges = build_privilege_escalation_edges(iam_data, service_accounts, secrets, debug)
    edges.extend(privesc_edges)
    stats["created"] += len(privesc_edges)

    print(f"[+] Edge Builder: Created {len(edges)} attack relationship edges")
    print(f"[+] Edge validation prevented invalid edges from being created")
    return edges

# NEW: Service account permission edge building function
def build_service_account_permission_edges(service_account_permissions, debug=False):
    """
    Build edges from service account IAM permission analysis.
    Creates User->ServiceAccount relationship edges for impersonation, key creation, etc.
    """
    edges = []
    edges_created = 0
    edges_skipped = 0
    conditioned_skipped = 0
    
    if not service_account_permissions:
        if debug:
            print("[DEBUG] No service account permission data provided")
        return edges
    
    for sa_perms in service_account_permissions:
        sa_email = sa_perms.get('serviceAccount')
        if not sa_email:
            edges_skipped += 1
            continue
            
        bindings = sa_perms.get('bindings', [])
        
        for binding in bindings:
            role = binding.get('role', '')
            members = binding.get('members', [])

            # Conditional grants must not create unconditional attack edges
            condition = binding_condition(binding)
            if condition:
                conditioned_skipped += 1
                continue
            
            for member in members:
                if member.startswith('user:'):
                    user_email = member.replace('user:', '')
                    
                    # Determine edge type and risk level based on role
                    edge_type, risk_level = determine_sa_permission_edge_type(role)
                    
                    if edge_type:
                        success = safe_add_edge(
                            edges=edges,
                            start_id=user_email,
                            end_id=sa_email,
                            kind=edge_type,
                            properties={
                                'source': 'service_account_iam_policy',
                                'role': role,
                                'riskLevel': risk_level,
                                'project': sa_perms.get('project', 'Unknown'),
                                'description': f"User can {edge_type.lower().replace('can', '')} service account via {role}"
                            }
                        )
                        
                        if success:
                            edges_created += 1
                            if debug and edges_created <= 10:
                                print(f"[DEBUG] ✅ SA permission edge: {user_email} --[{edge_type}]-> {sa_email}")
                        else:
                            edges_skipped += 1
                
                elif member.startswith('serviceAccount:'):
                    source_sa_email = member.replace('serviceAccount:', '')
                    
                    # Service account to service account relationships
                    edge_type, risk_level = determine_sa_permission_edge_type(role)
                    
                    if edge_type:
                        success = safe_add_edge(
                            edges=edges,
                            start_id=source_sa_email,
                            end_id=sa_email,
                            kind=edge_type,
                            properties={
                                'source': 'service_account_iam_policy',
                                'role': role,
                                'riskLevel': risk_level,
                                'project': sa_perms.get('project', 'Unknown'),
                                'description': f"Service account can {edge_type.lower().replace('can', '')} target service account via {role}"
                            }
                        )
                        
                        if success:
                            edges_created += 1
                            if debug and edges_created <= 10:
                                print(f"[DEBUG] ✅ SA-to-SA permission edge: {source_sa_email} --[{edge_type}]-> {sa_email}")
                        else:
                            edges_skipped += 1
    
    print(f"[+] Built {edges_created} service account permission edges")
    if edges_skipped > 0:
        print(f"[WARNING] Skipped {edges_skipped} invalid service account permission edges")
    if conditioned_skipped > 0:
        print(f"[~] Skipped {conditioned_skipped} conditional binding(s) on service accounts "
              f"(conditioned grants are not unconditional attack paths)")
    
    return edges

def determine_sa_permission_edge_type(role):
    """
    Determine edge type and risk level from GCP IAM role for service account permissions.
    Returns (edge_type, risk_level) tuple.
    """
    role_lower = role.lower()
    
    # Service Account User role
    if 'serviceaccountuser' in role_lower or 'iam.serviceAccounts.actAs' in role_lower:
        return 'CanImpersonate', 'HIGH'
    
    # Service Account Key Admin roles
    if 'serviceaccountkeyAdmin' in role_lower or 'iam.serviceAccountKeys.create' in role_lower:
        return 'CanCreateKeys', 'CRITICAL'
    
    # Service Account Admin role
    if 'serviceaccountadmin' in role_lower or 'iam.serviceAccounts.setIamPolicy' in role_lower:
        return 'CanManageSA', 'HIGH'
    
    # Token Creator role  
    if 'serviceaccounttokencreator' in role_lower or 'iam.serviceAccounts.getAccessToken' in role_lower:
        return 'CanGetAccessToken', 'HIGH'
    
    # Owner and Editor roles (broad permissions)
    if role_lower == 'roles/owner':
        return 'CanManageSA', 'CRITICAL'
    elif role_lower == 'roles/editor':
        return 'CanImpersonate', 'HIGH'
    
    # IAM Security Admin
    if 'iam.securityadmin' in role_lower:
        return 'CanManageSA', 'CRITICAL'
    
    return None, None

# All your existing functions remain unchanged below...

def get_sa_roles_from_iam(sa_email, iam_data):
    """Extract actual roles assigned to service account from IAM data.

    Conditional bindings are excluded: a role gated by an IAM condition does
    not imply unconditional privilege, so it must not drive privilege
    classification or attack-path edges.
    """
    sa_roles = []

    if not iam_data:
        return sa_roles

    service_account_identifier = f"serviceAccount:{sa_email}"

    for iam_policy in iam_data:
        bindings = iam_policy.get('bindings', [])

        for binding in bindings:
            if binding_condition(binding):
                continue
            members = binding.get('members', [])
            role = binding.get('role', '')

            if service_account_identifier in members:
                sa_roles.append(role)

    return sa_roles

def analyze_sa_actual_privileges(sa_email, iam_data):
    """Analyze service account's ACTUAL privilege level from IAM data"""
    if not iam_data:
        return "UNKNOWN"

    sa_roles = get_sa_roles_from_iam(sa_email, iam_data)

    critical_roles = ['roles/owner', 'roles/iam.securityAdmin', 'roles/iam.organizationAdmin']
    high_roles = ['roles/editor', 'roles/compute.admin', 'roles/storage.admin', 'roles/iam.serviceAccountAdmin']
    medium_roles = ['roles/compute.instanceAdmin', 'roles/storage.objectAdmin', 'roles/bigquery.dataEditor']

    # Name-unmatched roles (typically custom roles) are classified by their
    # actual includedPermissions when role definitions were collected.
    unmatched = [r for r in sa_roles
                 if r not in critical_roles + high_roles + medium_roles
                 and 'viewer' not in r.lower()]
    perm_class = None
    for role in unmatched:
        perms = role_resolver.permissions_for_role(role)
        classified = role_resolver.classify_role_by_permissions(perms)
        if classified == 'CRITICAL':
            perm_class = 'CRITICAL'
            break
        if classified == 'HIGH' and perm_class != 'CRITICAL':
            perm_class = 'HIGH'
        elif classified == 'MEDIUM' and perm_class is None:
            perm_class = 'MEDIUM'

    if perm_class == 'CRITICAL' or any(role in critical_roles for role in sa_roles):
        return "CRITICAL"
    elif perm_class == 'HIGH' or any(role in high_roles for role in sa_roles):
        return "HIGH"
    elif perm_class == 'MEDIUM' or any(role in medium_roles for role in sa_roles):
        return "MEDIUM"
    elif any('viewer' in role.lower() for role in sa_roles):
        return "LOW"
    else:
        return "LIMITED"

def get_privilege_reason(sa_email, iam_data):
    """Get human-readable reason why service account is considered high-privilege"""
    roles = get_sa_roles_from_iam(sa_email, iam_data)

    critical_roles = [r for r in roles if r in ['roles/owner', 'roles/iam.securityAdmin']]
    admin_roles = [r for r in roles if 'admin' in r.lower()]

    if critical_roles:
        return f"Has critical roles: {', '.join(critical_roles)}"
    elif admin_roles:
        return f"Has admin roles: {', '.join(admin_roles)}"
    elif len(roles) > 3:
        return f"Has multiple roles ({len(roles)}): {', '.join(roles[:3])}..."
    elif roles:
        return f"Has roles: {', '.join(roles)}"
    else:
        return "No roles found"

def build_service_account_edges(service_accounts, projects, iam_data=None, debug=False):
    """Build service account relationship edges with dynamic privilege analysis"""
    edges = []
    edges_created = 0
    edges_skipped = 0

    for sa in service_accounts:
        sa_email = sa.get('email', '').lower()
        project_id = sa.get('project', '').lower()

        if not sa_email or not project_id:
            edges_skipped += 1
            if debug:
                print(f"[DEBUG] Skipping SA with missing email/project: {sa}")
            continue

        # Basic containment edge with validation
        success = safe_add_edge(
            edges=edges,
            start_id=project_id,
            end_id=sa_email,
            kind="ContainsServiceAccount",
            properties={
                "source": "service_account_ownership",
                "riskLevel": "LOW",
                "keyCount": sa.get('keyCount', 0),
                "disabled": sa.get('disabled', False),
                "description": f"Project {project_id} contains service account {sa_email}"
            }
        )
        
        if success:
            edges_created += 1
            if debug:
                print(f"[DEBUG] ✅ Containment edge: {project_id} -> {sa_email}")
        else:
            edges_skipped += 1

        # Dynamic privilege analysis based on actual IAM roles
        actual_privilege_level = analyze_sa_actual_privileges(sa_email, iam_data)

        # Only create high-privilege edge if actually high-privileged
        if actual_privilege_level in ['CRITICAL', 'HIGH']:
            success = safe_add_edge(
                edges=edges,
                start_id=sa_email,
                end_id=project_id,
                kind="HighPrivilegeServiceAccount",
                properties={
                    "source": "iam_privilege_analysis",
                    "riskLevel": actual_privilege_level,
                    "actualRoles": get_sa_roles_from_iam(sa_email, iam_data),
                    "privilegeReason": get_privilege_reason(sa_email, iam_data),
                    "description": f"Service account {sa_email} has {actual_privilege_level} privileges based on IAM roles"
                }
            )
            
            if success:
                edges_created += 1
                if debug:
                    print(f"[DEBUG] ✅ High privilege edge: {sa_email} -> {project_id} ({actual_privilege_level})")
            else:
                edges_skipped += 1

    print(f"[+] Built {edges_created} service account edges (privilege analysis: {'IAM-based' if iam_data else 'limited'})")
    if edges_skipped > 0:
        print(f"[WARNING] Skipped {edges_skipped} invalid service account edges")
    return edges

def determine_resource_edge_kind(role, resource_type):
    """Map a role to an edge kind for resource-level IAM policies
    (buckets, secrets, BigQuery datasets, service accounts).

    Returns None when the role has no meaningful attack-path relationship
    to that resource type — those bindings are skipped rather than
    overstated. Custom roles are classified via the role resolver's
    permission expansion.
    """
    role_lower = (role or '').lower()
    perms = [p.lower() for p in role_resolver.permissions_for_role(role)] \
        if role_resolver.has_role_definitions() else []

    if resource_type == 'bucket':
        if role_lower in ('roles/owner', 'roles/storage.admin') \
                or 'storage.buckets.setiampolicy' in perms:
            return 'CanModifyBucketPolicy'
        return None
    if resource_type == 'secret':
        if role_lower in ('roles/secretmanager.secretaccessor', 'roles/secretmanager.admin') \
                or 'secretmanager.versions.access' in perms:
            return 'CanReadSecrets'
        return None
    if resource_type == 'dataset':
        if role_lower in ('roles/bigquery.dataviewer', 'roles/bigquery.dataowner',
                          'roles/bigquery.dataeditor', 'roles/bigquery.admin') \
                or any(p.startswith('bigquery.datasets.') for p in perms):
            return 'CanAccessBigQueryDataset'
        return None
    if resource_type == 'serviceAccount':
        sa_role_kinds = {
            'roles/owner': 'CanImpersonate',
            'roles/editor': 'CanImpersonate',
            'roles/iam.serviceaccountuser': 'CanImpersonate',
            'roles/iam.serviceaccounttokencreator': 'CanGetAccessToken',
            'roles/iam.serviceaccountkeyadmin': 'CanCreateKeys',
        }
        if role_lower in sa_role_kinds:
            return sa_role_kinds[role_lower]
        perm_map = {
            'iam.serviceaccounts.actas': 'CanImpersonate',
            'iam.serviceaccounts.getaccesstoken': 'CanGetAccessToken',
            'iam.serviceaccounts.signblob': 'CanSignBlob',
            'iam.serviceaccounts.signjwt': 'CanSignJWT',
            'iam.serviceaccountkeys.create': 'CanCreateKeys',
            'iam.serviceaccounts.setiampolicy': 'CanModifyIamPolicy',
            'iam.serviceaccounts.listkeys': 'CanListKeys',
        }
        for perm in perms:
            if perm in perm_map:
                return perm_map[perm]
        return None
    if resource_type == 'runService':
        # Invoking a Cloud Run service that runs as an SA yields code
        # execution as that identity; admin roles can grant themselves
        # invoker, so treat them equivalently.
        if role_lower in ('roles/run.invoker', 'roles/run.admin',
                          'roles/owner', 'roles/editor') \
                or 'run.services.setiampolicy' in perms \
                or 'run.routes.invoke' in perms \
                or 'run.jobs.run' in perms:
            return 'CanInvokeRunService'
        return None
    if resource_type == 'function':
        if role_lower in ('roles/cloudfunctions.invoker', 'roles/cloudfunctions.developer',
                          'roles/cloudfunctions.admin', 'roles/owner', 'roles/editor') \
                or 'cloudfunctions.functions.invoke' in perms:
            return 'CanAccessCloudFunction'
        return None
    if resource_type == 'kmsKey':
        # Decrypt on a key = access to everything encrypted with it
        if role_lower in ('roles/owner', 'roles/editor', 'roles/cloudkms.admin',
                          'roles/cloudkms.cryptokeydecrypter') \
                or 'cloudkms.cryptokeyversions.decrypt' in perms \
                or 'cloudkms.cryptokeys.setiampolicy' in perms:
            return 'CanDecrypt'
        return 'HasResourceRole'
    if resource_type == 'kmsKeyRing':
        return 'HasResourceRole'
    if resource_type in ('disk', 'snapshot', 'image'):
        # Snapshot/image read access is an exfil path but requires
        # compute permissions beyond plain IAM on the object; keep as
        # inventory rather than implying traversal.
        return 'HasResourceRole'
    if resource_type == 'pubsubTopic':
        if role_lower in ('roles/owner', 'roles/editor', 'roles/pubsub.publisher',
                          'roles/pubsub.editor', 'roles/pubsub.admin') \
                or 'pubsub.topics.publish' in perms:
            return 'CanPublishPubSub'
        if role_lower in ('roles/pubsub.subscriber', 'roles/pubsub.viewer') \
                or 'pubsub.topics.attachsubscription' in perms:
            return 'CanAccessPubSub'
        return 'HasResourceRole'
    if resource_type == 'pubsubSub':
        if role_lower in ('roles/owner', 'roles/editor', 'roles/pubsub.subscriber',
                          'roles/pubsub.viewer', 'roles/pubsub.admin') \
                or 'pubsub.subscriptions.consume' in perms:
            return 'CanAccessPubSub'
        return 'HasResourceRole'
    if resource_type == 'bqTable':
        return 'HasResourceRole'
    if resource_type == 'logSink':
        if role_lower in ('roles/owner', 'roles/editor', 'roles/logging.admin',
                          'roles/logging.configwriter') \
                or any(p.startswith('logging.sinks.') for p in perms):
            return 'CanWriteToLogSink'
        return 'HasResourceRole'
    if resource_type == 'logBucket':
        if role_lower in ('roles/owner', 'roles/editor', 'roles/logging.admin',
                          'roles/logging.viewermanager', 'roles/logging.privatelogviewer',
                          'roles/logging.viewer') \
                or any(p.startswith('logging.buckets.') for p in perms):
            return 'CanViewSensitiveLogs'
        return 'HasResourceRole'
    if resource_type == 'artifactRepo':
        return 'HasResourceRole'
    if resource_type == 'computeInstance':
        if role_lower in ('roles/compute.admin', 'roles/owner', 'roles/editor') \
                or 'compute.instances.setserviceaccount' in perms:
            return 'CanChangeInstanceServiceAccount'
        return 'HasResourceRole'
    # Other unmapped resource types have no meaningful edge kind.
    return None

def determine_enhanced_edge_kind_from_role(role, resource_type='project'):
    """Map role to enhanced edge kind for IAM edges (project / folder / organization)."""
    role_lower = role.lower()
    resource_type = (resource_type or 'project').lower()

    if resource_type == 'organization':
        if role_lower in ('roles/owner', 'roles/resourcemanager.organizationadmin'):
            return 'OwnsOrganization'
        if role_lower in (
            'roles/resourcemanager.organizationroleadmin',
            'roles/iam.organizationroleadmin',
            'roles/iam.securityadmin',
        ):
            return 'CanModifyOrganizationPolicy'
        if role_lower in ('roles/viewer', 'roles/browser', 'roles/resourcemanager.organizationviewer'):
            return 'MemberOfOrganization'
        return 'HasRoleOnOrganization'

    if resource_type == 'folder':
        if role_lower in ('roles/owner', 'roles/resourcemanager.folderadmin'):
            return 'OwnsFolder'
        if role_lower in (
            'roles/resourcemanager.folderiamadmin',
            'roles/iam.securityadmin',
        ):
            return 'CanModifyFolderPolicy'
        if role_lower in ('roles/viewer', 'roles/browser', 'roles/resourcemanager.folderviewer'):
            return 'MemberOfFolder'
        return 'HasRoleOnFolder'

    # Project (default)
    if role_lower == 'roles/owner':
        return 'OwnsProject'

    if role_lower in ['roles/resourcemanager.projectiamadmin', 'roles/iam.securityadmin', 'roles/iam.organizationadmin']:
        return 'ManageProjectIAM'

    if role_lower == 'roles/editor':
        return 'CanEditProject'
    if role_lower in ['roles/viewer', 'roles/browser']:
        return 'CanViewProject'

    if role_lower.startswith('roles/compute.') and 'admin' in role_lower:
        return 'ManageProjectCompute'
    if role_lower.startswith('roles/storage.') and 'admin' in role_lower:
        return 'ManageProjectStorage'
    if role_lower.startswith('roles/bigquery.') and 'admin' in role_lower:
        return 'ManageProjectBigQuery'

    if role_lower.startswith(('roles/datastore.', 'roles/firebase.', 'roles/firebaseauth.', 'roles/firebasedatabase.')):
        return 'HasRoleOnProject'

    if 'admin' in role_lower and not any(x in role_lower for x in ['datastore', 'firebase']):
        return 'AdministerProject'

    return 'HasRoleOnProject'


def _iam_policy_target(iam_policy):
    """Return (resource_type, resource_name) for an IAM policy entry."""
    resource_type = (iam_policy.get('resourceType') or '').lower()
    resource_name = iam_policy.get('resourceName', '')

    if resource_type == 'organization' or iam_policy.get('organizationId'):
        org_id = iam_policy.get('organizationId') or resource_name.replace('organizations/', '')
        return 'organization', resource_name or f'organizations/{org_id}'
    if resource_type == 'folder' or iam_policy.get('folderId'):
        folder_id = iam_policy.get('folderId') or resource_name.replace('folders/', '')
        return 'folder', resource_name or f'folders/{folder_id}'
    # Resource-level types collected via Cloud Asset Inventory
    for rt in ('bucket', 'secret', 'dataset', 'serviceAccount', 'runService',
               'function', 'computeInstance', 'kmsKey', 'kmsKeyRing', 'disk',
               'snapshot', 'image', 'pubsubTopic', 'pubsubSub', 'bqTable',
               'logSink', 'logBucket', 'artifactRepo'):
        if resource_type == rt.lower():
            return rt, resource_name

    project_id = (iam_policy.get('projectId') or '').lower()
    return 'project', project_id

def get_attack_surface_for_role(role):
    """Get attack surface description for GCP role"""
    attack_surfaces = {
        'roles/owner': 'Full project control including IAM, billing, and resource management',
        'roles/editor': 'Resource creation/modification without IAM management',
        'roles/viewer': 'Read-only access to project resources',
        'roles/iam.securityAdmin': 'IAM policy management and security configuration',
        'roles/compute.admin': 'Compute Engine instances and infrastructure control',
        'roles/storage.admin': 'Cloud Storage buckets and objects management',
        'roles/bigquery.admin': 'BigQuery datasets, jobs, and data access'
    }
    return attack_surfaces.get(role, 'Specialized role-based access to project resources')

def determine_risk_level_from_role(role):
    """Determine risk level from GCP role with enhanced granularity"""
    role_lower = role.lower()

    if any(critical in role_lower for critical in ['owner', 'securityadmin', 'iam.admin']):
        return 'CRITICAL'
    elif any(high in role_lower for high in ['editor', 'admin', 'compute.admin', 'storage.admin']):
        return 'HIGH'
    elif any(medium in role_lower for medium in ['dataviewer', 'bigquery.user', 'cloudsql.client']):
        return 'MEDIUM'
    elif 'viewer' in role_lower or 'browser' in role_lower:
        return 'LOW'
    else:
        return 'MEDIUM'

def build_iam_binding_edges(iam_data, projects, debug=False):
    """Build edges from IAM policy bindings with role-to-edge mapping"""
    edges = []
    edges_created = 0
    edges_skipped = 0

    for iam_policy in iam_data:
        resource_type, resource_name = _iam_policy_target(iam_policy)
        if not resource_name:
            edges_skipped += 1
            continue

        bindings = iam_policy.get('bindings', [])

        for binding in bindings:
            role = binding.get('role', '')
            members = binding.get('members', [])

            for member in members:
                if member.startswith('serviceAccount:'):
                    member_id = member.replace('serviceAccount:', '').lower()
                    member_type = 'ServiceAccount'
                elif member.startswith('user:'):
                    member_id = member.replace('user:', '').lower()
                    member_type = 'User'
                elif member.startswith('group:'):
                    member_id = member.replace('group:', '').lower()
                    member_type = 'Group'
                else:
                    continue
                condition = None

                # Resource-level IAM: only mapped resource types produce
                # edges (strong kinds where an attack relationship exists,
                # GCP_HasResourceRole inventory otherwise); conditioned
                # resource grants are skipped rather than mislabeled.
                if resource_type in ('bucket', 'secret', 'dataset', 'serviceAccount',
                                     'runService', 'function', 'computeInstance',
                                     'kmsKey', 'kmsKeyRing', 'disk', 'snapshot',
                                     'image', 'pubsubTopic', 'pubsubSub', 'bqTable',
                                     'logSink', 'logBucket', 'artifactRepo'):
                    if binding_condition(binding):
                        edges_skipped += 1
                        continue
                    edge_kind = determine_resource_edge_kind(role, resource_type)
                    if not edge_kind:
                        edges_skipped += 1
                        continue
                    # Normalize resource-level target ids to the canonical
                    # node ids json_builder exports for these types.
                    policy_project = (iam_policy.get('projectId', '') or '').lower()
                    policy_location = (iam_policy.get('location', '') or '').lower()
                    if resource_type == 'dataset':
                        resource_name = normalize_dataset_id(resource_name) or ''
                    elif resource_type == 'runService':
                        resource_name = (f"gcp-run-service-{policy_project}"
                                         f"-{policy_location}-{resource_name}").lower()
                    elif resource_type == 'function':
                        resource_name = (f"gcp-cloudfunction-{policy_project}"
                                         f"-{policy_location}-{resource_name}").lower()
                    elif resource_type == 'computeInstance':
                        resource_name = (f"gcp-compute-instance-{policy_project}"
                                         f"-{(iam_policy.get('zone', '') or '').lower()}"
                                         f"-{resource_name}")
                    elif resource_type == 'disk':
                        resource_name = (f"gcp-disk-{policy_project}"
                                         f"-{(iam_policy.get('zone', '') or '').lower()}"
                                         f"-{resource_name}")
                    elif resource_type == 'kmsKey':
                        resource_name = resource_name.lower()
                    elif resource_type == 'kmsKeyRing':
                        resource_name = resource_name.lower()
                    elif resource_type == 'snapshot':
                        resource_name = f"gcp-snapshot-{policy_project}-{resource_name}".lower()
                    elif resource_type == 'image':
                        resource_name = f"gcp-image-{policy_project}-{resource_name}".lower()
                    elif resource_type == 'pubsubTopic':
                        resource_name = f"gcp-pubsub-topic-{policy_project}-{resource_name}".lower()
                    elif resource_type == 'pubsubSub':
                        resource_name = (f"gcp-pubsub-subscription-{policy_project}"
                                         f"-{resource_name}").lower()
                    elif resource_type == 'bqTable':
                        resource_name = f"gcp-bq-table-{resource_name}".lower()
                    elif resource_type == 'logSink':
                        resource_name = f"{policy_project}-sink-{resource_name}"
                    elif resource_type == 'logBucket':
                        resource_name = f"{policy_project}-bucket-{resource_name}"
                    elif resource_type == 'artifactRepo':
                        resource_name = (f"gcp-artifact-repo-{policy_project}"
                                         f"-{policy_location}-{resource_name}").lower()
                    if not resource_name:
                        edges_skipped += 1
                        continue
                else:
                    edge_kind = determine_enhanced_edge_kind_from_role(role, resource_type)
                    condition = binding_condition(binding)
                    if condition:
                        # A conditional grant is not unconditional ownership or
                        # policy control; downgrade strong kinds to the generic
                        # role-grant edge and flag the condition on the edge.
                        edge_kind = f'HasRoleOn{resource_type.capitalize()}'
                risk_level = determine_risk_level_from_role(role)

                description = f"{member_type} {member_id} has {role} on {resource_type} {resource_name}"
                if condition:
                    description += f" (conditional: {condition['title'] or 'IAM condition'})"

                properties = {
                    "source": "iam_policy_binding",
                    "role": role,
                    "riskLevel": risk_level,
                    "memberType": member_type,
                    "resourceType": resource_type,
                    "resourceName": resource_name,
                    "attackSurface": get_attack_surface_for_role(role),
                    "description": description,
                    **condition_properties(binding),
                }
                if resource_type == 'project':
                    properties["projectId"] = resource_name

                success = safe_add_edge(
                    edges=edges,
                    start_id=member_id,
                    end_id=resource_name,
                    kind=edge_kind,
                    properties=properties
                )

                if success:
                    edges_created += 1
                    if debug and edges_created <= 5:
                        print(f"[DEBUG] ✅ IAM edge: {member_id} --[{edge_kind}]-> {resource_name}")
                else:
                    edges_skipped += 1

    print(f"[+] Built {edges_created} IAM binding edges")
    if edges_skipped > 0:
        print(f"[WARNING] Skipped {edges_skipped} invalid IAM binding edges")
    return edges

def build_resource_ownership_edges(projects, buckets, secrets, service_accounts, bigquery_datasets=None, debug=False):
    """Build resource ownership edges with validation - NOW INCLUDES BIGQUERY DATASETS"""
    edges = []
    edges_created = 0
    edges_skipped = 0

    # Existing bucket logic
    for bucket in buckets:
        bucket_name = bucket.get('name', '').lower()
        project_id = bucket.get('project', '').lower()

        if bucket_name and project_id:
            is_public = bucket.get('publicAccess') == 'allUsers'
            has_versioning = bucket.get('versioning', False)
            risk_level = "CRITICAL" if is_public else ("LOW" if has_versioning else "MEDIUM")

            success = safe_add_edge(
                edges=edges,
                start_id=project_id,
                end_id=bucket_name,
                kind="OwnsStorageBucket",
                properties={
                    "source": "resource_ownership", 
                    "resourceType": "Storage Bucket",
                    "riskLevel": risk_level,
                    "publicAccess": bucket.get('publicAccess', 'unknown'),
                    "versioning": has_versioning,
                    "location": bucket.get('location', ''),
                    "description": f"Project {project_id} owns storage bucket {bucket_name}"
                }
            )
            
            if success:
                edges_created += 1
                if debug:
                    print(f"[DEBUG] ✅ Bucket ownership: {project_id} -> {bucket_name}")
            else:
                edges_skipped += 1

    # Existing secrets logic
    for secret in secrets:
        secret_name = secret.get('name', '').lower()
        project_id = secret.get('project', '').lower()

        if secret_name and project_id:
            success = safe_add_edge(
                edges=edges,
                start_id=project_id,
                end_id=secret_name,
                kind="OwnsSecret",
                properties={
                    "source": "resource_ownership",
                    "resourceType": "Secret",
                    "riskLevel": "HIGH",
                    "encryptionStatus": "Google-managed",
                    "description": f"Project {project_id} owns secret {secret_name}"
                }
            )
            
            if success:
                edges_created += 1
                if debug:
                    print(f"[DEBUG] ✅ Secret ownership: {project_id} -> {secret_name}")
            else:
                edges_skipped += 1

    # BigQuery dataset logic
    if bigquery_datasets:
        for dataset in bigquery_datasets:
            dataset_id = dataset.get('dataset_id', '')
            project_id = dataset.get('project', '').lower()
            
            if dataset_id and project_id:
                # Use the SAME ID format your json_builder uses for dataset nodes
                canonical_dataset_id = normalize_dataset_id(dataset_id, project_id)
                
                success = safe_add_edge(
                    edges=edges,
                    start_id=project_id,
                    end_id=canonical_dataset_id,
                    kind="OwnsDataset",
                    properties={
                        "source": "resource_ownership",
                        "resourceType": "BigQuery Dataset", 
                        "riskLevel": dataset.get('riskLevel', 'MEDIUM'),
                        "tableCount": dataset.get('table_count', 0),
                        "location": dataset.get('location', 'Unknown'),
                        "fullDatasetId": dataset.get('full_dataset_id', f"{project_id}:{dataset_id}"),
                        "description": f"Project {project_id} owns BigQuery dataset {canonical_dataset_id}"
                    }
                )
                
                if success:
                    edges_created += 1
                    if debug:
                        print(f"[DEBUG] ✅ Dataset ownership: {project_id} -> {canonical_dataset_id}")
                else:
                    edges_skipped += 1

    print(f"[+] Built {edges_created} resource ownership edges")
    if edges_skipped > 0:
        print(f"[WARNING] Skipped {edges_skipped} invalid resource ownership edges")
    return edges

def get_enhanced_permissions_for_role(role):
    """Get comprehensive permissions contained in a GCP role"""
    role_permissions = {
        'roles/owner': [
            'iam.serviceAccounts.actAs', 'iam.serviceAccountKeys.create',
            'iam.serviceAccounts.signBlob', 'iam.serviceAccounts.signJwt', #added for sigining blob and jwt
            'compute.instances.create', 'cloudfunctions.functions.create',
            'resourcemanager.projects.setIamPolicy', 'storage.buckets.setIamPolicy'
            'secretmanager.secrets.get', 'secretmanager.versions.access'# added for secrets enumeration
        ],
        'roles/editor': [
            'iam.serviceAccounts.actAs',
            'iam.serviceAccounts.signBlob', 'iam.serviceAccounts.signJwt', #added for sigining blob and jwt
            'compute.instances.create',
            'cloudfunctions.functions.create', 'compute.instances.setServiceAccount'
        ],
        'roles/iam.serviceAccountTokenCreator': ['iam.serviceAccounts.getAccessToken', 'iam.serviceAccounts.signBlob', 'iam.serviceAccounts.signJwt'], #added for sigining blob and jwt
        'roles/iam.serviceAccountUser': ['iam.serviceAccounts.actAs'],
        'roles/iam.serviceAccountKeyAdmin': ['iam.serviceAccountKeys.create', 'iam.serviceAccountKeys.get'],
        'roles/iam.securityAdmin': ['iam.serviceAccounts.actAs', 'resourcemanager.projects.setIamPolicy'],
        'roles/compute.admin': ['compute.instances.create', 'compute.instances.setServiceAccount'],
        'roles/storage.admin': ['storage.buckets.setIamPolicy'],
        'roles/deploymentmanager.editor': ['deploymentmanager.deployments.create'],
        'roles/secretmanager.secretAccessor': ['secretmanager.versions.access'],# added for secrets enumeration
        'roles/secretmanager.admin': ['secretmanager.secrets.get', 'secretmanager.versions.access']# added for secrets enumeration
    }
    if role in role_permissions:
        return role_permissions[role]

    # Custom roles (organizations/*/roles/*, projects/*/roles/*) and any
    # predefined role not in the static map: use the actual includedPermissions
    # from the IAM role definitions collected by the role resolver.
    resolved = role_resolver.permissions_for_role(role)
    if resolved:
        return resolved
    return []

def get_escalation_risk_level(permission):
    critical_perms = [
        'iam.serviceAccounts.actAs', 'iam.serviceAccountKeys.create',
        'resourcemanager.projects.setIamPolicy', 'storage.buckets.setIamPolicy',
        'secretmanager.versions.access'# added for secrets permission
    ]
    high_perms = [
        'compute.instances.create', 'cloudfunctions.functions.create',
        'compute.instances.setServiceAccount', 'cloudfunctions.functions.sourceCodeSet',
        'secretmanager.secrets.get'# added for secrets permission
    ]
    if permission in critical_perms:
        return 'CRITICAL'
    elif permission in high_perms:
        return 'HIGH'
    else:
        return 'MEDIUM'

def get_attack_vector_for_permission(permission):
    """Map GCP permissions to attack vectors"""
    attack_vectors = {
        'iam.serviceAccounts.actAs': 'Service Account Impersonation',
        'iam.serviceAccounts.getAccessToken': 'Token Minting',
        'iam.serviceAccounts.signBlob': 'Credential Forging',
        'iam.serviceAccounts.signJwt': 'Credential Forging',
        'iam.serviceAccounts.setIamPolicy': 'Service Account Policy Takeover',
        'iam.serviceAccountKeys.create': 'Service Account Key Creation',
        'compute.instances.create': 'Compute Instance Privilege Escalation',
        'compute.instances.setServiceAccount': 'Instance Service Account Hijacking',
        'cloudfunctions.functions.create': 'Serverless Code Execution',
        'resourcemanager.projects.setIamPolicy': 'Project Policy Takeover',
        'storage.buckets.setIamPolicy': 'Bucket Policy Manipulation',
        'secretmanager.versions.access': 'Secret Value Access',# added for secrets permission
        'secretmanager.secrets.get': 'Secret Metadata Access'# added for secrets permission
    }
    return attack_vectors.get(permission, 'Resource Manipulation')

def get_mitre_technique_for_permission(permission):
    """Map GCP permissions to MITRE ATT&CK techniques (experimental for now, will work on enhancement later)"""
    mitre_mapping = {
        'iam.serviceAccounts.actAs': 'T1078.004',
        'iam.serviceAccounts.getAccessToken': 'T1078.004',
        'iam.serviceAccountKeys.create': 'T1098.001',
        'compute.instances.create': 'T1578.002',
        'cloudfunctions.functions.create': 'T1578.001'
    }
    return mitre_mapping.get(permission, '')

def clean_member_id(member):
    if member.startswith('serviceAccount:'):
        return member.replace('serviceAccount:', '').lower()
    elif member.startswith('user:'):
        return member.replace('user:', '').lower()
    elif member.startswith('group:'):
        return member.replace('group:', '').lower()
    return None

def build_privilege_escalation_edges(iam_data, service_accounts, secrets=None, debug=False):
    """Build privilege escalation edges with strict SA-to-SA and SA-to-Project separation"""
    edges = []
    edges_created = 0
    edges_skipped = 0
    conditioned_skipped = 0

    # Map service accounts by project for target resolution
    sa_by_project = {}
    for sa in service_accounts:
        project_id = sa.get('project', '').lower()
        sa_email = sa.get('email', '').lower()
        if project_id and sa_email:
            sa_by_project.setdefault(project_id, []).append(sa_email)

    # Permissions that operate on SERVICE ACCOUNTS - create SA->SA edges
    sa_scoped_permissions = {
        'iam.serviceAccounts.actAs': 'CanImpersonate',
        'iam.serviceAccounts.getAccessToken': 'CanGetAccessToken',
        'iam.serviceAccounts.signBlob': 'CanSignBlob',
        'iam.serviceAccounts.signJwt': 'CanSignJWT',
        'iam.serviceAccounts.setIamPolicy': 'CanModifyIamPolicy',
        'iam.serviceAccountKeys.create': 'CanCreateKeys'
    }
    
    secret_scoped_permissions = {# NEW DICTIONARY
    'secretmanager.versions.access': 'CanReadSecrets',
    'secretmanager.secrets.get': 'CanReadSecretMetadata'
    }

    # Permissions that operate on PROJECTS - create SA->Project edges
    project_scoped_permissions = {
        'compute.instances.create': 'CanCreateComputeInstance',
        'compute.instances.setServiceAccount': 'CanChangeInstanceServiceAccount',
        'cloudfunctions.functions.create': 'CanCreateCloudFunction',
        'resourcemanager.projects.setIamPolicy': 'CanModifyProjectPolicy',
        #'storage.buckets.setIamPolicy': 'CanModifyBucketPolicy'
        'storage.buckets.setIamPolicy': 'CanModifyBucketPoliciesInProject',
        'secretmanager.versions.access': 'CanReadSecretsInProject'# added for read secrets permissions
    }

    for iam_policy in iam_data:
        project_id = iam_policy.get('projectId', '').lower()
        # CAI-sourced SA-level policies target one specific SA; the
        # role-permission edges for them are built in build_iam_binding_edges
        # (exact target), so skip the project-wide fan-out here.
        if (iam_policy.get('resourceType') or '').lower() == 'serviceaccount':
            continue
        bindings = iam_policy.get('bindings', [])

        for binding in bindings:
            role = binding.get('role', '')
            members = binding.get('members', [])

            # Conditional grants must not create unconditional escalation edges
            if binding_condition(binding):
                conditioned_skipped += 1
                continue

            # Get permissions for this role
            escalation_perms = get_enhanced_permissions_for_role(role)

            for member in members:
                member_id = clean_member_id(member)
                if not member_id:
                    continue

                for perm in escalation_perms:
                    # SA-scoped permissions
                    if perm in sa_scoped_permissions:
                        edge_kind = sa_scoped_permissions[perm]
                        risk_level = get_escalation_risk_level(perm)
                        target_sas = sa_by_project.get(project_id, [])
                        for target_sa in target_sas:
                            if target_sa != member_id:  # No self-references
                                success = safe_add_edge(
                                    edges=edges,
                                    start_id=member_id,
                                    end_id=target_sa,
                                    kind=edge_kind,
                                    properties={
                                        "source": "privilege_escalation_analysis",
                                        "permission": perm,
                                        "role": role,
                                        "riskLevel": risk_level,
                                        "projectContext": project_id,
                                        "mitreTechnique": get_mitre_technique_for_permission(perm),
                                        "attackVector": get_attack_vector_for_permission(perm),
                                        "description": f"{member_id} can {perm.replace('.', ' ')} on service account {target_sa}"
                                    }
                                )
                                
                                if success:
                                    edges_created += 1
                                    if debug and edges_created <= 10:
                                        print(f"[DEBUG] ✅ SA-to-SA edge: {member_id} --[{edge_kind}]-> {target_sa}")
                                else:
                                    edges_skipped += 1

                    # Project-scoped permissions
                    elif perm in project_scoped_permissions:
                        edge_kind = project_scoped_permissions[perm]
                        risk_level = get_escalation_risk_level(perm)
                        
                        success = safe_add_edge(
                            edges=edges,
                            start_id=member_id,
                            end_id=project_id,
                            kind=edge_kind,
                            properties={
                                "source": "privilege_escalation_analysis",
                                "permission": perm,
                                "role": role,
                                "riskLevel": risk_level,
                                "mitreTechnique": get_mitre_technique_for_permission(perm),
                                "attackVector": get_attack_vector_for_permission(perm),
                                "description": f"{member_id} can escalate via {perm} in {project_id}"
                            }
                        )
                        
                        if success:
                            edges_created += 1
                            if debug and edges_created <= 10:
                                print(f"[DEBUG] ✅ SA-to-Project edge: {member_id} --[{edge_kind}]-> {project_id}")
                        else:
                            edges_skipped += 1
                    elif perm in secret_scoped_permissions:  # added for secrets permission
                        edge_kind = secret_scoped_permissions[perm]
                        risk_level = get_escalation_risk_level(perm)
                        project_secrets = [s for s in secrets if s.get('project', '').lower() == project_id]
                        for secret in project_secrets:
                            secret_name = secret.get('name', '').lower()
                            if secret_name:
                                success = safe_add_edge(
                                    edges=edges,
                                    start_id=member_id,
                                    end_id=secret_name,
                                    kind=edge_kind,
                                    properties={
                                        "source": "privilege_escalation_analysis",
                                        "permission": perm,
                                        "role": role,
                                        "riskLevel": risk_level,
                                        "projectContext": project_id,
                                        "attackVector": get_attack_vector_for_permission(perm),
                                        "description": f"{member_id} can access secret {secret_name} via {perm}"
                                    }
                                )
                                if success:
                                    edges_created += 1
                                else:
                                    edges_skipped += 1

    print(f"[+] Built {edges_created} privilege escalation edges")
    if edges_skipped > 0:
        print(f"[WARNING] Skipped {edges_skipped} invalid privilege escalation edges")
    if conditioned_skipped > 0:
        print(f"[~] Skipped {conditioned_skipped} conditional binding(s) in escalation analysis")
    return edges

# Additional helper functions for enhanced logging and debugging


