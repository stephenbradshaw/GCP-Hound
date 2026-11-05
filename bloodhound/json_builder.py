from bhopengraph.OpenGraph import OpenGraph
from bloodhound.opengraph_kinds import (
    namespace_edge_kind,
    namespace_node_kind,
    namespace_node_kinds,
)
from bhopengraph.Node import Node
from bhopengraph.Edge import Edge
from bhopengraph.Properties import Properties
from utils.id_utils import normalize_dataset_id, normalize_all_dataset_variations
import os
import json
import re

# ---- Google-managed SA and external user detection utilities ----

# Patterns for Google-managed / Google-owned robot service accounts. These
# SAs are not returned by serviceAccounts.list but do appear as IAM binding
# members, so they must be recognized and given nodes.
GOOGLE_MANAGED_SA_PATTERNS = [
    r'^service-\d+@gcp-sa-[a-z0-9\-]+\.iam\.gserviceaccount\.com$',
    r'^\d+@cloudservices\.gserviceaccount\.com$',
    r'^\d+@cloudbuild\.gserviceaccount\.com$',
    r'^service-\d+@compute-system\.iam\.gserviceaccount\.com$',
    r'^service-\d+@gcf-admin-robot\.iam\.gserviceaccount\.com$',
    r'^service-\d+@containerregistry\.iam\.gserviceaccount\.com$',
    r'^service-\d+@serverless-robot-prod\.iam\.gserviceaccount\.com$',
]

def is_google_managed_sa(email):
    """Detect Google-managed service accounts (gcp-sa-* and Google robot SAs)"""
    email = (email or '').strip().lower()
    return any(re.match(pattern, email) for pattern in GOOGLE_MANAGED_SA_PATTERNS)

def extract_service_name(sa_email):
    """Extract service name from Google-managed SA email"""
    if 'firebase' in sa_email.lower():
        return 'firebase'
    elif 'firestore' in sa_email.lower():
        return 'firestore'
    elif 'storage' in sa_email.lower():
        return 'storage'
    elif 'cloudrun' in sa_email.lower():
        return 'cloudrun'
    elif 'gcp-sa-' in sa_email:
        parts = sa_email.split('@')[1].split('.')[0].replace('gcp-sa-', '')
        return parts
    return 'unknown'

def is_gcp_service_account(email):
    """Check if email is a GCP service account (any kind)"""
    return email.endswith('.iam.gserviceaccount.com')

def is_external_user(email):
    """Any email that's NOT a GCP service account is external"""
    return not is_gcp_service_account(email)

def extract_project_from_iam_policy(iam_policy):
    """Extract project ID from IAM policy"""
    return iam_policy.get('projectId', '')

def get_user_roles_from_iam(user_email, iam_policy):
    """Get roles assigned to a specific user

    Conditional bindings are excluded so role-derived semantics only reflect
    unconditional grants (the roles list is descriptive only).
    """
    user_identifier = f"user:{user_email}"
    roles = []
    
    for binding in iam_policy.get('bindings', []):
        if user_identifier in binding.get('members', []):
            if binding.get('condition', {}).get('expression'):
                continue
            roles.append(binding.get('role', ''))
    
    return roles

def get_sa_roles_from_iam(sa_email, iam_data):
    """Extract actual roles assigned to service account from IAM data

    Conditional bindings are excluded: a role gated by an IAM condition does
    not imply unconditional privilege.
    """
    sa_roles = []
    
    if not iam_data:
        return sa_roles
    
    service_account_identifier = f"serviceAccount:{sa_email}"
    
    for iam_policy in iam_data:
        bindings = iam_policy.get('bindings', [])
        
        for binding in bindings:
            if binding.get('condition', {}).get('expression'):
                continue
            members = binding.get('members', [])
            role = binding.get('role', '')
            
            if service_account_identifier in members:
                sa_roles.append(role)
    
    return sa_roles

def normalize_variations(text, discovered_projects=None):
    """Generate all possible ID variations for fuzzy matching"""
    variations = set()
    variations.add(text)
    # Node ids are stored lowercase; include the lowercase form so a
    # mixed-case member still resolves to its node.
    variations.add(text.lower())
    
    var1 = text.replace('@', '-').replace('.', '-')
    var2 = text.replace('@', '_').replace('.', '_')
    var3 = text.replace('@', '').replace('.', '')
    
    variations.add(var1)
    variations.add(var2) 
    variations.add(var3)
    
    for var in list(variations):
        if '@' in text and 'gserviceaccount.com' in text:
            variations.add(f"gcp-sa-{var}")
            variations.add(f"user-{var}")

        if discovered_projects and '@' not in text:
            for project_name in discovered_projects:
                if project_name.lower() in text.lower():
                    variations.add(f"gcp-project-{var}")
                    variations.add(f"gcp-bucket-{var}")
                    break  
    
    return variations

def sanitize_property_value(value):
    """Ensure property values are schema compliant - keep arrays for node properties"""
    if value is None:
        return "Unknown"
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list):
        return value  # Keep arrays for node properties
    return str(value)

def sanitize_node_properties(props):
    """Build OpenGraph-safe node properties.

    BloodHound CE rejects reserved ``objectid`` inside ``properties`` (root
    ``id`` is the node identifier). Drop it and coerce remaining values.
    """
    if not props:
        return {}
    return {
        k: sanitize_property_value(v)
        for k, v in props.items()
        if k != "objectid"
    }

def opengraph_safe_id(node_id):
    """BloodHound does not fully support colons in OpenGraph object ids."""
    if node_id is None:
        return node_id
    return str(node_id).replace(":", "-")

def apply_opengraph_compliance(data):
    """Post-process exported graph JSON for BloodHound CE OpenGraph ingest."""
    if not isinstance(data, dict) or "graph" not in data:
        return data

    graph = data["graph"]
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []
    id_remap = {}

    for node in nodes:
        # Extra top-level fields are not part of the OpenGraph node schema.
        node.pop("label", None)

        props = node.get("properties")
        if isinstance(props, dict):
            props.pop("objectid", None)
            node["properties"] = props

        if isinstance(node.get("kinds"), list):
            node["kinds"] = namespace_node_kinds(node["kinds"])

        old_id = node.get("id")
        if isinstance(old_id, str) and ":" in old_id:
            new_id = opengraph_safe_id(old_id)
            id_remap[old_id] = new_id
            node["id"] = new_id

    for edge in edges:
        if "kind" in edge:
            edge["kind"] = namespace_edge_kind(edge["kind"])
        for end in ("start", "end"):
            ref = edge.get(end)
            if isinstance(ref, dict):
                value = ref.get("value")
                if value in id_remap:
                    ref["value"] = id_remap[value]
                elif isinstance(value, str) and ":" in value:
                    ref["value"] = opengraph_safe_id(value)
                ref["match_by"] = "id"
            elif isinstance(ref, str):
                if ref in id_remap:
                    edge[end] = id_remap[ref]
                elif ":" in ref:
                    edge[end] = opengraph_safe_id(ref)

        props = edge.get("properties")
        if isinstance(props, dict):
            props.pop("objectid", None)
            for prop_key, prop_value in list(props.items()):
                if isinstance(prop_value, list):
                    props[prop_key] = ", ".join(str(v) for v in prop_value) if prop_value else "None"

    return data

def fix_edge_name(edge_name):
    """Clean up verbose edge names to readable format"""
    edge_mapping = {
        "CanEscalateViaIamserviceaccountkeyscreate": "CanCreateKeys",
        "CanEscalateViaIamserviceaccountsactas": "CanImpersonate", 
        "CanEscalateViaIamserviceaccountsgetaccesstoken": "CanGetAccessToken",
        "CanEscalateViaIamserviceaccountssignblob": "CanSignBlob",
        "CanEscalateViaIamserviceaccountssignjwt": "CanSignJWT",
        "CanEscalateViaIamserviceaccounts": "CanImpersonate",
        "CanEscalateViaIamserviceaccountssetiampolicy": "CanModifyIamPolicy",
        "CanEscalateViaComputeinstancescreate": "CanCreateComputeInstance",
        "CanEscalateViaCloudfunctionscreate": "CanCreateCloudFunction",
        "CanEscalateViaResourcemanagerprojectssetiampolicy": "CanModifyProjectPolicy",
        #"CanEscalateViaStoragebucketssetiampolicy": "CanModifyBucketPolicy",
        "CanModifyBucketPoliciesInProject": "CanModifyBucketPoliciesInProject",
        "CanReadSecrets": "CanReadSecrets",# added to create read secrets edges
        "CanReadSecretsInProject": "CanReadSecretsInProject",# added to create read secrets edges
    }
    normalized = edge_mapping.get(edge_name, edge_name)
    return namespace_edge_kind(normalized)

def analyze_sa_actual_privileges_for_node(sa_email, iam_data):
    """Analyze service account privileges for node properties based on ACTUAL IAM roles"""
    if not iam_data:
        return {
            "privilegeLevel": "Unknown",
            "riskLevel": "Unknown",
            "roles": [],
            "reason": "No IAM data available",
            "escalationRisk": "Unknown",
            "remediationPriority": "Unknown"
        }
    
    sa_roles = get_sa_roles_from_iam(sa_email, iam_data)
    
    critical_roles = ['roles/owner', 'roles/iam.securityAdmin', 'roles/iam.organizationAdmin']
    high_roles = ['roles/editor', 'roles/compute.admin', 'roles/storage.admin', 'roles/iam.serviceAccountAdmin']
    medium_roles = ['roles/compute.instanceAdmin', 'roles/storage.objectAdmin', 'roles/bigquery.dataEditor']
    
    # Name-unmatched roles (typically custom roles) classified by permissions
    from collectors import role_resolver
    perm_class = None
    for role in [r for r in sa_roles
                 if r not in critical_roles + high_roles + medium_roles
                 and 'viewer' not in r.lower()]:
        classified = role_resolver.classify_role_by_permissions(
            role_resolver.permissions_for_role(role))
        if classified == 'CRITICAL':
            perm_class = 'CRITICAL'
            break
        if classified == 'HIGH' and perm_class != 'CRITICAL':
            perm_class = 'HIGH'
        elif classified == 'MEDIUM' and perm_class is None:
            perm_class = 'MEDIUM'

    if perm_class == 'CRITICAL' or any(role in critical_roles for role in sa_roles):
        return {
            "privilegeLevel": "CRITICAL",
            "riskLevel": "CRITICAL",
            "roles": sa_roles,
            "reason": f"Has critical roles: {[r for r in sa_roles if r in critical_roles]}",
            "escalationRisk": "CRITICAL",
            "remediationPriority": "CRITICAL"
        }
    elif perm_class == 'HIGH' or any(role in high_roles for role in sa_roles):
        return {
            "privilegeLevel": "HIGH",
            "riskLevel": "HIGH", 
            "roles": sa_roles,
            "reason": f"Has admin roles: {[r for r in sa_roles if r in high_roles]}",
            "escalationRisk": "HIGH",
            "remediationPriority": "HIGH"
        }
    elif perm_class == 'MEDIUM' or any(role in medium_roles for role in sa_roles):
        return {
            "privilegeLevel": "MEDIUM",
            "riskLevel": "MEDIUM",
            "roles": sa_roles,
            "reason": f"Has elevated roles: {[r for r in sa_roles if r in medium_roles]}",
            "escalationRisk": "MEDIUM", 
            "remediationPriority": "MEDIUM"
        }
    elif any('viewer' in role.lower() for role in sa_roles):
        return {
            "privilegeLevel": "LOW",
            "riskLevel": "LOW",
            "roles": sa_roles,
            "reason": "Read-only access",
            "escalationRisk": "LOW",
            "remediationPriority": "LOW"
        }
    else:
        return {
            "privilegeLevel": "LIMITED",
            "riskLevel": "LOW",
            "roles": sa_roles,
            "reason": f"Limited/custom roles: {sa_roles}" if sa_roles else "No roles found",
            "escalationRisk": "LOW",
            "remediationPriority": "LOW"
        }

def filter_edges_for_bloodhound(edges):
    """Remove duplicate and self-referencing edges"""
    seen_edges = set()
    clean_edges = []
    
    for edge in edges:
        start = edge.get('start', {}).get('value', '').lower()
        end = edge.get('end', {}).get('value', '').lower()
        kind = edge.get('kind', '')
        
        # Skip self-referencing edges
        if start == end:
            continue
            
        # Skip duplicate edges
        edge_key = f'{start}|{kind}|{end}'
        if edge_key in seen_edges:
            continue
            
        seen_edges.add(edge_key)
        clean_edges.append(edge)
    
    print(f"[+] Edge Filtering: {len(edges)} → {len(clean_edges)} edges (removed {len(edges) - len(clean_edges)} duplicates/self-refs)")
    return clean_edges

def validate_and_clean_graph_data(nodes, edges, args=None):
    """Validate nodes and edges before OpenGraph processing to prevent empty ID errors"""
    print("[DEBUG] Starting graph validation...")
    
    # Count original data
    original_edge_count = len(edges)
    
    # Validate edges - ensure start and end values exist and are non-empty
    valid_edges = []
    skipped_edges = 0
    
    for edge in edges:
        start_id = edge.get('start', {}).get('value')
        end_id = edge.get('end', {}).get('value')
        
        # Check both IDs exist and are non-empty strings
        if (start_id and end_id and 
            str(start_id).strip() and str(end_id).strip()):
            valid_edges.append(edge)
        else:
            skipped_edges += 1
            if args and hasattr(args, 'debug') and args.debug:
                print(f"[DEBUG] Skipped edge: start='{start_id}', end='{end_id}'")
    
    # Log results
    if skipped_edges > 0:
        print(f"[WARNING] Skipped {skipped_edges} edges with empty/invalid node references")
    
    print(f"[+] Graph validation: {len(valid_edges)}/{original_edge_count} valid edges")
    return valid_edges

def create_logging_access_edges(log_sinks, current_user, service_accounts, iam_data=None):
    """Create edges for log stream access - arrays converted to strings for edge properties"""
    edges = []
    
    for sink in log_sinks:
        # Check if this is actually a log stream
        is_stream = sink.get('type') == 'log_stream' or sink.get('isLogStream') is True
        if not is_stream:
            continue

        # User -> log stream (only if user exists)
        if current_user and current_user != "unknown":
            user_edge = {
                'start': {'value': current_user},
                'end': {'value': sink.get('objectId')},
                'kind': 'CanAccessLogStream',
                'properties': {
                    'logType': sink.get('logType', 'application'),
                    'riskLevel': sink.get('riskLevel', 'MEDIUM'),
                    'sensitivityLevel': sink.get('sensitivityLevel', 'LOW'),
                    'description': f"Can access {sink.get('logType')} logs: {sink.get('displayName')}",
                    'escalationMethod': 'log_stream_access',
                    'requiredPermissions': sink.get('accessRequired', []),
                    'accessRequired': ", ".join(sink.get('accessRequired', [])) if sink.get('accessRequired') else "None"
                }
            }
            edges.append(user_edge)

        # SA -> sensitive streams ONLY if SA has actual logging permissions
        if sink.get('sensitivityLevel') in ['CRITICAL', 'HIGH']:
            for sa in service_accounts:
                sa_email = sa.get('email', '')
                if not sa_email:
                    continue
                
                # Check if SA actually has logging permissions
                sa_roles = get_sa_roles_from_iam(sa_email, iam_data) if iam_data else []
                
                # Only SAs with these roles can access logging
                logging_roles = [
                    'roles/owner', 'roles/editor', 'roles/logging.viewer', 
                    'roles/logging.privateLogViewer', 'roles/logging.admin',
                    'roles/logging.logWriter'
                ]
                
                has_logging_access = any(role in logging_roles for role in sa_roles)
                
                # ONLY create edge if SA has actual logging permissions
                if has_logging_access:
                    granted_roles = [r for r in sa_roles if r in logging_roles]
                    
                    sa_edge = {
                        'start': {'value': sa_email},
                        'end': {'value': sink.get('objectId')},
                        'kind': 'CanViewSensitiveLogs',
                        'properties': {
                            'logType': sink.get('logType'),
                            'riskLevel': 'HIGH',
                            'sensitivityLevel': sink.get('sensitivityLevel'),
                            'description': f"SA with logging permissions can access sensitive {sink.get('logType')} logs",
                            'escalationMethod': 'privileged_log_access',
                            'grantedViaRoles': granted_roles
                        }
                    }
                    edges.append(sa_edge)
    
    return edges

def export_bloodhound_json(computers, users, projects, groups, service_accounts, buckets, secrets, edges, creds=None, iam_data=None, log_sinks=None, log_buckets=None, log_metrics=None, bigquery_datasets=None, folders=None, instances=None, wi_pools=None, api_keys=None, networking=None, kms_keys=None):
    """Export comprehensive GCP data to BloodHound JSON format using ONLY real enumerated data"""
    graph = OpenGraph()  # NO source_kind parameter
    
    print(f"[*] Phase 5: Building Complete Attack Path Graph with Real Data Only")
    print(f"[DEBUG] Starting export with {len(service_accounts)} SAs, {len(projects)} projects, {len(buckets)} buckets, {len(edges)} edges")

    # Handle all parameters with defaults
    log_sinks = log_sinks or []
    log_buckets = log_buckets or []
    log_metrics = log_metrics or []
    bigquery_datasets = bigquery_datasets or []
    folders = folders or []
    instances = instances or []
    wi_pools = wi_pools or []
    api_keys = api_keys or []
    networking = networking or ([], [], [])
    networks, subnets, firewalls = networking
    kms_keys = kms_keys or []

    if folders:
        print(f"[DEBUG] Including {len(folders)} folders")

    if instances:
        print(f"[DEBUG] Including {len(instances)} compute instances")
    
    if log_sinks or log_buckets or log_metrics:
        total_logging = len(log_sinks) + len(log_buckets) + len(log_metrics)
        print(f"[DEBUG] Including {total_logging} logging resources ({len(log_sinks)} sinks, {len(log_buckets)} buckets, {len(log_metrics)} metrics)")

    if bigquery_datasets:
        print(f"[DEBUG] Including {len(bigquery_datasets)} BigQuery datasets")

    # Extract project names from enumerated data
    discovered_project_names = [p.get('projectId', '').lower() for p in projects if p.get('projectId')]
    
    # Build node mapping
    node_id_map = {}

    # ---- NEW: Google-managed SAs from IAM bindings ----
    discovered_google_managed_sas = set()
    if iam_data:
        for policy in iam_data:
            for binding in policy.get('bindings', []):
                for member in binding.get('members', []):
                    if member.startswith('serviceAccount:'):
                        sa_email = member.replace('serviceAccount:', '').lower()
                        if is_google_managed_sa(sa_email):
                            discovered_google_managed_sas.add(sa_email)

    # Create nodes for Google-managed SAs (only if not already in service_accounts list)
    existing_sa_emails = [sa.get('email', '').lower() for sa in service_accounts]
    for gmsa_email in discovered_google_managed_sas:
        if gmsa_email.lower() not in existing_sa_emails:
            service_name = extract_service_name(gmsa_email)
            
            clean_properties = {
                "name": gmsa_email,
                "displayname": f"Google {service_name.title()} Service Account",
                "email": gmsa_email,
                "platform": "GCP",
                "description": f"Google-managed service account for {service_name}",
                "gcpResourceType": "Google Managed Service Account",
                "serviceType": service_name,
                "managedBy": "Google"
            }
            
            sanitized_properties = sanitize_node_properties(clean_properties)
            
            # FIXED: Only 2 kinds maximum
            gmsa_node = Node(
                id=gmsa_email,
                kinds=["GCP_GoogleManagedSA", "GCP_ServiceAccount"],
                properties=Properties(**sanitized_properties)
            )
            graph.add_node(gmsa_node)
            
            for variation in normalize_variations(gmsa_email, discovered_project_names):
                node_id_map[variation] = gmsa_email

    # ---- NEW: Users from IAM bindings ----
    discovered_users = set()
    if iam_data:
        for policy in iam_data:
            for binding in policy.get('bindings', []):
                for member in binding.get('members', []):
                    if member.startswith('user:'):
                        user_email = member.replace('user:', '').lower()
                        discovered_users.add(user_email)

    # Create nodes for discovered users (avoid duplicating current user)
    for user_email in discovered_users:
        if user_email not in graph.nodes:  # Avoid duplicating current user
            domain = user_email.split('@')[1] if '@' in user_email else 'unknown'
            username = user_email.split('@')[0] if '@' in user_email else user_email
            user_type = "External" if is_external_user(user_email) else "ServiceAccount"
            
            clean_properties = {
                "name": user_email,
                "displayname": user_email,
                "email": user_email,
                "username": username,
                "domain": domain,
                "platform": "GCP",
                "description": f"GCP User: {user_email}",
                "gcpResourceType": "User Account",
                "userType": user_type,
                "authMethod": "User"
            }
            
            sanitized_properties = sanitize_node_properties(clean_properties)
            
            # FIXED: Only 2 kinds maximum
            user_node = Node(
                id=user_email,
                kinds=["GCP_User", "GCP_Resource"],
                properties=Properties(**sanitized_properties)
            )
            graph.add_node(user_node)
            
            for variation in normalize_variations(user_email, discovered_project_names):
                node_id_map[variation] = user_email

    # Add service accounts using ONLY real enumerated data
    for sa in service_accounts:
        sa_email = sa.get('email', '').lower()
        
        # VALIDATION: Skip if no valid email
        if not sa_email or not sa_email.strip():
            print(f"[WARNING] Skipping service account with invalid email: {sa}")
            continue
            
        sa_name = sa.get('displayName', sa.get('name', sa_email))
        
        # Dynamic privilege level based on actual IAM roles
        actual_privilege_level = analyze_sa_actual_privileges_for_node(sa_email, iam_data)
        
        # Use ONLY real properties from enumerated data
        clean_properties = {
            "name": sa_email,
            "displayname": sa_name,
            "email": sa_email,
            "short_name": sa_email.split('@')[0] if '@' in sa_email else sa_email,
            "platform": "GCP",
            "project": sa.get('project', 'Unknown'),
            "description": f"GCP Service Account: {sa_name}",
            
            # Real GCP-specific metadata from API
            "gcpResourceType": "Service Account",
            "gcpProjectNumber": sa.get('projectNumber', 'Unknown'),
            "gcpServiceAccountId": sa.get('uniqueId', 'Unknown'),
            "gcpKeyCount": sa.get('keyCount', 0),
            "gcpDisabled": sa.get('disabled', False),
            
            # Dynamic security analysis based on actual IAM data
            "riskLevel": actual_privilege_level["riskLevel"],
            "privilegeLevel": actual_privilege_level["privilegeLevel"],
            "actualRoles": actual_privilege_level["roles"],
            "privilegeReason": actual_privilege_level["reason"],
            "hasExternalKeys": sa.get('keyCount', 0) > 0,
            "complianceStatus": "NON_COMPLIANT" if sa.get('keyCount', 0) > 2 else "COMPLIANT" if sa.get('keyCount', 0) >= 0 else "Unknown",
            "escalationRisk": actual_privilege_level["escalationRisk"],
            "remediationPriority": actual_privilege_level["remediationPriority"],
            
            # Real timestamps if available
            "creationTime": sa.get('creationTime', 'Unknown'),
            "lastKeyRotation": sa.get('lastKeyRotation', 'Unknown')
        }
        
        sanitized_properties = sanitize_node_properties(clean_properties)
        
        # FIXED: Only 2 kinds maximum
        sa_node = Node(
            id=sa_email,
            kinds=["GCP_ServiceAccount", "GCP_Resource"],
            properties=Properties(**sanitized_properties)
        )
        graph.add_node(sa_node)
        
        for variation in normalize_variations(sa_email, discovered_project_names):
            node_id_map[variation] = sa_email

    # ---- NEW: Principal nodes for the remaining IAM binding members ----
    # Every principal that appears in a collected binding gets a node
    # (lowercase id), so edges that start or end at it are kept. Only
    # principals present in the collected bindings/edges are materialized.
    if iam_data:
        for policy in iam_data:
            for binding in policy.get('bindings', []):
                for member in binding.get('members', []):
                    member = (member or '').strip()
                    if not member:
                        continue

                    if member.startswith('serviceAccount:'):
                        sa_email = member.replace('serviceAccount:', '').lower()
                        if (not sa_email or sa_email in graph.nodes
                                or sa_email in existing_sa_emails):
                            continue
                        if is_google_managed_sa(sa_email):
                            kinds = ["GCP_GoogleManagedSA", "GCP_ServiceAccount"]
                            description = f"Google-managed service account: {sa_email}"
                            resource_type = "Google Managed Service Account"
                        else:
                            kinds = ["GCP_ServiceAccount", "GCP_Resource"]
                            description = f"GCP Service Account: {sa_email}"
                            resource_type = "Service Account"
                        clean_properties = {
                            "name": sa_email,
                            "displayname": sa_email,
                            "email": sa_email,
                            "platform": "GCP",
                            "description": description,
                            "gcpResourceType": resource_type,
                            "source": "iam_binding"
                        }
                        principal_node = Node(
                            id=sa_email,
                            kinds=kinds,
                            properties=Properties(**sanitize_node_properties(clean_properties))
                        )
                        graph.add_node(principal_node)
                        for variation in normalize_variations(sa_email, discovered_project_names):
                            node_id_map[variation] = sa_email

                    elif member.startswith('group:'):
                        group_email = member.replace('group:', '').lower()
                        if not group_email or group_email in graph.nodes:
                            continue
                        clean_properties = {
                            "name": group_email,
                            "displayname": group_email,
                            "email": group_email,
                            "platform": "GCP",
                            "description": f"GCP Group: {group_email}",
                            "gcpResourceType": "Group",
                            "source": "iam_binding"
                        }
                        principal_node = Node(
                            id=group_email,
                            kinds=["GCP_Group", "GCP_Resource"],
                            properties=Properties(**sanitize_node_properties(clean_properties))
                        )
                        graph.add_node(principal_node)
                        for variation in normalize_variations(group_email, discovered_project_names):
                            node_id_map[variation] = group_email

                    elif member.startswith('domain:'):
                        domain_id = member.replace('domain:', '').lower()
                        if not domain_id or domain_id in graph.nodes:
                            continue
                        clean_properties = {
                            "name": domain_id,
                            "displayname": domain_id,
                            "platform": "GCP",
                            "description": f"GCP Domain: {domain_id}",
                            "gcpResourceType": "Domain",
                            "source": "iam_binding"
                        }
                        principal_node = Node(
                            id=domain_id,
                            kinds=["GCP_Principal", "GCP_Resource"],
                            properties=Properties(**sanitize_node_properties(clean_properties))
                        )
                        graph.add_node(principal_node)
                        for variation in normalize_variations(domain_id, discovered_project_names):
                            node_id_map[variation] = domain_id

                    elif member.lower() in ('allusers', 'allauthenticatedusers'):
                        principal_id = member.lower()
                        if principal_id in graph.nodes:
                            continue
                        clean_properties = {
                            "name": principal_id,
                            "displayname": member,
                            "platform": "GCP",
                            "description": f"GCP Public Principal: {member}",
                            "gcpResourceType": "Public Principal",
                            "source": "iam_binding"
                        }
                        principal_node = Node(
                            id=principal_id,
                            kinds=["GCP_Principal", "GCP_Resource"],
                            properties=Properties(**sanitize_node_properties(clean_properties))
                        )
                        graph.add_node(principal_node)
                        for variation in normalize_variations(principal_id, discovered_project_names):
                            node_id_map[variation] = principal_id

    # Add projects using ONLY real enumerated data
    for project in projects:
        project_id = project.get('projectId', '').lower()
        
        # VALIDATION: Skip if no valid project ID
        if not project_id or not project_id.strip():
            print(f"[WARNING] Skipping project with invalid ID: {project}")
            continue
            
        project_name = project.get('name', project_id)
        
        clean_properties = {
            "name": project_id,
            "displayname": project_name,
            "projectId": project_id,
            "platform": "GCP",
            "description": f"GCP Project: {project_name}",
            
            # Real GCP-specific metadata from API
            "gcpResourceType": "Project",
            "gcpProjectNumber": project.get('projectNumber', 'Unknown'),
            "gcpLifecycleState": project.get('lifecycleState', 'Unknown'),
            "gcpCreationTime": project.get('createTime', 'Unknown'),
            "projectOwner": project.get('owner', 'Unknown'),
            
            # Real billing info if available, otherwise Unknown
            "billingEnabled": project.get('billingEnabled', 'Unknown'),
            
            # Calculated security analysis
            "riskLevel": "MEDIUM",
            "privilegeLevel": "HIGH", 
            "escalationTarget": "Yes",
            "containsSensitiveData": "Unknown",
            "remediationPriority": "MEDIUM"
        }
        
        sanitized_properties = sanitize_node_properties(clean_properties)
        
        # FIXED: Only 2 kinds maximum
        proj_node = Node(
            id=project_id,
            kinds=["GCP_Project", "GCP_Resource"],
            properties=Properties(**sanitized_properties)
        )
        graph.add_node(proj_node)
        
        for variation in normalize_variations(project_id, discovered_project_names):
            node_id_map[variation] = project_id

    # Add buckets using ONLY real enumerated data
    for bucket in buckets:
        bucket_name = bucket.get('name', '').lower()
        
        # VALIDATION: Skip if no valid bucket name
        if not bucket_name or not bucket_name.strip():
            print(f"[WARNING] Skipping bucket with invalid name: {bucket}")
            continue
        
        clean_properties = {
            "name": bucket_name,
            "displayname": bucket_name,
            "platform": "GCP",
            "project": bucket.get('project', 'Unknown'),
            "description": f"GCP Storage Bucket: {bucket_name}",
            
            # Real GCP-specific metadata from API
            "gcpResourceType": "Storage Bucket",
            "gcpStorageClass": bucket.get('storageClass', 'Unknown'),
            "gcpEncryption": bucket.get('encryption', 'Unknown'),
            "gcpVersioning": bucket.get('versioning', False),
            "location": bucket.get('location', 'Unknown'),
            "timeCreated": bucket.get('timeCreated', 'Unknown'),
            "updated": bucket.get('updated', 'Unknown'),
            
            # Real security analysis based on actual bucket configuration
            "riskLevel": bucket.get('riskLevel', 'Unknown'),
            "publicAccess": bucket.get('publicAccess', 'Unknown'),
            "publicReadAccess": bucket.get('publicAccess') == 'allUsers' if bucket.get('publicAccess') != 'Unknown' else 'Unknown',
            "dataClassification": bucket.get('dataClassification', 'Unknown'),
            "encryptionStatus": bucket.get('encryption', 'Unknown'),
            "accessLogging": bucket.get('accessLogging', 'Unknown'),
            "remediationPriority": bucket.get('remediationPriority', 'Unknown')
        }
        
        sanitized_properties = sanitize_node_properties(clean_properties)
        
        # FIXED: Only 2 kinds maximum
        bucket_node = Node(
            id=bucket_name,
            kinds=["GCP_Bucket", "GCP_Resource"],
            properties=Properties(**sanitized_properties)
        )
        graph.add_node(bucket_node)
        
        for variation in normalize_variations(bucket_name, discovered_project_names):
            node_id_map[variation] = bucket_name

    # BigQuery datasets with canonical ID format using normalize_dataset_id
    for dataset in bigquery_datasets:
        dataset_id = dataset.get('dataset_id', '')
        project_id = dataset.get('project', '').lower()

        # VALIDATION: Skip if no valid dataset or project info
        if not project_id or not dataset_id:
            print(f"[WARNING] Skipping dataset with missing project/dataset info: {dataset}")
            continue

        canonical_dataset_id = normalize_dataset_id(dataset_id, project_id)
        
        clean_properties = {
            "name": dataset_id,
            "displayname": dataset.get('friendly_name', dataset_id),
            "datasetId": dataset_id,
            "platform": "GCP",
            "project": project_id,
            "description": f"BigQuery Dataset: {dataset_id}",
            "gcpResourceType": "BigQuery Dataset",
            "gcpDatasetType": "BigQuery",
            "gcpTableCount": dataset.get('table_count', 'Unknown'),
            "location": dataset.get('location', 'Unknown'),
            "creationTime": dataset.get('created', 'Unknown'),
            "lastModifiedTime": dataset.get('modified', 'Unknown'),
            "fullDatasetId": dataset.get('full_dataset_id', f"{project_id}:{dataset_id}"),
            "riskLevel": dataset.get('riskLevel', 'Unknown'),
            "gcpEncryption": dataset.get('encryption', 'Unknown'),
            "gcpDataClassification": dataset.get('dataClassification', 'Unknown'),
            "dataRetentionDays": dataset.get('dataRetentionDays', 'Unknown'),
            "containsPII": dataset.get('containsPII', 'Unknown'),
            "accessLogging": dataset.get('accessLogging', 'Unknown'),
            "remediationPriority": dataset.get('remediationPriority', 'Unknown')
        }

        sanitized_properties = sanitize_node_properties(clean_properties)
            
        # Create node with canonical ID - FIXED: Only 2 kinds maximum
        bq_node = Node(
            id=canonical_dataset_id,
            kinds=["GCP_Dataset", "GCP_Resource"],
            properties=Properties(**sanitized_properties)
        )
        graph.add_node(bq_node)
        
        # Comprehensive ID mapping using normalize_all_dataset_variations
        for variation in normalize_all_dataset_variations(dataset_id, project_id):
            node_id_map[variation] = canonical_dataset_id
        node_id_map[canonical_dataset_id] = canonical_dataset_id

    # Add logging resource nodes using ONLY real enumerated data
    for sink in log_sinks:
        sink_id = sink.get('objectId', sink.get('name', ''))
        
        # VALIDATION: Skip if no valid sink ID
        if not sink_id or not sink_id.strip():
            print(f"[WARNING] Skipping log sink with invalid ID: {sink}")
            continue
        
        # Determine if this is a log stream but keep GCPLogSink kind for UI compatibility
        is_stream = sink.get('type') == 'log_stream' or sink.get('isLogStream') is True
        
        clean_properties = {
            "name": sink.get('name', 'Unknown'),
            "displayname": sink.get('displayName', sink.get('name', 'Unknown')),
            "platform": "GCP",
            "project": sink.get('project', 'Unknown'),
            "description": f"GCP {'Log Stream' if is_stream else 'Log Sink'}: {sink.get('name', 'Unknown')}",
            
            # Real GCP-specific metadata from API
            "gcpResourceType": "Log Sink",  # Keep as Log Sink for UI
            "destination": sink.get('destination', 'Unknown'),
            "filter": sink.get('filter', 'Unknown'),
            "writerIdentity": sink.get('writerIdentity', 'Unknown'),
            "includeChildren": sink.get('includeChildren', 'Unknown'),
            "disabled": sink.get('disabled', 'Unknown'),
            "createTime": sink.get('createTime', 'Unknown'),
            "updateTime": sink.get('updateTime', 'Unknown'),
            
            # Stream-specific properties
            "isLogStream": is_stream,  # Flag to identify streams
            "logType": sink.get('logType', 'Unknown'),
            "sensitivityLevel": sink.get('sensitivityLevel', 'Unknown'),
            "accessRequired": sink.get('accessRequired', []),
            
            # Real security analysis
            "riskLevel": sink.get('riskLevel', 'Unknown'),
            "escalationTarget": "Yes" if sink.get('writerIdentity') and sink.get('writerIdentity') != 'Unknown' else "Unknown",
            "remediationPriority": sink.get('remediationPriority', 'Unknown')
        }
        
        sanitized_properties = sanitize_node_properties(clean_properties)
        
        # Use GCPLogSink kind for UI compatibility - FIXED: Only 2 kinds maximum
        sink_node = Node(
            id=sink_id,
            kinds=["GCP_LogSink", "GCP_Resource"],
            properties=Properties(**sanitized_properties)
        )
        graph.add_node(sink_node)
        
        for variation in normalize_variations(sink_id, discovered_project_names):
            node_id_map[variation] = sink_id

    # Add other logging resources (log buckets, metrics)
    for bucket in log_buckets:
        bucket_id = bucket.get('objectId', bucket.get('name', ''))
        
        # VALIDATION: Skip if no valid bucket ID
        if not bucket_id or not bucket_id.strip():
            print(f"[WARNING] Skipping log bucket with invalid ID: {bucket}")
            continue
        
        clean_properties = {
            "name": bucket.get('name', 'Unknown'),
            "displayname": bucket.get('displayName', bucket.get('name', 'Unknown')),
            "platform": "GCP",
            "project": bucket.get('project', 'Unknown'),
            "description": f"GCP Log Bucket: {bucket.get('name', 'Unknown')}",
            
            # Real GCP-specific metadata from API
            "gcpResourceType": "Log Bucket",
            "location": bucket.get('location', 'Unknown'),
            "retentionDays": bucket.get('retentionDays', 'Unknown'),
            "locked": bucket.get('locked', 'Unknown'),
            "lifecycleState": bucket.get('lifecycleState', 'Unknown'),
            "createTime": bucket.get('createTime', 'Unknown'),
            "updateTime": bucket.get('updateTime', 'Unknown'),
            
            # Real security analysis
            "riskLevel": bucket.get('riskLevel', 'Unknown'),
            "dataRetention": f"{bucket.get('retentionDays', 'Unknown')} days" if bucket.get('retentionDays') != 'Unknown' else 'Unknown',
            "complianceStatus": "COMPLIANT" if bucket.get('locked') is True else "NON_COMPLIANT" if bucket.get('locked') is False else "Unknown",
            "remediationPriority": bucket.get('remediationPriority', 'Unknown')
        }
        
        sanitized_properties = sanitize_node_properties(clean_properties)
        
        # FIXED: Only 2 kinds maximum
        log_bucket_node = Node(
            id=bucket_id,
            kinds=["GCP_LogBucket", "GCP_Resource"],
            properties=Properties(**sanitized_properties)
        )
        graph.add_node(log_bucket_node)
        
        for variation in normalize_variations(bucket_id, discovered_project_names):
            node_id_map[variation] = bucket_id

    for metric in log_metrics:
        metric_id = metric.get('objectId', metric.get('name', ''))
        
        # VALIDATION: Skip if no valid metric ID
        if not metric_id or not metric_id.strip():
            print(f"[WARNING] Skipping log metric with invalid ID: {metric}")
            continue
        
        clean_properties = {
            "name": metric.get('name', 'Unknown'),
            "displayname": metric.get('displayName', metric.get('name', 'Unknown')),
            "platform": "GCP",
            "project": metric.get('project', 'Unknown'),
            "description": f"GCP Log Metric: {metric.get('name', 'Unknown')}",
            
            # Real GCP-specific metadata from API
            "gcpResourceType": "Log Metric",
            "filter": metric.get('filter', 'Unknown'),
            "disabled": metric.get('disabled', 'Unknown'),
            "createTime": metric.get('createTime', 'Unknown'),
            "updateTime": metric.get('updateTime', 'Unknown'),
            "metricDescriptor": str(metric.get('metricDescriptor', 'Unknown')),
            
            # Real security analysis
            "riskLevel": metric.get('riskLevel', 'Unknown'),
            "monitoringSensitive": "Yes" if metric.get('filter') and any(sensitive in metric.get('filter', '').lower() 
                                               for sensitive in ['audit', 'auth', 'admin']) else "Unknown",
            "remediationPriority": metric.get('remediationPriority', 'Unknown')
        }
        
        sanitized_properties = sanitize_node_properties(clean_properties)
        
        # FIXED: Only 2 kinds maximum
        metric_node = Node(
            id=metric_id,
            kinds=["GCP_LogMetric", "GCP_Resource"],
            properties=Properties(**sanitized_properties)
        )
        graph.add_node(metric_node)
        
        for variation in normalize_variations(metric_id, discovered_project_names):
            node_id_map[variation] = metric_id

    # Add folder nodes using ONLY real enumerated data, BEFORE any folder edge
    # is exported: an edge whose folder id is missing is a bug, not a skip.
    for folder in folders:
        folder_name = folder.get('name') or f"folders/{folder.get('id', '')}"
        
        # VALIDATION: Skip if no valid folder id
        if not folder_name or not folder_name.strip() or not folder_name.startswith('folders/'):
            print(f"[WARNING] Skipping folder with invalid id: {folder}")
            continue
        
        clean_properties = {
            "name": folder_name,
            "displayname": folder.get('displayName', folder_name),
            "platform": "GCP",
            "description": f"GCP Folder: {folder.get('displayName', folder_name)}",
            
            # Real GCP-specific metadata from API
            "gcpResourceType": "Folder",
            "parent": folder.get('parent', 'Unknown'),
            "lifecycleState": folder.get('lifecycleState', 'Unknown'),
            "parentType": folder.get('parentType', 'unknown'),
            
            # Real security analysis
            "riskLevel": folder.get('riskLevel', 'Unknown'),
            "remediationPriority": "Unknown"
        }
        
        sanitized_properties = sanitize_node_properties(clean_properties)
        
        folder_node = Node(
            id=folder_name,
            kinds=["GCP_Folder", "GCP_Resource"],
            properties=Properties(**sanitized_properties)
        )
        graph.add_node(folder_node)
        
        for variation in normalize_variations(folder_name, discovered_project_names):
            node_id_map[variation] = folder_name

        # Ensure the folder's parent has a node so containment edges resolve
        parent = folder.get('parent', '')
        if parent and parent not in graph.nodes:
            if parent.startswith('folders/'):
                parent_properties = {
                    "name": parent,
                    "displayname": parent,
                    "platform": "GCP",
                    "description": f"GCP Folder: {parent}",
                    "gcpResourceType": "Folder",
                    "riskLevel": "Unknown"
                }
                parent_kinds = ["GCP_Folder", "GCP_Resource"]
            elif parent.startswith('organizations/'):
                parent_properties = {
                    "name": parent,
                    "displayname": parent,
                    "platform": "GCP",
                    "description": f"GCP Organization: {parent}",
                    "gcpResourceType": "Organization",
                    "riskLevel": "Unknown"
                }
                parent_kinds = ["GCP_Organization", "GCP_Resource"]
            else:
                continue
            
            parent_node = Node(
                id=parent,
                kinds=parent_kinds,
                properties=Properties(**sanitize_node_properties(parent_properties))
            )
            graph.add_node(parent_node)
            
            for variation in normalize_variations(parent, discovered_project_names):
                node_id_map[variation] = parent

    # Add compute instance nodes using ONLY real enumerated data, using the
    # same ids the compute edges use (gcp-compute-instance-<project>-<zone>-<name>)
    for instance in instances:
        instance_name = instance.get('name', '')
        project_id = (instance.get('project', '') or '').lower()
        zone = instance.get('zone', '')
        if not instance_name or not project_id:
            print(f"[WARNING] Skipping compute instance with missing name/project: {instance}")
            continue
        
        instance_id = f"gcp-compute-instance-{project_id}-{zone}-{instance_name}"
        
        clean_properties = {
            "name": instance_name,
            "displayname": instance_name,
            "platform": "GCP",
            "description": f"GCP Compute Instance: {instance_name}",
            
            # Real GCP-specific metadata from API
            "gcpResourceType": "Compute Instance",
            "project": project_id,
            "zone": zone,
            "machineType": instance.get('machineType', 'Unknown'),
            "status": instance.get('status', 'Unknown'),
            "region": zone.rsplit('-', 1)[0] if zone and '-' in zone else 'Unknown',
            
            # Real security analysis
            "riskLevel": instance.get('riskLevel', 'Unknown'),
            "remediationPriority": "Unknown"
        }
        
        sanitized_properties = sanitize_node_properties(clean_properties)
        
        instance_node = Node(
            id=instance_id,
            kinds=["GCP_Instance", "GCP_Resource"],
            properties=Properties(**sanitized_properties)
        )
        graph.add_node(instance_node)
        
        for variation in normalize_variations(instance_id, discovered_project_names):
            node_id_map[variation] = instance_id

    # Directory users (Admin SDK). BloodHound search indexes name/displayname;
    # edge-only stubs without those properties are not findable in the UI.
    for user in users or []:
        user_email = (user.get('email') or user.get('primaryEmail') or '').strip().lower()
        if not user_email or '@' not in user_email:
            continue
        display = (user.get('name') or user.get('fullName') or user_email)
        if isinstance(display, dict):
            display = display.get('fullName') or user_email
        clean_properties = {
            "name": user_email,
            "displayname": display,
            "email": user_email,
            "username": user_email.split('@')[0],
            "domain": user_email.split('@')[1] if '@' in user_email else 'unknown',
            "platform": "GCP",
            "description": f"GCP User: {display}",
            "gcpResourceType": "User Account",
            "riskLevel": user.get('riskLevel', 'Unknown'),
            "isAdmin": user.get('isAdmin', False),
            "isDelegatedAdmin": user.get('isDelegatedAdmin', False),
            "suspended": user.get('suspended', False),
            "source": "directory",
        }
        if user_email in graph.nodes:
            for variation in normalize_variations(user_email, discovered_project_names):
                node_id_map[variation] = user_email
            continue

        graph.add_node(Node(
            id=user_email,
            kinds=["GCP_User", "GCP_Resource"],
            properties=Properties(**sanitize_node_properties(clean_properties)),
        ))
        for variation in normalize_variations(user_email, discovered_project_names):
            node_id_map[variation] = user_email

    # Add group nodes using ONLY real enumerated data (groups were collected
    # via the Admin SDK but never exported as nodes; edges reference the raw
    # group email)
    for group in groups:
        group_email = (group.get('email', '') or '').strip().lower()
        if not group_email or group_email in graph.nodes:
            continue
        
        clean_properties = {
            "name": group_email,
            "displayname": group.get('name', group_email),
            "email": group_email,
            "platform": "GCP",
            "description": f"GCP Group: {group.get('name', group_email)}",
            "gcpResourceType": "Group",
            "memberCount": group.get('directMembersCount', 0),
            "riskLevel": group.get('riskLevel', 'Unknown')
        }
        
        sanitized_properties = sanitize_node_properties(clean_properties)
        
        group_node = Node(
            id=group_email,
            kinds=["GCP_Group", "GCP_Resource"],
            properties=Properties(**sanitized_properties)
        )
        graph.add_node(group_node)
        
        for variation in normalize_variations(group_email, discovered_project_names):
            node_id_map[variation] = group_email

    # Workload Identity Federation pools + providers. External identities
    # federating through a provider can be granted SA impersonation, so the
    # federation surface is exported as inventory nodes attached to the
    # project (GCP_Contains edges).
    for pool in wi_pools:
        pool_name = (pool.get('name', '') or '').lower()
        project_id = (pool.get('project', '') or '').lower()
        if not pool_name:
            continue
        state = pool.get('state', '')
        pool_properties = {
            "name": pool_name,
            "displayname": pool.get('displayName', pool_name),
            "platform": "GCP",
            "description": f"GCP Workload Identity Pool: {pool.get('displayName', pool_name)}",
            "gcpResourceType": "Workload Identity Pool",
            "poolId": pool.get('poolId', ''),
            "state": state,
            "providerCount": len(pool.get('providers', [])),
            "project": project_id,
            "riskLevel": "HIGH" if state == 'ACTIVE' else "LOW",
        }
        if pool_name not in graph.nodes:
            graph.add_node(Node(
                id=pool_name,
                kinds=["GCP_WorkloadIdentityPool", "GCP_Resource"],
                properties=Properties(**sanitize_node_properties(pool_properties)),
            ))
        if project_id:
            edges.append({
                'start': {'value': project_id},
                'end': {'value': pool_name},
                'kind': 'Contains',
                'properties': {
                    'source': 'workload_identity_enumeration',
                    'riskLevel': 'MEDIUM' if state == 'ACTIVE' else 'LOW',
                    'description': f"Project {project_id} contains workload identity pool "
                                   f"{pool.get('displayName', pool_name)}"
                }
            })

        for provider in pool.get('providers', []):
            provider_name = (provider.get('name', '') or '').lower()
            if not provider_name or provider_name in graph.nodes:
                continue
            provider_state = provider.get('state', '')
            provider_properties = {
                "name": provider_name,
                "displayname": provider.get('displayName', provider_name),
                "platform": "GCP",
                "description": f"GCP Workload Identity Provider: {provider.get('displayName', provider_name)}",
                "gcpResourceType": "Workload Identity Provider",
                "providerId": provider.get('providerId', ''),
                "state": provider_state,
                "riskLevel": "HIGH" if provider_state == 'ACTIVE' else "LOW",
            }
            graph.add_node(Node(
                id=provider_name,
                kinds=["GCP_WorkloadIdentityProvider", "GCP_Resource"],
                properties=Properties(**sanitize_node_properties(provider_properties)),
            ))
            edges.append({
                'start': {'value': pool_name},
                'end': {'value': provider_name},
                'kind': 'Contains',
                'properties': {
                    'source': 'workload_identity_enumeration',
                    'riskLevel': 'MEDIUM' if provider_state == 'ACTIVE' else 'LOW',
                    'description': f"Workload identity pool contains provider "
                                   f"{provider.get('displayName', provider_name)}"
                }
            })

    # API keys: exfiltratable project-scoped credentials. Exported as
    # inventory nodes attached to the project via GCP_Contains.
    for api_key in api_keys:
        key_name = (api_key.get('name', '') or '').lower()
        project_id = (api_key.get('project', '') or '').lower()
        if not key_name:
            continue
        unrestricted = api_key.get('unrestricted', False)
        key_properties = {
            "name": key_name,
            "displayname": api_key.get('displayName', api_key.get('keyId', key_name)),
            "platform": "GCP",
            "description": f"GCP API Key: {api_key.get('displayName', api_key.get('keyId', key_name))}",
            "gcpResourceType": "API Key",
            "keyId": api_key.get('keyId', ''),
            "restrictions": api_key.get('restrictions', 'none'),
            "unrestricted": unrestricted,
            "riskLevel": "HIGH" if unrestricted else "MEDIUM",
        }
        if key_name not in graph.nodes:
            graph.add_node(Node(
                id=key_name,
                kinds=["GCP_ApiKey", "GCP_Resource"],
                properties=Properties(**sanitize_node_properties(key_properties)),
            ))
        if project_id:
            edges.append({
                'start': {'value': project_id},
                'end': {'value': key_name},
                'kind': 'Contains',
                'properties': {
                    'source': 'api_key_enumeration',
                    'riskLevel': 'HIGH' if unrestricted else 'MEDIUM',
                    'description': f"Project {project_id} contains API key "
                                   f"{api_key.get('displayName', api_key.get('keyId', ''))}"
                                   + (" without API/referrer restrictions" if unrestricted else "")
                }
            })

    # VPC networking: networks, subnets and firewall rules as inventory
    # nodes (containment edges only — no traversal implied).
    for net in networks:
        net_id = f"gcp-network-{(net.get('project') or '').lower()}-{(net.get('name') or '').lower()}"
        if not net.get('name') or net_id in graph.nodes:
            continue
        project_id = (net.get('project') or '').lower()
        graph.add_node(Node(
            id=net_id,
            kinds=["GCP_Network", "GCP_Resource"],
            properties=Properties(**sanitize_node_properties({
                "name": net_id,
                "displayname": net.get('name', net_id),
                "platform": "GCP",
                "description": f"GCP VPC Network: {net.get('name', net_id)}",
                "gcpResourceType": "VPC Network",
                "networkName": net.get('name', ''),
                "autoCreateSubnetworks": net.get('autoCreateSubnetworks', True),
                "routingMode": net.get('routingMode', ''),
                "project": project_id,
                "riskLevel": "Unknown",
            })),
        ))
        if project_id:
            edges.append({
                'start': {'value': project_id},
                'end': {'value': net_id},
                'kind': 'Contains',
                'properties': {
                    'source': 'networking_enumeration',
                    'riskLevel': 'LOW',
                    'description': f"Project {project_id} contains VPC network {net.get('name', '')}"
                }
            })

    for subnet in subnets:
        project_id = (subnet.get('project') or '').lower()
        subnet_id = (f"gcp-subnet-{project_id}-{(subnet.get('region') or '').lower()}"
                     f"-{(subnet.get('name') or '').lower()}")
        if not subnet.get('name') or subnet_id in graph.nodes:
            continue
        graph.add_node(Node(
            id=subnet_id,
            kinds=["GCP_Subnet", "GCP_Resource"],
            properties=Properties(**sanitize_node_properties({
                "name": subnet_id,
                "displayname": subnet.get('name', subnet_id),
                "platform": "GCP",
                "description": f"GCP Subnet: {subnet.get('name', subnet_id)}",
                "gcpResourceType": "Subnet",
                "region": subnet.get('region', ''),
                "ipCidrRange": subnet.get('ipCidrRange', ''),
                "gatewayAddress": subnet.get('gatewayAddress', ''),
                "privateIpGoogleAccess": subnet.get('privateIpGoogleAccess', False),
                "project": project_id,
                "riskLevel": "Unknown",
            })),
        ))
        network_name = (subnet.get('network') or '').lower()
        if network_name:
            parent_id = f"gcp-network-{project_id}-{network_name}"
            edges.append({
                'start': {'value': parent_id},
                'end': {'value': subnet_id},
                'kind': 'Contains',
                'properties': {
                    'source': 'networking_enumeration',
                    'riskLevel': 'LOW',
                    'description': f"Network {network_name} contains subnet "
                                   f"{subnet.get('name', '')} ({subnet.get('ipCidrRange', '')})"
                }
            })

    for fw in firewalls:
        project_id = (fw.get('project') or '').lower()
        fw_id = f"gcp-firewall-{project_id}-{(fw.get('name') or '').lower()}"
        if not fw.get('name') or fw_id in graph.nodes:
            continue
        source_ranges = fw.get('sourceRanges') or []
        open_ingress = (
            not fw.get('disabled') and fw.get('direction') == 'INGRESS'
            and '0.0.0.0/0' in source_ranges
        )
        graph.add_node(Node(
            id=fw_id,
            kinds=["GCP_Firewall", "GCP_Resource"],
            properties=Properties(**sanitize_node_properties({
                "name": fw_id,
                "displayname": fw.get('name', fw_id),
                "platform": "GCP",
                "description": f"GCP Firewall Rule: {fw.get('name', fw_id)}",
                "gcpResourceType": "Firewall Rule",
                "direction": fw.get('direction', ''),
                "disabled": fw.get('disabled', False),
                "sourceRanges": source_ranges,
                "targetTags": fw.get('targetTags', []),
                "allowed": fw.get('allowedSummary', ''),
                "project": project_id,
                "riskLevel": "HIGH" if open_ingress else "LOW",
            })),
        ))
        network_name = (fw.get('network') or '').lower()
        if network_name:
            parent_id = f"gcp-network-{project_id}-{network_name}"
            edges.append({
                'start': {'value': parent_id},
                'end': {'value': fw_id},
                'kind': 'Contains',
                'properties': {
                    'source': 'networking_enumeration',
                    'riskLevel': 'HIGH' if open_ingress else 'LOW',
                    'description': f"Network {network_name} contains firewall rule "
                                   f"{fw.get('name', '')} ({fw.get('allowedSummary', '')})"
                }
            })

    # Cloud KMS crypto keys: inventory nodes attached to the project
    # (decrypt capability is IAM-driven; no traversal edge is implied).
    for kms_key in kms_keys:
        key_path = (kms_key.get('name', '') or '').lower()
        project_id = (kms_key.get('project', '') or '').lower()
        if not key_path:
            continue
        if key_path not in graph.nodes:
            graph.add_node(Node(
                id=key_path,
                kinds=["GCP_KMSKey", "GCP_Resource"],
                properties=Properties(**sanitize_node_properties({
                    "name": key_path,
                    "displayname": kms_key.get('keyId', key_path),
                    "platform": "GCP",
                    "description": f"GCP KMS Crypto Key: {kms_key.get('keyId', key_path)}",
                    "gcpResourceType": "KMS Crypto Key",
                    "keyRing": kms_key.get('keyRing', ''),
                    "purpose": kms_key.get('purpose', ''),
                    "rotationPeriod": kms_key.get('rotationPeriod', ''),
                    "primaryState": kms_key.get('primaryState', ''),
                    "primaryAlgorithm": kms_key.get('primaryAlgorithm', ''),
                    "project": project_id,
                    "riskLevel": "Unknown",
                })),
            ))
        if project_id:
            edges.append({
                'start': {'value': project_id},
                'end': {'value': key_path},
                'kind': 'Contains',
                'properties': {
                    'source': 'kms_enumeration',
                    'riskLevel': 'LOW',
                    'description': f"Project {project_id} contains KMS key "
                                   f"{kms_key.get('keyId', '')} "
                                   f"(ring: {kms_key.get('keyRing', '')})"
                }
            })

    # Add secret nodes using ONLY real enumerated data (secrets were
    # collected but never exported as nodes). Edge builders reference
    # secrets both as gcp-secret-<project>-<name> and by the raw name, so
    # the raw name is registered as an alias of the canonical node.
    for secret in secrets:
        secret_name = (secret.get('name', '') or '').strip().lower()
        project_id = (secret.get('project', '') or '').strip().lower()
        if not secret_name:
            print(f"[WARNING] Skipping secret with invalid name: {secret}")
            continue
        
        canonical_id = f"gcp-secret-{project_id}-{secret_name}" if project_id else secret_name
        if canonical_id in graph.nodes:
            continue
        
        clean_properties = {
            "name": secret_name,
            "displayname": secret_name,
            "platform": "GCP",
            "project": project_id or 'Unknown',
            "description": f"GCP Secret: {secret_name}",
            
            # Real GCP-specific metadata from API
            "gcpResourceType": "Secret",
            "versionCount": secret.get('versionCount', 'Unknown'),
            "hasEnabledVersions": secret.get('hasEnabledVersions', 'Unknown'),
            
            # Real security analysis
            "riskLevel": secret.get('riskLevel', 'Unknown'),
            "remediationPriority": "Unknown"
        }
        
        sanitized_properties = sanitize_node_properties(clean_properties)
        
        secret_node = Node(
            id=canonical_id,
            kinds=["GCP_Secret", "GCP_Resource"],
            properties=Properties(**sanitized_properties)
        )
        graph.add_node(secret_node)
        
        for variation in normalize_variations(canonical_id, discovered_project_names):
            node_id_map[variation] = canonical_id
        # Alias: edge_builder references secrets by their raw name
        if secret_name != canonical_id:
            node_id_map[secret_name] = canonical_id

    # Add current user using real data when possible
    if creds:
        try:
            from utils.auth import get_active_account
            current_user = get_active_account(creds).lower()
        except:
            current_user = "unknown"
    else:
        current_user = "unknown"
    
    if current_user != "unknown":
        current_user_name = current_user.split('@')[0] if '@' in current_user else current_user
        
        clean_properties = {
            "name": current_user,
            "displayname": current_user,
            "email": current_user,
            "platform": "GCP",
            "description": f"Authenticated User: {current_user}",
            
            # Enhanced searchability
            "username": current_user_name,
            "domain": current_user.split('@')[1] if '@' in current_user else 'Unknown',
            "userPrincipalName": current_user,
            
            # Real user info - mark as unknown since we don't have Admin SDK access
            "lastLogin": "Unknown",
            "creationTime": "Unknown",
            "mfaEnabled": "Unknown",
            "suspended": "Unknown",
            "mailboxSetup": "Unknown",
            
            # Security analysis
            "gcpResourceType": "User Account",
            "privilegeLevel": "Unknown",
            "accessLevel": "Unknown",
            "riskLevel": "Unknown",
            "remediationPriority": "Unknown",
            "detectedRoles": [],
            
            # Enhanced metadata
            "authMethod": "Service Account" if "gserviceaccount.com" in current_user else "User",
            "projectsAccessible": len(projects)
        }
        
        sanitized_properties = sanitize_node_properties(clean_properties)
        
        # FIXED: Only 2 kinds maximum
        user_node = Node(
            id=current_user,
            kinds=["GCP_User", "GCP_Resource"],
            properties=Properties(**sanitized_properties)
        )
        graph.add_node(user_node)
        
        for variation in normalize_variations(current_user, discovered_project_names):
            node_id_map[variation] = current_user

    # ---- NEW: Add edge types for new relationships ----
    # Add Project -> HasGoogleOwnedSA -> GoogleManagedSA edges (project policies only)
    for policy in iam_data or []:
        if (policy.get('resourceType') or 'project') not in ('project', ''):
            continue
        project_id = extract_project_from_iam_policy(policy)
        for binding in policy.get('bindings', []):
            for member in binding.get('members', []):
                if member.startswith('serviceAccount:'):
                    sa_email = member.replace('serviceAccount:', '')
                    if is_google_managed_sa(sa_email) and project_id:
                        edges.append({
                            'start': {'value': project_id},
                            'end': {'value': sa_email},
                            'kind': 'HasGoogleOwnedSA',
                            'properties': {
                                'source': 'iam_analysis',
                                'managedService': extract_service_name(sa_email),
                                'description': 'Project uses Google-managed service account'
                            }
                        })

    # Add User -> OwnsProject/MemberOfProject -> Project edges (project policies only)
    for policy in iam_data or []:
        if (policy.get('resourceType') or 'project') not in ('project', ''):
            continue
        project_id = extract_project_from_iam_policy(policy)
        for binding in policy.get('bindings', []):
            role = binding.get('role', '').lower()
            for member in binding.get('members', []):
                if member.startswith('user:'):
                    user_email = member.replace('user:', '')
                    is_owner = 'owner' in role
                    edge_kind = "OwnsProject" if is_owner else "MemberOfProject"
                    user_roles = get_user_roles_from_iam(user_email, policy)
                    
                    if project_id:
                        edges.append({
                            'start': {'value': user_email},
                            'end': {'value': project_id},
                            'kind': edge_kind,
                            'properties': {
                                'source': 'iam_analysis',
                                'roles': ", ".join(user_roles),  # Convert array to string for edge properties
                                'description': f'User has {", ".join(user_roles)} on project'
                            }
                        })

    # Create logging access edges with IAM data
    logging_edges = create_logging_access_edges(log_sinks, current_user, service_accounts, iam_data)
    edges.extend(logging_edges)

    # Edge filtering
    edges = filter_edges_for_bloodhound(edges)

    # Validate edges before processing
    edges = validate_and_clean_graph_data(graph.nodes, edges, None)

    # Build edge variations for validation
    all_sa_variations = set()
    for sa in service_accounts:
        sa_email = sa.get('email', '').lower()
        for variation in normalize_variations(sa_email, discovered_project_names):
            all_sa_variations.add(variation)

    all_project_variations = set()
    for project in projects:
        project_id = project.get('projectId', '').lower()
        for variation in normalize_variations(project_id, discovered_project_names):
            all_project_variations.add(variation)

    # SA-scoped edge types that should NEVER target projects.
    # Kinds are namespaced by fix_edge_name() before this check runs.
    sa_scoped_edge_types = {
        'GCP_CanGetAccessToken', 'GCP_CanSignBlob', 'GCP_CanSignJWT',
        'GCP_CanModifyIamPolicy', 'GCP_CanImpersonate', 'GCP_CanCreateKeys',
    }

    # Drop SA-scoped edges that target projects BEFORE building nodes, so no
    # orphan nodes are created for endpoints that only appear on edges the
    # SA-scoped guard will reject. (These come from privesc edges like
    # CanEscalateViaIamserviceaccountkeyscreate that fix_edge_name renames
    # into SA-scoped kinds while still targeting a project.)
    sa_scoped_blocked = 0
    kept_edges = []
    for edge_data in edges:
        kind = fix_edge_name(edge_data.get("kind", "RelatedTo"))
        raw_end = edge_data.get("end", {}).get("value", "")
        end_id = str(raw_end).strip().lower() if raw_end else ""
        if kind in sa_scoped_edge_types and end_id in all_project_variations:
            sa_scoped_blocked += 1
            raw_start = edge_data.get("start", {}).get("value", "")
            print(f"[DEBUG] ❌ Blocking invalid SA→Project edge: {str(raw_start).strip().lower()} --[{kind}]-> {end_id}")
            continue
        kept_edges.append(edge_data)
    edges = kept_edges

    def infer_node_kinds(node_id):
        """
        Infer node kinds and description from ID pattern.
        Uses smart pattern matching for all GCP resource types.
        """
        import re
        
        # Google-managed Service Account (standard pattern)
        if re.match(r"^service-\d+@gcp-sa-[a-z0-9\-]+\.iam\.gserviceaccount\.com$", node_id):
            # Extract service name from the pattern
            service_match = re.search(r"@gcp-sa-([a-z0-9\-]+)\.", node_id)
            service_name = service_match.group(1) if service_match else "unknown"
            return (
                ["GCP_GoogleManagedSA", "GCP_ServiceAccount"],
                f"Google-managed {service_name.replace('-', ' ').title()} Service Account"
            )
        
        # Cloud service robots (compute-system, firebase-rules, gcf-admin-robot, cloudservices)
        robot_pattern = r"@(cloudservices|compute-system|firebase-rules|gcf-admin-robot|container-engine-robot)\.iam\.gserviceaccount\.com$"
        if re.search(robot_pattern, node_id):
            service_match = re.search(r"@([a-z\-]+)\.", node_id)
            if service_match:
                service_name = service_match.group(1).replace('-', ' ').title()
                return (
                    ["GCP_GoogleManagedSA", "GCP_ServiceAccount"],
                    f"Google {service_name} Service Robot"
                )
        
        # Regular GCP Service Account (ends with @*.gserviceaccount.com)
        # This includes user- prefixed SAs and regular ones
        if node_id.endswith("@gserviceaccount.com") or ("@" in node_id and "gserviceaccount.com" in node_id):
            # Handle special prefixes
            if node_id.startswith("user-"):
                sa_name = node_id.split("@")[0].replace("user-", "")
                return (
                    ["GCP_ServiceAccount", "GCP_Resource"],
                    f"Service Account: {sa_name}"
                )
            else:
                return (
                    ["GCP_ServiceAccount", "GCP_Resource"],
                    "GCP Service Account"
                )
        
        # GCP User (has @ but NOT a service account)
        if "@" in node_id and "gserviceaccount.com" not in node_id:
            return (
                ["GCP_User", "GCP_Resource"],
                f"GCP User: {node_id}"
            )
        
        # Compute instance (gcp-compute-instance-<project>-<zone>-<name>)
        if node_id.startswith("gcp-compute-instance-"):
            return (
                ["GCP_Instance", "GCP_Resource"],
                f"GCP Compute Instance: {node_id}"
            )
        
        # Typed resource prefixes (ids match the collectors' edge id formats)
        typed_resource_prefixes = (
            ("gcp-pubsub-topic-", ["GCP_PubSubTopic", "GCP_Resource"], "Pub/Sub Topic"),
            ("gcp-pubsub-subscription-", ["GCP_PubSubTopic", "GCP_Resource"], "Pub/Sub Subscription"),
            ("gcp-gke-cluster-", ["GCP_Cluster", "GCP_Resource"], "GKE Cluster"),
            ("gcp-gke-nodepool-", ["GCP_Resource"], "GKE Node Pool"),
            ("gcp-secret-", ["GCP_Secret", "GCP_Resource"], "Secret Manager Secret"),
            ("gcp-bq-table-", ["GCP_Resource"], "BigQuery Table"),
            ("gcp-cloudsql-", ["GCP_SQLInstance", "GCP_Resource"], "Cloud SQL Instance"),
            ("gcp-cloudfunction-", ["GCP_Function", "GCP_Resource"], "Cloud Function"),
        )
        for prefix, kinds, label in typed_resource_prefixes:
            if node_id.startswith(prefix):
                return (kinds, f"{label}: {node_id}")
        
        # Project node with gcp-project- prefix
        if node_id.startswith("gcp-project-"):
            project_id = node_id.replace("gcp-project-", "")
            return (
                ["GCP_Project", "GCP_Resource"],
                f"GCP Project: {project_id}"
            )
        
        # Regular project ID pattern (lowercase alphanumeric with hyphens, 6-30 chars)
        if re.match(r"^[a-z][a-z0-9\-]{5,30}$", node_id) and ":" not in node_id:
            return (
                ["GCP_Project", "GCP_Resource"],
                f"GCP Project: {node_id}"
            )
        
        # Organization / folder resource names
        if node_id.startswith("organizations/"):
            return (
                ["GCP_Organization", "GCP_Resource"],
                f"GCP Organization: {node_id}"
            )
        if node_id.startswith("folders/"):
            return (
                ["GCP_Folder", "GCP_Resource"],
                f"GCP Folder: {node_id}"
            )

        # Log sink/stream
        if "logstream:" in node_id or "sink:" in node_id:
            return (
                ["GCP_LogSink", "GCP_Resource"],
                f"Log Stream: {node_id.split(':')[-1]}"
            )
        
        # Log bucket
        if "bucket:" in node_id and ("_Default" in node_id or "_Required" in node_id):
            return (
                ["GCP_LogBucket", "GCP_Resource"],
                f"Log Bucket: {node_id.split(':')[-1]}"
            )
        
        # Storage bucket (ends with .app or .appspot.com)
        if node_id.endswith(".app") or node_id.endswith(".appspot.com"):
            return (
                ["GCP_Bucket", "GCP_Resource"],
                f"Storage Bucket: {node_id}"
            )
        
        # Dataset (has gcp-bq-dataset prefix or contains dataset keyword)
        if node_id.startswith("gcp-bq-dataset-") or "dataset" in node_id.lower():
            return (
                ["GCP_Dataset", "GCP_Resource"],
                f"BigQuery Dataset: {node_id}"
            )
        
        # Fallback - generic resource
        return (
            ["GCP_Resource"],
            f"GCP Resource: {node_id}"
        )

    # Build every node BEFORE the edge loop: missing edge endpoints are
    # created first, not logged and dropped. (This pass used to run after
    # the edge loop, where edges to missing nodes had already been skipped.)
    for edge_data in edges:
        for endpoint in ["start", "end"]:
            raw_id = edge_data.get(endpoint, {}).get("value")
            node_id = str(raw_id).strip().lower() if raw_id else ""
            if not node_id:
                continue
            resolved_id = node_id_map.get(node_id, node_id)
            if resolved_id in graph.nodes:
                continue
            # USE infer_node_kinds() detection for 15+ GCP resource types
            kinds, desc = infer_node_kinds(node_id)
            # BloodHound CE search indexes name/displayname — always set them.
            props = {
                "name": resolved_id,
                "displayname": resolved_id,
                "platform": "GCP",
                "description": desc,
            }
            if "@" in resolved_id and "gserviceaccount.com" not in resolved_id:
                props["email"] = resolved_id
                props["username"] = resolved_id.split("@")[0]
                props["domain"] = resolved_id.split("@")[1] if "@" in resolved_id else "unknown"
                props["gcpResourceType"] = "User Account"
            elif "@" in resolved_id:
                props["email"] = resolved_id
                props["gcpResourceType"] = "Service Account"
            graph.add_node(Node(
                id=resolved_id,
                kinds=kinds,
                properties=Properties(**sanitize_node_properties(props))
            ))
            for variation in normalize_variations(node_id, discovered_project_names):
                node_id_map[variation] = resolved_id

    # Process edges with RESTORED detailed debugging
    edges_added = 0
    skipped_edges = 0
    
    print(f"[DEBUG] ✅ Total nodes in graph: {graph.get_node_count()}")
    print(f"[DEBUG] ✅ Total entries in node_id_map: {len(node_id_map)}")
    
    # Generic dataset node existence verification
    if bigquery_datasets:
        sample_dataset = bigquery_datasets[0]
        sample_dataset_id = sample_dataset.get('dataset_id', '')
        sample_project_id = sample_dataset.get('project', '')
        if sample_dataset_id and sample_project_id:
            canonical_id = normalize_dataset_id(sample_dataset_id, sample_project_id)
            exists_in_graph = canonical_id in graph.nodes
            exists_in_map = canonical_id in node_id_map
            print(f"[DEBUG] Sample dataset node in graph: {exists_in_graph}")
            print(f"[DEBUG] Sample dataset node in mapping: {exists_in_map}")
    else:
        print("[DEBUG] No datasets enumerated for verification")
    
    for i, edge_data in enumerate(edges):
        start_id = edge_data.get("start", {}).get("value", "").lower()
        end_id = edge_data.get("end", {}).get("value", "").lower()
        kind = fix_edge_name(edge_data.get("kind", "RelatedTo"))
        
        # VALIDATION: Skip if either ID is empty
        if not start_id or not start_id.strip() or not end_id or not end_id.strip():
            skipped_edges += 1
            print(f"[DEBUG] ❌ Skipping edge with empty ID: start='{start_id}', end='{end_id}'")
            continue
        
        actual_start = node_id_map.get(start_id, start_id)
        actual_end = node_id_map.get(end_id, end_id)
        
        # Block SA→Project edges for SA-scoped permissions
        if kind in sa_scoped_edge_types and end_id in all_project_variations:
            skipped_edges += 1
            print(f"[DEBUG] ❌ Blocking invalid SA→Project edge: {start_id} --[{kind}]-> {end_id}")
            continue
            
        # Block if target is not a valid node
        if actual_start not in graph.nodes or actual_end not in graph.nodes:
            skipped_edges += 1
            print(f"[DEBUG] ❌ Skipping edge to missing node: {actual_start} -> {actual_end}")
            continue
        
        # Process valid edges
        edge = Edge(
            start_node=actual_start,
            end_node=actual_end,
            kind=kind
        )
        
        # Convert arrays to strings only for edge properties
        for key, value in edge_data.get("properties", {}).items():
            if isinstance(value, list):
                sanitized_value = ", ".join([str(v) for v in value]) if value else "None"
            else:
                sanitized_value = sanitize_property_value(value)
            edge.set_property(key, sanitized_value)
        
        if graph.add_edge(edge):
            edges_added += 1
            # Show first 10 successful edges for debugging
            if edges_added <= 10:
                print(f"[DEBUG] ✅ Edge #{edges_added}: {actual_start} --[{kind}]-> {actual_end}")

    print(f"[DEBUG] Edges added: {edges_added}/{len(edges) + sa_scoped_blocked} (skipped {skipped_edges} invalid edges, blocked {sa_scoped_blocked} SA-scoped project-target edges)")

    # Export with schema validation
    os.makedirs("./output", exist_ok=True)
    
    # Dynamic filename generation based on authenticated user
    if creds and current_user != "unknown":
        try:
            from utils.auth import get_safe_output_filename
            output_filename = get_safe_output_filename(current_user)
        except Exception:
            output_filename = "gcp-bhopgraph.json"
    else:
        output_filename = "gcp-bhopgraph.json"
    
    output_file = os.path.join("./output", output_filename)

    success = graph.export_to_file(output_file)
    
    if success:
        try:
            with open(output_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            # BloodHound CE OpenGraph: drop reserved properties.objectid,
            # remove non-schema top-level fields (e.g. label), and rewrite
            # colon-containing ids which CE does not fully support.
            data = apply_opengraph_compliance(data)

            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            print(f"[DEBUG] ✅ Clean export completed - OpenGraph CE compliance applied")
            
        except Exception as e:
            print(f"[DEBUG] ⚠️ Export warning: {e}")

        print(f"[+] ✅ FINAL RESULT: {graph.get_node_count()} nodes, {edges_added} edges")
        print(f"[+] File: {output_file}")
        print(f"[+] 🎯 GCP ATTACK SURFACE WITH NEW FEATURES COMPLETE")
        return output_file
    else:
        print(f"[!] ❌ Export failed")
        return None
