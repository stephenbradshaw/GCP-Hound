"""BloodHound OpenGraph kind names for GCP-Hound structured graphs.

BloodHound CE pathfinding requires an installed extension definition schema
whose node_kinds / relationship_kinds use ``<namespace>_<Name>`` names, and
matching kinds in the uploaded graph payload. This module is the single
source of truth for remapping legacy (un-namespaced) exporter kinds to the
structured ``GCP_*`` names used by ``gcp-extension-schema.json``.
"""

from __future__ import annotations

NAMESPACE = "GCP"

# Legacy exporter kind → structured OpenGraph kind
NODE_KIND_MAP = {
    "GCPBucket": "GCP_Bucket",
    "GCPCluster": "GCP_Cluster",
    "GCPDataset": "GCP_Dataset",
    "GCPFirewall": "GCP_Firewall",
    "GCPFolder": "GCP_Folder",
    "GCPFunction": "GCP_Function",
    "GCPGoogleManagedSA": "GCP_GoogleManagedSA",
    "GCPGroup": "GCP_Group",
    "GCPInstance": "GCP_Instance",
    "GCPKMSKey": "GCP_KMSKey",
    "GCPLogBucket": "GCP_LogBucket",
    "GCPLogMetric": "GCP_LogMetric",
    "GCPLogSink": "GCP_LogSink",
    "GCPNetwork": "GCP_Network",
    "GCPOrganization": "GCP_Organization",
    "GCPPrincipal": "GCP_Principal",
    "GCPProject": "GCP_Project",
    "GCPPubSubTopic": "GCP_PubSubTopic",
    "GCPResource": "GCP_Resource",
    "GCPRole": "GCP_Role",
    "GCPSQLInstance": "GCP_SQLInstance",
    "GCPSecret": "GCP_Secret",
    "GCPServiceAccount": "GCP_ServiceAccount",
    "GCPServiceAccountKey": "GCP_ServiceAccountKey",
    "GCPUser": "GCP_User",
    # Rare legacy aliases from early exporters / model leftovers
    "ServiceAccount": "GCP_ServiceAccount",
    "Project": "GCP_Project",
    "Bucket": "GCP_Bucket",
    "Dataset": "GCP_Dataset",
}

# Abuse / control-taking edges → traversable in the extension schema.
# Inventory / containment edges stay non-traversable.
EDGE_KIND_MAP = {
    # SA takeover
    "CanCreateKeys": "GCP_CanCreateKeys",
    "CanGetAccessToken": "GCP_CanGetAccessToken",
    "CanImpersonate": "GCP_CanImpersonate",
    "CanSignBlob": "GCP_CanSignBlob",
    "CanSignJWT": "GCP_CanSignJWT",
    "CanModifyIamPolicy": "GCP_CanModifyIamPolicy",
    "CanListKeys": "GCP_CanListKeys",
    # Project / runtime escalate
    "CanCreateComputeInstance": "GCP_CanCreateComputeInstance",
    "CanCreateCloudFunction": "GCP_CanCreateCloudFunction",
    "CanModifyProjectPolicy": "GCP_CanModifyProjectPolicy",
    "CanModifyBucketPolicy": "GCP_CanModifyBucketPolicy",
    "CanModifyBucketPoliciesInProject": "GCP_CanModifyBucketPoliciesInProject",
    "CanReadSecrets": "GCP_CanReadSecrets",
    "CanReadSecretsInProject": "GCP_CanReadSecretsInProject",
    "CanEscalateViaComputeInstance": "GCP_CanEscalateViaComputeInstance",
    "CanEscalateViaGKECluster": "GCP_CanEscalateViaGKECluster",
    "CanEscalateViaGroup": "GCP_CanEscalateViaGroup",
    "CanEscalateToAdmin": "GCP_CanEscalateToAdmin",
    "CanAccessCloudFunction": "GCP_CanAccessCloudFunction",
    "CanAccessCloudSQL": "GCP_CanAccessCloudSQL",
    "CanAccessPubSub": "GCP_CanAccessPubSub",
    "CanAccessBigQueryDataset": "GCP_CanAccessBigQueryDataset",
    "AdminTo": "GCP_AdminTo",
    "HighPrivilegeServiceAccount": "GCP_HighPrivilegeServiceAccount",
    # Inventory / containment / recon
    "BelongsTo": "GCP_BelongsTo",
    "Contains": "GCP_Contains",
    "ContainsServiceAccount": "GCP_ContainsServiceAccount",
    "OwnsProject": "GCP_OwnsProject",
    "OwnsStorageBucket": "GCP_OwnsStorageBucket",
    "OwnsDataset": "GCP_OwnsDataset",
    "OwnsSecret": "GCP_OwnsSecret",
    "HasGoogleOwnedSA": "GCP_HasGoogleOwnedSA",
    "HasRoleOnProject": "GCP_HasRoleOnProject",
    "MemberOf": "GCP_MemberOf",
    "MemberOfProject": "GCP_MemberOfProject",
    "UsesServiceAccount": "GCP_UsesServiceAccount",
    "SubscribesTo": "GCP_SubscribesTo",
    "RelatedTo": "GCP_RelatedTo",
    "CanViewSensitiveLogs": "GCP_CanViewSensitiveLogs",
    "CanAccessLogStream": "GCP_CanAccessLogStream",
    "CanWriteToLogSink": "GCP_CanWriteToLogSink",
}

# Edges that represent control-taking for pathfinding.
TRAVERSABLE_EDGE_KINDS = {
    "GCP_CanCreateKeys",
    "GCP_CanGetAccessToken",
    "GCP_CanImpersonate",
    "GCP_CanSignBlob",
    "GCP_CanSignJWT",
    "GCP_CanModifyIamPolicy",
    "GCP_CanCreateComputeInstance",
    "GCP_CanCreateCloudFunction",
    "GCP_CanModifyProjectPolicy",
    "GCP_CanModifyBucketPolicy",
    "GCP_CanModifyBucketPoliciesInProject",
    "GCP_CanReadSecrets",
    "GCP_CanReadSecretsInProject",
    "GCP_CanEscalateViaComputeInstance",
    "GCP_CanEscalateViaGKECluster",
    "GCP_CanEscalateViaGroup",
    "GCP_CanEscalateToAdmin",
    "GCP_CanAccessCloudFunction",
    "GCP_CanAccessCloudSQL",
    "GCP_CanAccessPubSub",
    "GCP_CanAccessBigQueryDataset",
    "GCP_AdminTo",
    "GCP_HighPrivilegeServiceAccount",
}


def namespace_node_kind(kind: str) -> str:
    if not kind:
        return kind
    if kind in NODE_KIND_MAP:
        return NODE_KIND_MAP[kind]
    if kind.startswith(f"{NAMESPACE}_"):
        return kind
    return kind


def namespace_edge_kind(kind: str) -> str:
    if not kind:
        return kind
    if kind in EDGE_KIND_MAP:
        return EDGE_KIND_MAP[kind]
    if kind.startswith(f"{NAMESPACE}_"):
        return kind
    # Verbose collector names that fix_edge_name may have missed
    return EDGE_KIND_MAP.get(kind, kind)


def namespace_node_kinds(kinds):
    if not kinds:
        return kinds
    return [namespace_node_kind(k) for k in kinds]
