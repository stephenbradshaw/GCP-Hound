"""
Cloud Asset Inventory (CAI) based IAM collection for GCP-Hound.

Opt-in (--use-cai): replaces the per-resource getIamPolicy walk with a single
paginated searchAllIamPolicies call per scope (org > folder > project). One
call returns every IAM policy below the scope, including conditional
bindings, with far fewer API round-trips.

Requires cloudasset.assets.searchAllIamPolicies, included in
roles/cloudasset.viewer (not in roles/iam.securityAuditor). On permission
failure the caller should fall back to the standard getIamPolicy flow.

The cloudasset v1 discovery document does not expose the
iamPolicies.searchAll method, so this module calls the REST endpoint
directly over an AuthorizedSession (google.auth, already a dependency).

Covers the resource-manager hierarchy (org/folder/project) plus
resource-level policies on buckets, secrets, BigQuery datasets and
service accounts, which map onto existing node ids. Other resource
types are counted and reported but not transformed.
"""

import json

from google.auth.transport.requests import AuthorizedSession
from utils.auth import credentials_for_bootstrap

_CAI_SEARCH_URL = "https://cloudasset.googleapis.com/v1/{scope}:searchAllIamPolicies"
_CRM_PREFIX = "//cloudresourcemanager.googleapis.com/"


def _error_reason(response):
    """Extract the error reason from a google API JSON error response."""
    try:
        data = response.json()
        details = data.get('error', {}).get('details', [])
        for detail in details:
            reason = detail.get('reason') or ''
            if reason:
                return reason
        errors = data.get('error', {}).get('errors', [])
        if errors:
            return errors[0].get('reason') or ''
        return data.get('error', {}).get('status') or ''
    except Exception:
        return ''


def _resolve_scopes(orgs=None, folders=None, projects=None):
    """Build the list of CAI scopes to query.

    An organization scope covers everything below it, so one scope suffices.
    Without an org, use each top-level folder (org-parented); without those,
    one scope per project.
    """
    for org in orgs or []:
        name = org.get("name") or ""
        if name.startswith("organizations/"):
            return [name]

    folder_scopes = []
    for folder in folders or []:
        parent = folder.get("parent") or ""
        name = folder.get("name") or ""
        if parent.startswith("organizations/") and name:
            folder_scopes.append(name)
    if folder_scopes:
        return sorted(set(folder_scopes))

    project_ids = sorted({(p.get("projectId") or "").lower() for p in projects or []} - {""})
    return [f"projects/{pid}" for pid in project_ids]


def collect_iam_policies_cai(creds, orgs=None, folders=None, projects=None, args=None):
    """Collect IAM policies via CAI searchAllIamPolicies.

    Queries one scope per unresolved hierarchy root (a single org scope
    covers the whole tree; otherwise top-level folders, else projects).

    Returns the iam_data list, or None when CAI could not be used at all
    (build failure or permission denied) so the caller can fall back to the
    getIamPolicy flow. Entries match the getIamPolicy-based collector format.
    """
    iam_data = []
    skipped_resource_policies = 0

    scopes = _resolve_scopes(orgs, folders, projects)
    if not scopes:
        if args and args.verbose:
            print("[!] CAI: no scope available (no orgs/folders/projects)")
        return None

    try:
        session = AuthorizedSession(credentials_for_bootstrap(creds))
    except Exception as e:
        if args and args.debug:
            print(f"[DEBUG] CAI credentials unavailable: {e}")
        print(f"[!] CAI IAM collection unavailable ({e}); falling back to getIamPolicy flow")
        return None

    if args and args.verbose:
        print(f"[*] CAI: searching IAM policies under {len(scopes)} scope(s)")

    for scope in scopes:
        try:
            url = _CAI_SEARCH_URL.format(scope=scope)
            params = {"pageSize": "1000"}
            while True:
                # The REST binding is a GET (asset_service.proto:
                # get: "/v1/{scope=*/*}:searchAllIamPolicies"); POST returns
                # a generic front-end 404.
                response = session.get(url, params=params)
                if response.status_code == 403:
                    reason = _error_reason(response)
                    if reason in ('SERVICE_DISABLED', 'accessNotConfigured', 'USER_PROJECT_DENIED'):
                        print(f"[!] CAI searchAllIamPolicies failed on {scope} "
                              f"({reason}): enable cloudasset.googleapis.com on the "
                              f"quota project (GCPHOUND_QUOTA_PROJECT) and ensure the "
                              f"caller has serviceusage.services.use there; "
                              f"falling back to getIamPolicy flow")
                    else:
                        print(f"[!] CAI searchAllIamPolicies denied on {scope} "
                              f"(needs cloudasset.assets.searchAllIamPolicies on the "
                              f"search scope; reason: {reason or 'unknown'}); "
                              f"falling back to getIamPolicy flow")
                    return None
                if response.status_code != 200:
                    print(f"[!] CAI searchAllIamPolicies failed on {scope} "
                          f"(HTTP {response.status_code}): {response.text[:200]}; "
                          f"falling back to getIamPolicy flow")
                    return None
                data = response.json()
                results = data.get("results", [])
                if args and args.debug and results:
                    sample = json.dumps(results[0])[:500]
                    print(f"[DEBUG] CAI result sample (keys={list(results[0].keys())}): {sample}")
                for result in results:
                    policy = _transform_cai_result(result)
                    if policy:
                        iam_data.append(policy)
                    elif result.get("resource"):
                        skipped_resource_policies += 1
                        if args and args.debug and skipped_resource_policies <= 3:
                            print(f"[DEBUG] CAI skipped resource: {result.get('resource')} "
                                  f"(keys={list(result.keys())})")
                page_token = data.get("nextPageToken") or ""
                if not page_token:
                    break
                params["pageToken"] = page_token
        except Exception as e:
            print(f"[!] CAI searchAllIamPolicies error on {scope}: {e}; "
                  f"falling back to getIamPolicy flow")
            return None

    by_type = {}
    for policy in iam_data:
        rtype = policy.get("resourceType", "unknown")
        by_type[rtype] = by_type.get(rtype, 0) + 1
    summary = ", ".join(f"{count} {rtype}" for rtype, count in sorted(by_type.items()))
    print(f"[+] CAI: collected {len(iam_data)} IAM policies ({summary or 'none'})")
    if skipped_resource_policies:
        print(f"[~] CAI: {skipped_resource_policies} resource-level policy(ies) skipped "
              f"(v1 collects org/folder/project only)")

    return iam_data


def _transform_cai_result(result):
    """Convert a CAI searchAllIamPolicies result to the iam_data dict format.

    Resource-manager hierarchy resources map directly; a few resource-level
    families (buckets, secrets, BigQuery datasets, service accounts) map to
    existing node ids so resource-scoped bindings produce real edges instead
    of being discarded. Returns None for anything else.
    """
    resource = result.get("resource") or ""
    iam_policy = result.get("iamPolicy") or {}
    bindings = iam_policy.get("bindings", [])
    if not bindings:
        return None

    if not resource.startswith("//"):
        return None

    without_protocol = resource[2:]
    slash_idx = without_protocol.find("/")
    if slash_idx <= 0:
        return None
    service = without_protocol[:slash_idx]
    path = without_protocol[slash_idx + 1:].rstrip("/")
    parts = path.split("/")

    if service == "cloudresourcemanager.googleapis.com":
        if len(parts) >= 2 and parts[0] == "projects":
            project_id = parts[1]
            return {
                "resourceType": "project",
                "resourceName": f"projects/{project_id}",
                "projectId": project_id,
                "projectName": project_id,
                "bindings": bindings,
                "bindingCount": len(bindings),
                "source": "cai_search_all",
            }
        if len(parts) >= 2 and parts[0] == "folders":
            folder_id = parts[1]
            return {
                "resourceType": "folder",
                "resourceName": f"folders/{folder_id}",
                "folderId": folder_id,
                "bindings": bindings,
                "bindingCount": len(bindings),
                "source": "cai_search_all",
            }
        if len(parts) >= 2 and parts[0] == "organizations":
            org_id = parts[1]
            return {
                "resourceType": "organization",
                "resourceName": f"organizations/{org_id}",
                "organizationId": org_id,
                "organizationName": org_id,
                "bindings": bindings,
                "bindingCount": len(bindings),
                "source": "cai_search_all",
            }
        return None

    if service == "storage.googleapis.com" and len(parts) >= 2 and parts[0] == "buckets":
        return {
            "resourceType": "bucket",
            "resourceName": parts[1],
            "bindings": bindings,
            "bindingCount": len(bindings),
            "source": "cai_search_all",
        }

    if service == "secretmanager.googleapis.com" and len(parts) >= 4 \
            and parts[0] == "projects" and parts[2] == "secrets":
        return {
            "resourceType": "secret",
            "resourceName": parts[3],
            "projectId": parts[1],
            "bindings": bindings,
            "bindingCount": len(bindings),
            "source": "cai_search_all",
        }

    if service == "bigquery.googleapis.com" and len(parts) >= 4 \
            and parts[0] == "projects" and parts[2] == "datasets":
        return {
            "resourceType": "dataset",
            "resourceName": f"projects/{parts[1]}/datasets/{parts[3]}",
            "projectId": parts[1],
            "bindings": bindings,
            "bindingCount": len(bindings),
            "source": "cai_search_all",
        }

    if service == "iam.googleapis.com" and len(parts) >= 4 \
            and parts[0] == "projects" and parts[2] == "serviceAccounts":
        return {
            "resourceType": "serviceAccount",
            "resourceName": parts[3],
            "projectId": parts[1],
            "bindings": bindings,
            "bindingCount": len(bindings),
            "source": "cai_search_all",
        }

    return None