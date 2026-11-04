"""
Workload Identity Federation enumeration for GCP-Hound.

Workload identity pools + providers are a privilege-escalation surface:
external identities federating through a provider can impersonate service
accounts (via pool-level SA bindings), so pools/providers are exported as
graph nodes attached to their project.

Requires iam.workloadIdentityPools.list (included in
roles/iam.workloadIdentityPoolAdmin / roles/viewer); failures are
non-fatal and reported once per run.
"""

from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from utils.auth import credentials_for_bootstrap


def collect_workload_identity(creds, projects, args=None):
    """Collect workload identity pools and their providers per project.

    Returns a list of pool dicts:
    {
      "name": "projects/<p>/locations/global/workloadIdentityPools/<id>",
      "poolId": ..., "displayName": ..., "state": ...,
      "project": <project_id>,
      "providers": [ {"name": ..., "providerId": ..., "displayName": ...,
                      "state": ..., "providerType": ...} ]
    }
    """
    pools_out = []
    if not creds or not projects:
        return pools_out

    denied_reported = False
    try:
        iam = build('iam', 'v1', credentials=credentials_for_bootstrap(creds))
    except Exception as e:
        if args and args.debug:
            print(f"[DEBUG] Workload identity collector: IAM service build failed: {e}")
        return pools_out

    for project in projects:
        project_id = (project.get('projectId') or '').lower()
        if not project_id:
            continue
        parent = f'projects/{project_id}/locations/global'
        try:
            request = iam.projects().locations().workloadIdentityPools().list(parent=parent)
            while request is not None:
                response = request.execute()
                for pool in response.get('workloadIdentityPools', []):
                    pool_name = pool.get('name', '')
                    pool_entry = {
                        'name': pool_name,
                        'poolId': pool_name.rsplit('/', 1)[-1],
                        'displayName': pool.get('displayName', ''),
                        'state': pool.get('state', 'STATE_UNSPECIFIED'),
                        'project': project_id,
                        'providers': [],
                    }
                    pool_entry['providers'] = _collect_providers(iam, pool_name, args)
                    pools_out.append(pool_entry)
                request = (
                    iam.projects()
                    .locations()
                    .workloadIdentityPools()
                    .list_next(previous_request=request, previous_response=response)
                )
        except HttpError as e:
            if e.resp is not None and e.resp.status == 403 and not denied_reported:
                denied_reported = True
                if args and args.verbose:
                    print("[!] Workload identity pools not accessible "
                          "(needs iam.workloadIdentityPools.list; skipping)")
            elif args and args.debug:
                print(f"[DEBUG] WI pools unavailable for {project_id}: {e}")
        except Exception as e:
            if args and args.debug:
                print(f"[DEBUG] WI pool collection error for {project_id}: {e}")

    if pools_out:
        provider_count = sum(len(p['providers']) for p in pools_out)
        print(f"[+] Workload Identity: {len(pools_out)} pool(s), "
              f"{provider_count} provider(s)")

    return pools_out


def _collect_providers(iam, pool_name, args=None):
    providers = []
    try:
        request = (
            iam.projects()
            .locations()
            .workloadIdentityPools()
            .providers()
            .list(name=pool_name)
        )
        while request is not None:
            response = request.execute()
            for provider in response.get('workloadIdentityPoolProviders', []):
                provider_name = provider.get('name', '')
                providers.append({
                    'name': provider_name,
                    'providerId': provider_name.rsplit('/', 1)[-1],
                    'displayName': provider.get('displayName', ''),
                    'state': provider.get('state', 'STATE_UNSPECIFIED'),
                    'providerType': provider.get('description', ''),
                })
            request = (
                iam.projects()
                .locations()
                .workloadIdentityPools()
                .providers()
                .list_next(previous_request=request, previous_response=response)
            )
    except Exception as e:
        if args and args.debug:
            print(f"[DEBUG] WI providers unavailable for {pool_name}: {e}")
    return providers