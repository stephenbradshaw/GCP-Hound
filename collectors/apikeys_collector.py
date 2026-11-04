"""
API key enumeration for GCP-Hound.

API keys are simple, exfiltratable credentials: a string that identifies a
project (and optionally is restricted to specific APIs / referrers). Any
principal who can read a key can consume quota and call unrestricted APIs
as the project. Keys are exported as GCP_ApiKey nodes attached to their
project.

Requires apikeys.keys.list (roles/viewer includes it); failures are
non-fatal. Key strings are never returned by list and are not collected.
"""

from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from utils.auth import credentials_for_bootstrap


def collect_api_keys(creds, projects, args=None):
    """Collect API keys per project.

    Returns a list of key dicts:
    { "name": full resource name, "keyId": ..., "displayName": ...,
      "project": <project_id>, "restrictions": <summary string>,
      "unrestricted": bool }
    """
    keys_out = []
    if not creds or not projects:
        return keys_out

    denied_reported = False
    try:
        apikeys = build('apikeys', 'v2', credentials=credentials_for_bootstrap(creds))
    except Exception as e:
        if args and args.debug:
            print(f"[DEBUG] API key collector: service build failed: {e}")
        return keys_out

    for project in projects:
        project_id = (project.get('projectId') or '').lower()
        if not project_id:
            continue
        parent = f'projects/{project_id}/locations/global'
        try:
            request = apikeys.projects().locations().keys().list(parent=parent)
            while request is not None:
                response = request.execute()
                for key in response.get('keys', []):
                    key_name = key.get('name', '')
                    restrictions = key.get('restrictions') or {}
                    unrestricted = not any(
                        restrictions.get(field)
                        for field in ('apiTargets', 'browserKeyRestrictions',
                                      'serverKeyRestrictions')
                    )
                    keys_out.append({
                        'name': key_name,
                        'keyId': key_name.rsplit('/', 1)[-1],
                        'displayName': key.get('displayName', ''),
                        'project': project_id,
                        'uid': key.get('uid', ''),
                        'restrictions': _summarize_restrictions(restrictions),
                        'unrestricted': unrestricted,
                    })
                request = (
                    apikeys.projects().locations().keys()
                    .list_next(previous_request=request, previous_response=response)
                )
        except HttpError as e:
            if e.resp is not None and e.resp.status == 403 and not denied_reported:
                denied_reported = True
                if args and args.verbose:
                    print("[!] API keys not accessible "
                          "(needs apikeys.keys.list; skipping)")
            elif args and args.debug:
                print(f"[DEBUG] API keys unavailable for {project_id}: {e}")
        except Exception as e:
            if args and args.debug:
                print(f"[DEBUG] API key collection error for {project_id}: {e}")

    if keys_out:
        unrestricted_count = sum(1 for k in keys_out if k['unrestricted'])
        print(f"[+] API keys: {len(keys_out)} key(s) "
              f"({unrestricted_count} without API/referrer restrictions)")

    return keys_out


def _summarize_restrictions(restrictions):
    if not restrictions:
        return 'none'
    parts = []
    api_targets = restrictions.get('apiTargets') or []
    if api_targets:
        services = [t.get('service', '') for t in api_targets]
        parts.append('apis:' + ','.join(s for s in services if s))
    if restrictions.get('browserKeyRestrictions'):
        parts.append('browser-restricted')
    if restrictions.get('serverKeyRestrictions'):
        parts.append('server-restricted')
    return '; '.join(parts) if parts else 'none'