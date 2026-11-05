"""
Cloud KMS enumeration for GCP-Hound.

Collects key rings and crypto keys per project (cloudkms v1) and exports
them as GCP_KMSKey inventory nodes attached to their project. Keys are
attack-relevant: a principal with cloudkms.cryptoKeyVersions.decrypt
can decrypt CMEK-protected secrets/disks, so key metadata (rotation,
purpose, next rotation) is surfaced on the node.

Read-only via cloudkms.keyRings.list / cloudkms.cryptoKeys.list
(roles/viewer and roles/iam.securityAuditor include them). Failures are
non-fatal. Key material is never accessible via these APIs.
"""

from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from utils.auth import credentials_for_bootstrap


def collect_kms_keys(creds, projects, args=None):
    """Collect KMS key rings and crypto keys per project.

    Returns a list of key dicts:
    { "name": full crypto key path, "keyId": short name, "keyRing": ...,
      "project": ..., "purpose": ..., "rotationPeriod": ...,
      "nextRotationTime": ..., "primaryState": ..., "labels": {} }
    """
    keys_out = []
    if not creds or not projects:
        return keys_out

    denied_reported = False
    try:
        kms = build('cloudkms', 'v1', credentials=credentials_for_bootstrap(creds))
    except Exception as e:
        if args and args.debug:
            print(f"[DEBUG] KMS collector: service build failed: {e}")
        return keys_out

    for project in projects:
        project_id = (project.get('projectId') or '').lower()
        if not project_id:
            continue
        parent = f'projects/{project_id}'

        # Enumerate locations (global + regional)
        try:
            locations = []
            request = kms.projects().locations().list(name=parent)
            while request is not None:
                response = request.execute()
                locations.extend(l.get('locationId', '') for l in response.get('locations', []))
                request = kms.projects().locations().list_next(request, response)
        except Exception as e:
            _debug(args, f'KMS locations for {project_id}', e)
            continue

        for location in locations:
            location_name = f'{parent}/locations/{location}'
            try:
                ring_request = kms.projects().locations().keyRings().list(parent=location_name)
                while ring_request is not None:
                    ring_response = ring_request.execute()
                    for ring in ring_response.get('keyRings', []):
                        ring_name = ring.get('name', '')
                        keys_out.extend(_collect_ring_keys(kms, ring_name, project_id, args))
                    ring_request = (kms.projects().locations().keyRings()
                                    .list_next(ring_request, ring_response))
            except HttpError as e:
                if e.resp is not None and e.resp.status == 403 and not denied_reported:
                    denied_reported = True
                    if args and args.verbose:
                        print("[!] KMS not accessible (needs cloudkms.keyRings.list; skipping)")
                else:
                    _debug(args, f'KMS keyrings in {location_name}', e)
            except Exception as e:
                _debug(args, f'KMS keyrings in {location_name}', e)

    if keys_out:
        print(f"[+] KMS: {len(keys_out)} crypto key(s)")

    return keys_out


def _collect_ring_keys(kms, ring_name, project_id, args=None):
    keys = []
    try:
        request = kms.projects().locations().keyRings().cryptoKeys().list(parent=ring_name)
        while request is not None:
            response = request.execute()
            for key in response.get('cryptoKeys', []):
                key_name = key.get('name', '')
                primary = key.get('primary') or {}
                keys.append({
                    'name': key_name,
                    'keyId': key_name.rsplit('/', 1)[-1],
                    'keyRing': ring_name.rsplit('/', 1)[-1],
                    'project': project_id,
                    'purpose': key.get('purpose', ''),
                    'rotationPeriod': key.get('rotationPeriod', ''),
                    'nextRotationTime': key.get('nextRotationTime', ''),
                    'primaryState': primary.get('state', ''),
                    'primaryAlgorithm': primary.get('algorithm', ''),
                })
            request = (kms.projects().locations().keyRings().cryptoKeys()
                       .list_next(request, response))
    except HttpError as e:
        if e.resp is not None and e.resp.status == 403:
            if args and args.verbose:
                print(f"[!] KMS cryptoKeys.list denied for {ring_name}")
        else:
            _debug(args, f'cryptoKeys in {ring_name}', e)
    except Exception as e:
        _debug(args, f'cryptoKeys in {ring_name}', e)
    return keys


def _debug(args, label, error):
    if args and args.debug:
        print(f"[DEBUG] KMS: error collecting {label}: {error}")