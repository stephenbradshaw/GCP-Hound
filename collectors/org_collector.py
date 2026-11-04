from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from utils.auth import credentials_for_bootstrap

def collect_orgs(creds):
    """
    Enumerate GCP organizations visible to the current credentials.

    CRM v1 no longer exposes organizations().list() in current discovery
    documents — use organizations().search() instead.
    """
    try:
        crm = build(
            "cloudresourcemanager", "v1",
            credentials=credentials_for_bootstrap(creds),
        )
        orgs = []
        # Empty filter returns organizations the caller can see. The search
        # body field is "filter" (not "query" — the API rejects unknown
        # body fields with a 400).
        request = crm.organizations().search(body={})
        while request is not None:
            resp = request.execute()
            orgs.extend(resp.get("organizations", []))
            request = crm.organizations().search_next(request, resp)

        if orgs:
            print(f"[+] Found {len(orgs)} organizations:")
            for org in orgs:
                org_id = org.get("name", "unknown")
                display_name = org.get("displayName", "N/A")
                print(f"    - {org_id}: {display_name}")
        else:
            print("[~] No organizations visible (this is normal for most service accounts)")
        return orgs
    except HttpError as e:
        print(f"[!] Unable to search organizations: {e}")
        return []
    except Exception as e:
        print(f"[!] Unable to list organizations: {e}")
        return []


def merge_orgs_from_folders(orgs, folders):
    """
    Ensure org IAM can run even when organizations.search returns nothing.

    Folder parents like organizations/123 still identify orgs we should
    attempt getIamPolicy on (e.g. after a CRM search API mismatch).
    """
    merged = list(orgs or [])
    seen = set()
    for org in merged:
        name = org.get("name") or ""
        if name.startswith("organizations/"):
            seen.add(name)
        else:
            oid = name or org.get("organizationId") or ""
            if oid:
                seen.add(oid if oid.startswith("organizations/") else f"organizations/{oid}")

    added = 0
    for folder in folders or []:
        parent = folder.get("parent") or ""
        if not parent.startswith("organizations/") or parent in seen:
            continue
        seen.add(parent)
        merged.append({
            "name": parent,
            "displayName": folder.get("parentDisplayName") or parent,
            "source": "folder_parent",
        })
        added += 1

    if added:
        print(f"[+] Added {added} organization(s) from folder parents for IAM collection")
        for name in sorted(seen):
            if any(o.get("source") == "folder_parent" and o.get("name") == name for o in merged):
                print(f"    - {name} (from folder parent)")
    return merged
