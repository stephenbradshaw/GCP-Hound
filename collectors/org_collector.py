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
        # Empty query returns organizations the caller can see.
        request = crm.organizations().search(body={"query": ""})
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
