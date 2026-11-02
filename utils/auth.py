import os
import re
import base64
import json
import sqlite3
from google.oauth2 import service_account
from google.oauth2.credentials import Credentials as UserCredentials
import google.auth

def get_google_credentials(debug=False):
    """
    Attempts to retrieve Google Cloud credentials in order:
    1. Service account key from GCP_CREDS env var.
    2. Application Default Credentials (gcloud auth application-default login).
    3. Experimental: gcloud CLI credentials.db (active account)—handles both service accounts and user OAuth.
    Exits the process with a descriptive message if no credentials are found.
    """
    # 1. Preferred: Service account for automation (key file, no browser)
    env_path = os.getenv("GCP_CREDS")
    if env_path and os.path.exists(env_path):
        creds = service_account.Credentials.from_service_account_file(env_path)
        return creds

    # 2. Fallback: Application Default Credentials (ADC, browser login)
    try:
        creds, _ = google.auth.default()
        # Attach the gcloud account email to the credential when it can be
        # determined locally, so get_active_account can report the identity
        # instead of the OAuth client id.
        account_email = _read_gcloud_account_email()
        if account_email:
            try:
                creds.account_email = account_email
            except Exception:
                pass
        return creds
    except Exception:
        pass

    # 3. Experimental: Try extracting from gcloud credentials.db
    try:
        print("[!] No standard credentials found, attempting gcloud CLI credentials (EXPERIMENTAL, UNSUPPORTED)...")
        config_path = os.path.expanduser("~/.config/gcloud/configurations/config_default")
        active_account = None
        if os.path.exists(config_path):
            with open(config_path) as f:
                for line in f:
                    if line.strip().startswith("account ="):
                        active_account = line.split("=", 1)[1].strip()
                        break
        if not active_account:
            raise Exception("No active gcloud CLI account found in config_default.")

        db_path = os.path.expanduser("~/.config/gcloud/credentials.db")
        if not os.path.exists(db_path):
            raise Exception("gcloud credentials.db not found.")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM credentials")
        found_cred = None
        debug_matches = [] # collect info for debug output
        for row in cursor.fetchall():
            account_email = str(row[0]).strip().lower()  # normalize
            active_account_compare = str(active_account).strip().lower()  # normalize
            if debug:
                print(f"[DEBUG] Comparing db account_id: '{account_email}' <-> active: '{active_account_compare}'")
            if active_account_compare == account_email:
                import json
                cred_json = json.loads(row[1])  # 'credential' JSON blob
                found_cred = cred_json
                print("[DEBUG] Match found for active account.")
                break
        conn.close()

        if not found_cred:
            raise Exception(f"No credential entry found for account {active_account}")

        # If credential is a service account, load credentials from info dict
        if found_cred.get("type") == "service_account":
            creds = service_account.Credentials.from_service_account_info(found_cred)
            print(f"[+] Loaded gcloud CLI credentials for: {active_account} (service account key from credentials.db)")
            return creds

        # If credential is OAuth2 (user login), handle refresh/access token
        refresh_token = found_cred.get("refresh_token")
        client_id = found_cred.get("client_id")
        client_secret = found_cred.get("client_secret")
        token_uri = found_cred.get("token_uri", "https://oauth2.googleapis.com/token")

        if refresh_token and client_id and client_secret:
            creds = UserCredentials(
                token=None,
                refresh_token=refresh_token,
                client_id=client_id,
                client_secret=client_secret,
                token_uri=token_uri
            )
            creds.account_email = active_account
            print(f"[+] Loaded gcloud CLI credentials for: {active_account} (with refresh token)")
            return creds

        # If only access_token (rare/short-lived)
        access_token = found_cred.get("access_token")
        if access_token:
            from datetime import datetime
            expiry = None
            expiry_str = found_cred.get("token_expiry")
            if expiry_str:
                try:
                    expiry = datetime.strptime(expiry_str, "%Y-%m-%dT%H:%M:%SZ")
                except Exception:
                    expiry = None
            creds = UserCredentials(
                token=access_token,
                refresh_token=None,
                client_id=None,
                client_secret=None,
                token_uri=token_uri,
                expiry=expiry
            )
            creds.account_email = active_account
            print(f"[+] Loaded gcloud CLI access token for: {active_account} (NO refresh token, may expire soon!)")
            return creds

        raise Exception(f"No usable refresh/access token or service account found for {active_account}")

    except Exception as e:
        print(f"[!] Experimental gcloud CLI fallback failed: {e}")

    print(
        "[!] No valid Google Cloud credentials found!\n"
        "You can authenticate with one of the following methods:\n"
        " 1. Export a service account key with:\n"
        "    export GCP_CREDS='/full/path/to/your/key.json'\n"
        " 2. Or run:\n"
        "    gcloud auth application-default login\n"
        "Then run:\n"
        "  python3 main.py"
    )
    exit(1)

def _looks_like_email(value):
    """True when value is a string that looks like an email address"""
    return isinstance(value, str) and '@' in value and '.' in value.split('@', 1)[1]

def _decode_jwt_email(jwt_value):
    """Extract the email claim from a JWT (e.g. an id_token), or None"""
    if not isinstance(jwt_value, str):
        return None
    parts = jwt_value.split('.')
    if len(parts) != 3:
        return None
    try:
        payload = parts[1]
        payload += '=' * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
        email = claims.get('email')
        if _looks_like_email(email):
            return email
    except Exception:
        pass
    return None

def _read_gcloud_account_email():
    """
    Best-effort read of the active gcloud account email from local config:
    the ADC file's `account` field, or the active account in gcloud's
    config_default. Returns None when no account email can be found.
    """
    adc_path = os.path.expanduser("~/.config/gcloud/application_default_credentials.json")
    if os.path.exists(adc_path):
        try:
            with open(adc_path) as f:
                account = json.load(f).get("account", "")
            if _looks_like_email(account):
                return account
        except Exception:
            pass

    config_path = os.path.expanduser("~/.config/gcloud/configurations/config_default")
    if os.path.exists(config_path):
        try:
            with open(config_path) as f:
                for line in f:
                    if line.strip().startswith("account ="):
                        account = line.split("=", 1)[1].strip()
                        if _looks_like_email(account):
                            return account
        except Exception:
            pass
    return None

def get_active_account(creds):
    """
    Return the signed-in identity for the given credentials:

    - Service account credentials: the service account email.
    - User credentials: the email on the credential (id_token email, token
      email, or the account email already known to the credential).
    - "unknown" when no email is available. The OAuth client_id is never
      returned: for `gcloud auth application-default login` it is the public
      gcloud client id, not an identity.
    """
    if creds is None:
        return "unknown"

    # Service account: the service account email is the identity
    sa_email = getattr(creds, "service_account_email", None)
    if _looks_like_email(sa_email):
        return sa_email

    # Impersonated credentials: the target principal is the acting identity
    target_principal = getattr(creds, "target_principal", None)
    if _looks_like_email(target_principal):
        return target_principal

    # User: email from the id_token, when the credential carries one
    email = _decode_jwt_email(getattr(creds, "id_token", None))
    if email:
        return email

    # User: some credentials carry the email as the token itself (JWT)
    email = _decode_jwt_email(getattr(creds, "token", None))
    if email:
        return email

    # User: account email already known to the credential
    for attr in ("account", "account_email", "email"):
        value = getattr(creds, attr, None)
        if _looks_like_email(value):
            return value

    return "unknown"

def get_safe_output_filename(email):
    """
    Generate safe output filename based on authenticated user email.
    Takes first word of username and sanitizes it for filesystem safety.

    Examples:
     - compute@project.iam.gserviceaccount.com -> compute_gcp-bhopgraph.json
     - script@project.iam.gserviceaccount.com  -> script_gcp-bhopgraph.json
     - john.doe@example.com                   -> john_gcp-bhopgraph.json
    """
    if not email or '@' not in email:
        return "gcp-bhopgraph.json"

    username = email.split('@')[0]
    tokens = re.split(r'[^a-zA-Z0-9]', username)
    first_word = tokens[0].lower() if tokens and tokens[0] else ''
    safe_name = re.sub(r'[^a-z0-9_-]', '', first_word)
    if not safe_name:
        safe_name = "output"
    return f"{safe_name}_gcp-bhopgraph.json"
