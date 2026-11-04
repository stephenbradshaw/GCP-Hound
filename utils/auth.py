import os
import re
import base64
import json
import sqlite3
from google.oauth2 import service_account
from google.oauth2.credentials import Credentials as UserCredentials
import google.auth

# Env / ADC quota used only for APIs with no target project (Admin SDK, org
# bootstrap, projects.list). Project-scoped collectors should call
# credentials_for_project() so each target project is the quota consumer.
QUOTA_ENV_VARS = ("GCPHOUND_QUOTA_PROJECT", "GOOGLE_CLOUD_QUOTA_PROJECT")


def get_quota_fallback(creds=None):
    """Project ID used only when a call has no natural target project."""
    for key in QUOTA_ENV_VARS:
        value = (os.environ.get(key) or "").strip()
        if value:
            return value
    if creds is not None:
        stored = getattr(creds, "_gcphound_quota_fallback", None)
        if stored:
            return stored
        return getattr(creds, "quota_project_id", None)
    return None


def credentials_with_quota(creds, project_id):
    """Return creds that send x-goog-user-project for the given project."""
    if not creds or not project_id or not hasattr(creds, "with_quota_project"):
        return creds
    try:
        cloned = creds.with_quota_project(project_id)
        # Preserve identity metadata attached by get_google_credentials
        for attr in ("account_email", "verified_account_email", "_gcphound_quota_fallback"):
            if hasattr(creds, attr):
                try:
                    setattr(cloned, attr, getattr(creds, attr))
                except Exception:
                    pass
        return cloned
    except Exception:
        return creds


def credentials_for_project(creds, project_id):
    """
    Prefer the *target* project as quota project so IAM/Service Usage/etc.
    only need to be enabled on that project—not on a central ADC quota project.
    """
    if project_id:
        return credentials_with_quota(creds, project_id)
    return credentials_for_bootstrap(creds)


def credentials_for_bootstrap(creds):
    """
    Quota for org/folder/project discovery and Workspace Admin SDK.
    Uses GCPHOUND_QUOTA_PROJECT / GOOGLE_CLOUD_QUOTA_PROJECT / ADC fallback.
    """
    fallback = get_quota_fallback(creds)
    if fallback:
        return credentials_with_quota(creds, fallback)
    return creds


def _detach_global_quota(creds):
    """
    Clear ADC's global quota_project_id so every API call does not require
    every service enabled on one project. Fallback is kept for bootstrap/Admin.
    """
    fallback = get_quota_fallback(creds)
    try:
        creds._gcphound_quota_fallback = fallback
    except Exception:
        pass
    if not getattr(creds, "quota_project_id", None):
        return creds
    if hasattr(creds, "with_quota_project"):
        try:
            cleared = creds.with_quota_project(None)
            try:
                cleared._gcphound_quota_fallback = fallback
            except Exception:
                pass
            for attr in ("account_email", "verified_account_email"):
                if hasattr(creds, attr):
                    try:
                        setattr(cleared, attr, getattr(creds, attr))
                    except Exception:
                        pass
            return cleared
        except Exception:
            pass
    return creds


def get_google_credentials(debug=False):
    """
    Attempts to retrieve Google Cloud credentials in order:
    1. Service account key from GCP_CREDS env var.
    2. Application Default Credentials (gcloud auth application-default login).
    3. Experimental: gcloud CLI credentials.db (active account)—handles both service accounts and user OAuth.
    Exits the process with a descriptive message if no credentials are found.

    User ADC quota is applied selectively: project-scoped calls should use
    credentials_for_project(); Admin SDK / org bootstrap use credentials_for_bootstrap().
    Set GCPHOUND_QUOTA_PROJECT to a small project with Admin SDK + Resource Manager
    enabled—do not enable every collector API there.
    """
    # 1. Preferred: Service account for automation (key file, no browser)
    env_path = os.getenv("GCP_CREDS")
    if env_path and os.path.exists(env_path):
        creds = service_account.Credentials.from_service_account_file(env_path)
        return creds

    # 2. Fallback: Application Default Credentials (ADC, browser login)
    try:
        creds, _ = google.auth.default()
        # Attach the gcloud account email to the credential when the ADC file
        # itself records one, so get_active_account can use it as an offline
        # fallback. The active gcloud CLI account is NOT used as a guess: ADC
        # and CLI credentials are separate stores, and guessing has proven to
        # misreport the identity.
        cred_file = _credentials_source_path(creds)
        adc_account = _read_adc_account_email(cred_file) or _read_adc_account_email()
        if adc_account:
            try:
                creds.account_email = adc_account
            except Exception:
                pass
        cli_account = _read_gcloud_cli_account()
        if adc_account and cli_account and adc_account != cli_account:
            config_name = _read_gcloud_active_config_name()
            source = f" ({cred_file})" if cred_file else ""
            print(
                f"[!] Note: the credentials file{source} records account {adc_account}, while "
                f"the active gcloud CLI configuration '{config_name}' uses {cli_account}. The "
                f"authenticated identity is verified against the credential token at startup."
            )
        creds = _detach_global_quota(creds)
        fallback = get_quota_fallback(creds)
        if debug and fallback:
            print(f"[DEBUG] Selective quota: fallback project={fallback} "
                  f"(used only for Admin SDK / org bootstrap; project APIs use target project)")
        elif debug:
            print("[DEBUG] Selective quota: no fallback project set "
                  "(set GCPHOUND_QUOTA_PROJECT for Admin SDK / projects.list)")
        return creds
    except Exception:
        pass

    # 3. Experimental: Try extracting from gcloud credentials.db
    try:
        print("[!] No standard credentials found, attempting gcloud CLI credentials (EXPERIMENTAL, UNSUPPORTED)...")
        active_account = _read_gcloud_cli_account()
        if not active_account:
            raise Exception("No active gcloud CLI account found in the gcloud configuration.")

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

def _gcloud_config_dir():
    """gcloud config directory, honoring CLOUDSDK_CONFIG like google.auth does"""
    return os.environ.get("CLOUDSDK_CONFIG") or os.path.expanduser("~/.config/gcloud")

def _credentials_source_path(creds):
    """
    File the credentials were loaded from, when google.auth recorded one
    (_cred_file_path). google.auth may load credentials from
    GOOGLE_APPLICATION_CREDENTIALS or CLOUDSDK_CONFIG rather than the
    default gcloud ADC path, so the recorded account can come from a
    different file than ~/.config/gcloud/application_default_credentials.json.
    """
    path = getattr(creds, "_cred_file_path", None)
    return path if isinstance(path, str) and path else None

def _read_adc_account_email(adc_path=None):
    """
    Account email recorded in an authorized-user credentials file (set by
    `gcloud auth application-default login`). This is recorded metadata and
    can be stale relative to the file's refresh token.
    """
    if not adc_path:
        adc_path = os.path.join(_gcloud_config_dir(), "application_default_credentials.json")
    if os.path.exists(adc_path):
        try:
            with open(adc_path) as f:
                info = json.load(f)
            if info.get("type") == "authorized_user":
                account = info.get("account", "")
                if _looks_like_email(account):
                    return account
        except Exception:
            pass
    return None

def _read_gcloud_active_config_name():
    """
    Name of the active gcloud CLI configuration (e.g. 'adminin'):
    CLOUDSDK_ACTIVE_CONFIG_NAME, else the active_config entry in the
    [configuration] section of gcloud's properties file, else the plain
    active_config file written by some gcloud versions, else 'default'.
    """
    name = os.environ.get("CLOUDSDK_ACTIVE_CONFIG_NAME")
    if name:
        return name

    config_dir = _gcloud_config_dir()

    properties_path = os.path.join(config_dir, "properties")
    if os.path.exists(properties_path):
        try:
            section = None
            with open(properties_path) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("[") and line.endswith("]"):
                        section = line[1:-1].strip().lower()
                        continue
                    if section == "configuration" and line.startswith("active_config"):
                        value = line.split("=", 1)[1].strip() if "=" in line else ""
                        if value:
                            return value
        except Exception:
            pass

    active_config_path = os.path.join(config_dir, "active_config")
    if os.path.exists(active_config_path):
        try:
            with open(active_config_path) as f:
                value = f.read().strip()
            if value:
                return value
        except Exception:
            pass

    return "default"

def _read_gcloud_cli_account():
    """
    Active account of the gcloud CLI, read from the ACTIVE configuration
    (which may not be config_default when several configurations exist).
    This is NOT necessarily the identity of the ADC credentials - it is
    only a guess used when the ADC file does not record an account.
    """
    account = os.environ.get("CLOUDSDK_CORE_ACCOUNT")
    if _looks_like_email(account):
        return account

    config_dir = _gcloud_config_dir()
    config_name = _read_gcloud_active_config_name()
    config_path = os.path.join(config_dir, "configurations", f"config_{config_name}")
    if not os.path.exists(config_path):
        config_path = os.path.join(config_dir, "configurations", "config_default")
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

def _read_gcloud_account_email():
    """
    Best-effort read of the account email to report for ADC credentials:
    the identity recorded in the ADC file, falling back to the active
    gcloud CLI account. Returns None when neither is available.
    """
    return _read_adc_account_email() or _read_gcloud_cli_account()

def _lookup_token_email(access_token):
    """
    Look up the email an access token was issued for, via Google's identity
    endpoints (userinfo / tokeninfo). Returns None on any failure.
    """
    try:
        import requests
    except Exception:
        return None
    headers = {"Authorization": f"Bearer {access_token}"}
    urls = (
        ("https://www.googleapis.com/oauth2/v1/userinfo", None),
        ("https://oauth2.googleapis.com/tokeninfo", {"access_token": access_token}),
    )
    for url, params in urls:
        try:
            response = requests.get(url, headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                email = response.json().get("email")
                if _looks_like_email(email):
                    return email
        except Exception:
            continue
    return None

def _resolve_user_identity_from_token(creds):
    """
    Resolve the identity behind user credentials from the live token itself.
    The account recorded in the ADC file can be stale, so the token is
    authoritative: refresh the credential if needed (a call to Google's
    token endpoint, not to any GCP project API) and read the id_token email,
    or fall back to a userinfo/tokeninfo lookup with the access token.
    Returns the email, or None. The verified email is cached on the
    credential as verified_account_email so later calls are free.
    """
    if getattr(creds, "refresh_token", None) is None and getattr(creds, "token", None) is None:
        return None
    try:
        from google.auth.transport.requests import Request
        if not creds.valid:
            creds.refresh(Request())
    except Exception:
        pass

    email = _decode_jwt_email(getattr(creds, "id_token", None))
    if not email:
        email = _lookup_token_email(getattr(creds, "token", None))
    if email:
        try:
            creds.verified_account_email = email
        except Exception:
            pass
    return email

def get_active_account(creds):
    """
    Return the signed-in identity for the given credentials:

    - Service account credentials: the service account email.
    - User credentials: the email on the credential. The id_token/token email
      and a resolution against the live token are authoritative; the account
      email recorded on the credential (ADC file / gcloud config) is only a
      fallback, since it can be stale.
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

    # User: identity already verified against the live token earlier
    verified = getattr(creds, "verified_account_email", None)
    if _looks_like_email(verified):
        return verified

    # User: resolve the identity from the live token when possible
    verified = _resolve_user_identity_from_token(creds)
    if verified:
        recorded = getattr(creds, "account", None) or getattr(creds, "account_email", None)
        if _looks_like_email(recorded) and recorded != verified:
            cred_file = _credentials_source_path(creds)
            source = f" in {cred_file}" if cred_file else " on the credential"
            print(
                f"[!] Note: the account recorded{source} ({recorded}) differs from "
                f"the verified credential identity ({verified}); using {verified}. "
                f"Re-run 'gcloud auth application-default login' to refresh the ADC file."
            )
        return verified

    # User: account email already known to the credential (offline fallback)
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
