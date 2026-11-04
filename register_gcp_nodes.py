#!/usr/bin/env python3
"""
GCP-Hound BloodHound registration helpers.

Installs:
  1) OpenGraph extension (schema + optional saved Cypher queries as a ZIP bundle)
  2) Optional custom-node icons via /api/v2/custom-nodes

BloodHound v9.9.0+ accepts extension ZIP bundles with:
  schema.json, saved_queries.json (optional), pz_rules.json (optional)
Older servers still accept schema-only JSON (no saved queries).
"""

import argparse
import io
import json
import logging
import sys
import zipfile
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_MODEL = "gcp-model.json"
DEFAULT_EXTENSION = "gcp-extension-schema.json"
DEFAULT_SAVED_QUERIES = "saved_queries.json"


class BloodHoundRegistrar:
    def __init__(self, url, username, password):
        self.url = url.rstrip("/")
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.verify = False
        self.token = None

        logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")
        self.logger = logging.getLogger(__name__)

    def login(self):
        login_url = self.url + "/api/v2/login"
        payload = {
            "login_method": "secret",
            "username": self.username,
            "secret": self.password,
        }
        try:
            response = self.session.post(login_url, json=payload, timeout=30)
            if response.status_code == 200:
                data = response.json()
                self.token = data["data"]["session_token"]
                self.session.headers.update({"Authorization": f"Bearer {self.token}"})
                self.logger.info("✅ Login successful to BloodHound")
                return True
            self.logger.error(f"❌ Login failed: {response.status_code}")
            self.logger.error(f"Response: {response.text}")
            return False
        except Exception as e:
            self.logger.error(f"❌ Login error: {e}")
            return False

    def logout(self):
        try:
            self.session.post(self.url + "/api/v2/logout")
            self.logger.info("🔐 Logged out from BloodHound")
        except Exception as e:
            self.logger.warning(f"⚠️ Logout warning: {e}")

    def get_existing_kinds(self):
        try:
            response = self.session.get(self.url + "/api/v2/custom-nodes")
            if response.status_code == 200:
                data = response.json()
                kinds = [
                    item.get("kindName")
                    for item in data.get("data", [])
                    if item.get("kindName")
                ]
                self.logger.info(f"Found {len(kinds)} custom node kinds: {kinds}")
                return kinds
            self.logger.warning(f"Failed to get kinds: {response.status_code}")
            return []
        except Exception as e:
            self.logger.warning(f"⚠️ Error fetching existing kinds: {e}")
            return []

    def delete_kind(self, kind):
        try:
            response = self.session.delete(self.url + f"/api/v2/custom-nodes/{kind}")
            if response.status_code == 200:
                self.logger.info(f"🗑️ Deleted existing kind: {kind}")
                return True
            return False
        except Exception as e:
            self.logger.warning(f"⚠️ Error deleting kind {kind}: {e}")
            return False

    def reset_all_kinds(self):
        self.logger.info("🔄 Resetting ALL existing custom node kinds...")
        existing_kinds = self.get_existing_kinds()
        if not existing_kinds:
            self.logger.info("ℹ️ No existing custom node kinds found to reset")
            return True
        for kind in existing_kinds:
            self.delete_kind(kind)
        return True

    def _build_extension_bundle(self, schema_path, saved_queries_path=None):
        """Build an in-memory ZIP: schema.json (+ saved_queries.json when present)."""
        schema_path = Path(schema_path)
        schema = json.loads(schema_path.read_text())
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            # Bundle requires the file to be named schema.json at ZIP root
            zf.writestr("schema.json", json.dumps(schema, indent=2))
            query_count = 0
            if saved_queries_path and Path(saved_queries_path).is_file():
                queries_obj = json.loads(Path(saved_queries_path).read_text())
                query_count = len(queries_obj.get("queries", []))
                zf.writestr(
                    "saved_queries.json",
                    json.dumps(queries_obj, indent=2),
                )
        buf.seek(0)
        return buf, schema, query_count

    def install_extension(self, schema_path, saved_queries_path=None):
        """
        Install/update the OpenGraph extension.

        Prefers a ZIP bundle (schema + saved queries) for BH 9.9+.
        Falls back to schema-only JSON if the server rejects the bundle.
        """
        schema_path = Path(schema_path)
        try:
            schema = json.loads(schema_path.read_text())
        except Exception as e:
            self.logger.error(f"❌ Could not load extension schema {schema_path}: {e}")
            return False

        meta = schema.get("schema", {})
        self.logger.info(
            "📦 Installing OpenGraph extension "
            f"{meta.get('name')} {meta.get('version')} "
            f"(namespace={meta.get('namespace')})"
        )

        queries_path = Path(saved_queries_path) if saved_queries_path else None
        use_bundle = bool(queries_path and queries_path.is_file())

        if use_bundle:
            try:
                bundle, schema, query_count = self._build_extension_bundle(
                    schema_path, queries_path
                )
                self.logger.info(
                    f"📦 Uploading extension bundle "
                    f"(schema + {query_count} saved queries)"
                )
                response = self.session.put(
                    self.url + "/api/v2/extensions",
                    data=bundle.getvalue(),
                    headers={"Content-Type": "application/zip"},
                    timeout=120,
                )
                if response.status_code in (200, 201):
                    self.logger.info("✅ OpenGraph extension bundle installed/updated")
                    self.logger.info(
                        f"   node_kinds={len(schema.get('node_kinds', []))} "
                        f"relationship_kinds={len(schema.get('relationship_kinds', []))} "
                        f"saved_queries={query_count}"
                    )
                    self.logger.info(
                        "   Saved queries appear under Explore → Saved Queries "
                        "(filter Platform = GCP-Hound / extension name)"
                    )
                    return True
                body = (response.text or "")[:500]
                # Prefer surfacing Cypher/schema validation over a version guess —
                # a 400 with "invalid Cypher" means the server *does* support bundles.
                if "invalid Cypher" in body or "graph schema validation" in body:
                    hint = (
                        "Saved-query Cypher failed server validation "
                        "(fix aliases/reserved words in saved_queries.json)."
                    )
                elif response.status_code in (404, 405):
                    hint = "Server may be < BloodHound v9.9 (ZIP extension bundles)."
                else:
                    hint = (
                        "If this is not a Cypher validation error, "
                        "confirm BloodHound v9.9+ (CE or Enterprise)."
                    )
                self.logger.warning(
                    f"⚠️ Bundle upload failed ({response.status_code}); "
                    f"falling back to schema-only JSON. {hint} Response: {body}"
                )
            except Exception as e:
                self.logger.warning(
                    f"⚠️ Bundle upload error ({e}); falling back to schema-only JSON"
                )

        try:
            response = self.session.put(
                self.url + "/api/v2/extensions",
                json=schema,
                timeout=120,
            )
            if response.status_code in (200, 201):
                self.logger.info("✅ OpenGraph extension schema installed/updated")
                self.logger.info(
                    f"   node_kinds={len(schema.get('node_kinds', []))} "
                    f"relationship_kinds={len(schema.get('relationship_kinds', []))}"
                )
                if use_bundle:
                    self.logger.warning(
                        "⚠️ Saved queries were NOT installed with the schema fallback. "
                        "Re-run after fixing saved_queries.json, or import them manually. "
                        "ZIP bundles require BloodHound v9.9+ (CE and Enterprise)."
                    )
                return True
            self.logger.error(f"❌ Extension install failed: {response.status_code}")
            self.logger.error(f"Response: {response.text}")
            return False
        except Exception as e:
            self.logger.error(f"❌ Extension install error: {e}")
            return False

    def register_nodes(self, model):
        if "custom_kinds" not in model or not model["custom_kinds"]:
            self.logger.error("❌ No custom kinds found in model")
            return False
        payload = {"custom_types": {}}
        for kind_name, kind_config in model["custom_kinds"].items():
            payload["custom_types"][kind_name] = {
                "icon": kind_config.get("icon", {}),
                "searchable_properties": kind_config.get("searchable_properties", []),
                "display_property": kind_config.get("display_property", "name"),
            }
        self.logger.info(
            f"📝 Registering {len(model['custom_kinds'])} custom node icon types..."
        )
        try:
            response = self.session.post(
                self.url + "/api/v2/custom-nodes", json=payload, timeout=60
            )
            if response.status_code in (200, 201):
                self.logger.info(
                    f"✅ Successfully registered {len(model['custom_kinds'])} kinds"
                )
                return True
            if response.status_code == 409:
                self.logger.info("ℹ️ Custom node kinds already registered")
                return True
            self.logger.error(f"❌ Registration failed: {response.status_code}")
            self.logger.error(f"Response: {response.text}")
            return False
        except Exception as e:
            self.logger.error(f"❌ Registration error: {e}")
            return False

    def load_model(self, file_path):
        try:
            with open(file_path, "r") as f:
                model = json.load(f)
            self.logger.info(f"📋 Loaded model from: {file_path}")
            return model
        except Exception as e:
            self.logger.error(f"❌ Error loading model from {file_path}: {e}")
            return None


def main():
    parser = argparse.ArgumentParser(
        description="Install GCP-Hound OpenGraph extension + optional custom node icons"
    )
    parser.add_argument("-s", "--server", required=True, help="BloodHound server URL")
    parser.add_argument("-u", "--username", required=True, help="BloodHound username")
    parser.add_argument("-p", "--password", required=True, help="BloodHound password")
    parser.add_argument(
        "-m",
        "--model",
        default=DEFAULT_MODEL,
        help="Path to GCP icon model JSON (custom-nodes)",
    )
    parser.add_argument(
        "--extension-schema",
        default=DEFAULT_EXTENSION,
        help="Path to OpenGraph extension definition schema JSON",
    )
    parser.add_argument(
        "--saved-queries",
        default=DEFAULT_SAVED_QUERIES,
        help="Path to saved_queries.json included in the extension ZIP bundle "
        "(BloodHound v9.9+). Pass empty string to skip.",
    )
    parser.add_argument(
        "--icons-only",
        action="store_true",
        help="Only register custom-node icons (skip extension schema)",
    )
    parser.add_argument(
        "--extension-only",
        action="store_true",
        help="Only install extension schema/bundle (skip custom-node icons)",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Reset ALL existing custom node kinds before registering icons",
    )
    parser.add_argument(
        "--list-existing",
        action="store_true",
        help="List existing custom node kinds and exit",
    )

    args = parser.parse_args()

    print("🔐 GCP-Hound BloodHound OpenGraph setup")
    print("=" * 60)

    # Fix accidental space in attribute from draft - use clean class
    registrar = BloodHoundRegistrar(args.server, args.username, args.password)
    if not registrar.login():
        print("❌ Failed to authenticate with BloodHound")
        sys.exit(1)

    try:
        if args.list_existing:
            existing = registrar.get_existing_kinds()
            print(f"\n📋 Existing custom node kinds ({len(existing)}):")
            for kind in existing:
                print(f"   • {kind}")
            return

        ok = True

        if not args.icons_only:
            saved = args.saved_queries.strip() if args.saved_queries else ""
            if not registrar.install_extension(
                args.extension_schema,
                saved_queries_path=saved or None,
            ):
                ok = False

        if not args.extension_only:
            if args.reset:
                registrar.reset_all_kinds()
            model = registrar.load_model(args.model)
            if model is None or not registrar.register_nodes(model):
                ok = False

        if not ok:
            print("❌ Setup incomplete")
            sys.exit(1)

        print("\n🎉 SUCCESS! BloodHound is ready for GCP-Hound structured graphs")
        print("=" * 60)
        if not args.icons_only:
            print("✅ OpenGraph extension installed (schema ± saved Cypher queries)")
        if not args.extension_only:
            print("✅ Custom GCP node icons registered")
        print("\n💡 Next steps:")
        print("   1. python3 gcp-hound.py")
        print("   2. Upload output/*gcp-bhopgraph.json in BloodHound")
        print("   3. Explore → Saved Queries → filter by GCP-Hound / Identity")
        print("   4. Pathfinding with traversable edges (GCP_MemberOf, GCP_CanCreateKeys, …)")
    finally:
        registrar.logout()


if __name__ == "__main__":
    main()
