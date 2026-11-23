"""
OpenGenerator -- API key storage routes (optional macOS Keychain). Same style as campaign_api.py:
plain functions taking parsed JSON and returning ``(status, dict)``. A key is never echoed back.
"""
import keystore


def _obj(data):
    return data if isinstance(data, dict) else {}


def _err(status, exc):
    return status, {"error": str(exc)}


def keys_status(data):
    if not keystore.available():
        return 200, {"available": False, "stored": []}
    try:
        return 200, {"available": True, "stored": keystore.stored_ids()}
    except keystore.KeystoreError:
        return 200, {"available": True, "stored": []}


def keys_save(data):
    data = _obj(data)
    try:
        keystore.save(data.get("id"), data.get("key"))
    except keystore.KeystoreError as e:
        return _err(400, e)
    return 200, {"ok": True}


def keys_forget(data):
    data = _obj(data)
    try:
        keystore.forget(data.get("id"))
    except keystore.KeystoreError as e:
        return _err(400, e)
    return 200, {"ok": True}


def resolve_key(item_id, supplied_key, use_stored):
    """The key a route should use: a supplied key wins; else, when use_stored is true, the Keychain copy.
    Returns "" when neither applies. Raises keystore.KeystoreError (safe message) when use_stored is
    true but nothing is stored or the Keychain is unavailable."""
    if isinstance(supplied_key, str) and supplied_key:
        return supplied_key
    if use_stored is True:
        secret = keystore.load(item_id)
        if secret is None:
            raise keystore.KeystoreError("no saved key for that name; type the key instead")
        return secret
    return ""


ROUTES = {
    "/api/keys/status": keys_status,
    "/api/keys/save": keys_save,
    "/api/keys/forget": keys_forget,
}
