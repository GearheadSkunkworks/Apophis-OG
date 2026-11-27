"""Reference capability module (v5b Phase 2): a runtime-loadable sensor provider.

Proves the third capability kind — a ``SensorProvider`` — plugs in as a module. ``register``
adds a no-op provider named ``demo`` to the sensorops provider registry (so it becomes a
selectable push target) and declares teardown via ``kernel.on_unload``. It never contacts
anything; its methods return empty/benign values, so loading it changes nothing until someone
explicitly pushes to a sensor named with the ``demo`` provider.
"""
from sensorops.provider import SensorProvider
from sensorops import providers as _providers

PROVIDER = "demo"


class DemoProvider(SensorProvider):
    """A provider that implements the interface with inert stubs (no network I/O)."""
    name = PROVIDER

    def identity(self):
        return {"hostname": self.sensor, "platform": "demo-provider", "version": "0"}

    def list_decrypt_keys(self):
        return []

    def delete_decrypt_key(self, key_id):
        return None

    def create_decrypt_key(self, name, cert_pem, key_pem):
        return {"id": "demo-key", "name": name}

    def key_protocols(self, key_id):
        return []

    def map_key_protocol(self, key_id, protocol, port):
        return None

    def is_mapping_conflict(self, error):
        return False

    def collection_key(self, name):
        return name

    def list_collections(self):
        return []

    def delete_collection(self, col_id):
        return None

    def upload_collection(self, name, stix_bytes, filename, detections):
        return 200

    def set_collection_detection(self, col_id, field):
        return None

    def deployment_check(self):
        return {"threat_intel": True, "console": True, "console_threat_intel": True,
                "notes": "demo provider — inert, contacts nothing"}

    def explain(self, error):
        return str(error)


def register(kernel):
    """Add the demo provider to the sensorops registry and declare its teardown."""
    _providers._REGISTRY[PROVIDER] = DemoProvider
    kernel.on_unload(lambda: _providers._REGISTRY.pop(PROVIDER, None))


def self_test():
    """Confirm the provider is registered and instantiable through the normal factory."""
    try:
        ok = PROVIDER in _providers.available()
        inst = _providers.get_provider("demo.local", "x", name=PROVIDER)
        ok = ok and isinstance(inst, DemoProvider)
    except Exception as e:                               # noqa: BLE001 - factory failure is the check result, returned as not ok
        return {"ok": False, "detail": "provider factory failed: %s" % e}
    return {"ok": ok, "detail": "registered as provider %r; available: %s"
            % (PROVIDER, ", ".join(_providers.available()))}
