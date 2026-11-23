"""The neutral sensor-provider contract.

A SensorProvider is everything push_cert and push_ti need from a monitoring platform's
management API, expressed in platform-neutral terms. Concrete providers (see
``sensorops.providers``) implement it for one platform; the push modules orchestrate over
this interface and know nothing about any platform's endpoints, payloads, auth scheme or
error text.

Construction carries the connection and the credential: ``Provider(sensor_address, api_key)``.
The credential lives only on the instance for the life of one push and is never logged or
returned to the UI.

Normalisation is the provider's job. Methods return neutral data — plain ids, and collection
objects as dicts with the fixed keys documented on ``list_collections`` — so a push never
has to know a platform's object shape. Methods raise on transport/HTTP failure; the push
catches and routes the exception through ``explain()``.
"""
from abc import ABC, abstractmethod


class SensorProvider(ABC):
    #: human-readable platform name, for logs and messages; set by the concrete provider.
    name = "sensor"

    def __init__(self, sensor, apikey):
        self.sensor = sensor
        self.apikey = apikey

    # ---- identity ---------------------------------------------------------
    @abstractmethod
    def identity(self):
        """A dict ``{"hostname","platform","version"}`` describing the appliance, or None."""

    # ---- SSL decryption keys (push_cert) ----------------------------------
    @abstractmethod
    def list_decrypt_keys(self):
        """Current decryption keys as a list of ``{"id","name"}`` dicts."""

    @abstractmethod
    def delete_decrypt_key(self, key_id):
        """Remove one decryption key."""

    @abstractmethod
    def create_decrypt_key(self, name, cert_pem, key_pem):
        """Upload a certificate/key pair named ``name``; return the new key's id (resolving it
        however the platform exposes it), or None if the id could not be determined."""

    @abstractmethod
    def key_protocols(self, key_id):
        """Protocol/port mappings already on a key, as ``{"protocol","port"}`` dicts."""

    @abstractmethod
    def map_key_protocol(self, key_id, protocol, port):
        """Map a protocol to a port for a key."""

    @abstractmethod
    def is_mapping_conflict(self, error):
        """True if ``error`` is the platform reporting that the protocol/port mapping is
        already present — a success state, not a failure (on some platforms the mapping is a
        capture-wide setting, so one entry covers every key)."""

    # ---- threat collection (push_ti) --------------------------------------
    @abstractmethod
    def collection_key(self, name):
        """The platform's normalisation of a collection name, used to recognise 'our' one."""

    @abstractmethod
    def list_collections(self):
        """Threat collections as a list of neutral dicts, each with the keys:
        ``id``, ``name``, ``key`` (normalised, per ``collection_key``), ``builtin`` (bool),
        ``indicators`` (int imported count or None), ``detection_field`` (the name of the
        boolean field that controls detection-on-match, or None if unidentifiable) and
        ``detection_on`` (bool)."""

    @abstractmethod
    def delete_collection(self, col_id):
        """Remove one threat collection."""

    @abstractmethod
    def upload_collection(self, name, stix_bytes, filename, detections):
        """Upload a STIX bundle as a collection named ``name``; return the HTTP status code.
        ``detections`` asks the platform to raise detections on an indicator match."""

    @abstractmethod
    def set_collection_detection(self, col_id, field):
        """Enable detection-on-match on a collection by setting ``field`` true (``field`` comes
        from a collection's ``detection_field``)."""

    @abstractmethod
    def deployment_check(self):
        """Why a collection upload might be refused, established read-only before anything is
        sent: a dict ``{"threat_intel","console","console_threat_intel","notes"}``."""

    # ---- detections (campaign feedback) -----------------------------------
    def list_detections(self, from_ms, until_ms, limit=2000):
        """Raw detection records whose window falls in ``[from_ms, until_ms]`` (epoch
        milliseconds), as a list of dicts in the platform's own shape; the feedback scorer
        normalises them. Deliberately not abstract: a provider that cannot list detections
        simply inherits this, so adding the method does not break existing providers.
        ``limit`` caps how many records come back."""
        raise NotImplementedError("this sensor provider cannot list detections")

    # ---- errors -----------------------------------------------------------
    @abstractmethod
    def explain(self, error):
        """Turn a transport/HTTP failure into one actionable sentence, without echoing the
        credential."""

    # ---- shared orchestration helper (neutral; uses the dicts above) ------
    def find_our_collections(self, collections, name):
        """Every non-builtin collection whose normalised key matches ``name``'s key."""
        key = self.collection_key(name)
        return [c for c in (collections or [])
                if isinstance(c, dict) and not c.get("builtin") and c.get("key") == key]
