"""sensorops — modular sensor-push operations, split out of the former sensor.py.

Two referenceable pushes, each in its own module and each with its own state, orchestrating
over a platform-neutral `SensorProvider` (see `sensorops.provider`):

  * push_cert — load the generated server certificates and keys (SSL decryption).
  * push_ti   — load the exported STIX 2.1 threat collection.

Importers use the modules directly, e.g.::

    from sensorops import push_cert, push_ti
    push_cert.push_cert(sensor, apikey, certs_dir)   # start the cert push
    push_ti.push_ti(sensor, apikey, stix_path)       # start the threat-collection push

These are reached from the UI's "Beta Operations" section. The push entry points are
`push_cert.push_cert` and `push_ti.push_ti`; each module also exposes its own preflight,
stop and status.

Both pushes are platform-agnostic: every sensor-API specific (endpoints, payloads, auth,
error text) lives behind a `SensorProvider` (`sensorops.provider`), implemented per platform
in `sensorops.providers`. OpenGenerator ships the the sensor vendor provider; the push modules never
name a platform. Shared, provider-independent filesystem helpers live in `_util`.
"""
from . import push_cert, push_ti   # noqa: F401
