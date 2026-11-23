"""Sensor providers: concrete SensorProvider implementations, selected by name.

The vendor provider is an optional module and may be absent (public builds do not include it). A downstream build, or support for another
platform, adds one by registering its class here; the push modules never name a platform
directly — they ask ``get_provider(sensor, apikey)`` for the default and orchestrate over the
neutral SensorProvider interface.
"""
_REGISTRY = {}
try:                                       # the vendor connector is optional: a build without it has no sensor push
    from .network_sensor import NetworkSensorProvider
    _REGISTRY["network_sensor"] = NetworkSensorProvider
except ImportError:
    pass

DEFAULT = "network_sensor"


def get_provider(sensor, apikey, name=DEFAULT):
    """Construct the sensor provider ``name``, bound to (sensor, apikey)."""
    if not _REGISTRY:
        raise ValueError("no sensor provider is installed in this build")
    try:
        cls = _REGISTRY[(name or DEFAULT).lower()]
    except (KeyError, AttributeError):
        raise ValueError("unknown sensor provider %r (available: %s)"
                         % (name, ", ".join(sorted(_REGISTRY))))
    return cls(sensor, apikey)


def available():
    """The provider names that can be requested."""
    return sorted(_REGISTRY)
