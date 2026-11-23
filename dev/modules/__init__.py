"""Capability modules (v5b).

Each subdirectory is a self-contained capability module discovered and managed at run time by
``netgen.platform`` (the kernel). See ``modules/README.md`` for the contract. This package
marker only makes ``import modules.<name>`` work; it imports nothing itself, so discovery never
has side effects.
"""
