"""
TLS bootstrap. Import this once, first thing in a process entrypoint.

Makes Python trust the OS certificate store (via `truststore`) so corporate /
self-signed root CAs are honored — fixes CERTIFICATE_VERIFY_FAILED on networks
that MITM TLS. Best-effort: a no-op if truststore isn't installed (e.g. on
Railway, where the default CA bundle already works).
"""
try:
    import truststore

    truststore.inject_into_ssl()
except Exception:  # noqa: BLE001 — never let TLS setup crash startup
    pass
