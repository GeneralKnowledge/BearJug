"""BearJug's evidence policy for the first public sensor.

Adopted 2026-11-18 for one public sensor and one private collector. It is
deliberately conservative: revisit it once real daily evidence volume has been
measured (see ``docs/ingestion.md``, "Evidence policy").

Principles:

* keep sensitive raw material for the shortest useful period;
* keep ordinary raw evidence long enough to investigate recurring activity;
* (later) keep derived intelligence longer than the attacker material it came from;
* never let a failed collector connection fill the sensor's root filesystem.

Every default in the collector, the shipper and the disk guard comes from here,
so the policy lives in one place and its tests pin it.
"""

MIB = 1024 * 1024
GIB = 1024 * MIB

# Collector ------------------------------------------------------------------
RETENTION_DAYS_SENSITIVE = 30
"""TTY recordings, uploads and anything carrying an attempted password."""
RETENTION_DAYS_DEFAULT = 90
"""Everything else."""
MAX_EVIDENCE_BYTES = 32 * MIB
"""Largest single piece of evidence the collector accepts."""
SENSITIVE_READERS: tuple[str, ...] = ()
"""Nobody may decrypt sensitive evidence. ``--actor`` is a label the caller
supplies, not an authenticated identity, so this stays empty until the
collector enforces operator identity at the OS level."""

# Shipper (on the sensor) ----------------------------------------------------
DEAD_LETTER_RETENTION_DAYS = 14
DEAD_LETTER_MAX_BYTES = 64 * MIB
UNPRESERVED_RETENTION_DAYS = 7
"""Refused evidence the shipper couldn't copy to the dead-letter directory."""
SPOOL_WARN_BYTES = 8 * GIB
"""Warn when the spool directories alone hold this much. The disk guard
watches the whole evidence filesystem separately."""

# Sensor evidence volume and disk guard --------------------------------------
EVIDENCE_VOLUME_BYTES = 12 * GIB
"""Dedicated, encrypted filesystem holding Cowrie's output, the shipper state
and the dead-letter directory. A pilot allocation, not an outage guarantee."""
VOLUME_WARN_PERCENT = 70
VOLUME_STOP_PERCENT = 80
"""Stop Cowrie cleanly. Unacknowledged evidence is never deleted for space."""
VOLUME_RESUME_PERCENT = 60
"""Restart Cowrie only below this, and only when shipping is healthy."""
SHIPPER_HEALTHY_WITHIN_SECONDS = 120
"""Shipping counts as healthy if the shipper's last pass, no older than this,
reached the collector."""
