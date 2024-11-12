""" Security utilities for generating high-entropy seeds. """

from os import getenv, getpid, urandom, times
from time import time_ns, time, perf_counter_ns
from socket import gethostname
from hashlib import sha256
from psutil import Process


def get_enhanced_seed() -> str:
    """
    Generate a high-entropy seed for cryptographic operations.

    Returns:
        str: A hex string derived from multiple entropy sources.
    """
    try:
        # System-specific elements
        process_id = str(getpid())
        hostname = gethostname()
        nano_time = str(time_ns())
        random_bytes = urandom(16).hex()
        memory_info = str(Process().memory_info().rss)
        totp_secret = str(getenv("TOTP_SECRET_KEY", ""))
        current_time = str(int(time()))

        # Combine and hash all elements
        combined = (
            f"{totp_secret}"
            f"{current_time}"
            f"{process_id}"
            f"{hostname}"
            f"{nano_time}"
            f"{random_bytes}"
            f"{memory_info}"
        )
        return sha256(combined.encode()).hexdigest()

    except Exception:  # pylint: disable=W0718
        # Fallback with reliable sources
        system_time = str(perf_counter_ns())
        process_start_time = str(times().user)
        totp_secret = str(getenv("TOTP_SECRET_KEY", ""))
        current_time = str(int(time()))

        combined = (
            f"{totp_secret}" f"{current_time}" f"{system_time}" f"{process_start_time}"
        )
        return sha256(combined.encode()).hexdigest()
