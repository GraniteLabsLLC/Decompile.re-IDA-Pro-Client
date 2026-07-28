"""HTTP transport creation for the signed client updater."""

from __future__ import annotations

import threading

import requests


def create_update_session(
    cancel_event: threading.Event | None = None,
) -> requests.Session:
    """Create the requests session used for release checks and downloads."""
    del cancel_event
    return requests.Session()
