# SPDX-License-Identifier: AGPL-3.0-or-later
"""Command-line interface: a button that syncs a folder with a Telegram group.

    tgsync              what changed, yours and others' (same as `tgsync status`)
    tgsync pull         download others' changes
    tgsync push         upload yours
    tgsync log          who changed what and when
    tgsync restore      bring back an older version of a file
    tgsync new DIR      start a vault        tgsync join CODE   join one
    tgsync invite / members / accept CODE / remove NAME
    tgsync --json ...   one JSON object on stdout, for scripts and plugins

One file per topic; each adds its commands to `main` (defined in common.py) on import.
"""

from . import common, people, restore, setup, syncing  # noqa: F401  (registers the commands)
from .common import main

__all__ = ["common", "main"]
