"""The command line parser every command uses."""

from __future__ import annotations

import argparse
import sys
from typing import NoReturn

from haprion import exit_codes


class ArgumentParser(argparse.ArgumentParser):
    """argparse, with a mistake on the command line exiting 64 (`USAGE`).

    argparse's own 2 is in no table this project publishes (CONTRACT.md), so a
    script could not tell a mistyped call from anything else (review 26-10-24,
    06-06). Every command parses with this; a test holds them to it.
    """

    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self.exit(exit_codes.USAGE, f"{self.prog}: error: {message}\n")
