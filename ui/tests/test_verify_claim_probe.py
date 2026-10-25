"""03-verify's claim probe is the worker's claim (review 26-10-24, 05-05).

The probe said "exactly as the worker will write it" and was not: no attempts,
no held condition, no claim gate. The column matrix and the database suite
cover the claim today; this keeps the probe from drifting from it again.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from haprion_ui import db

VERIFY = Path(__file__).resolve().parents[2] / "install/platform/03-verify"


def words(sql: str) -> str:
    return " ".join(re.sub(r"\(\s+", "(", re.sub(r"\s+\)", ")", sql)).split())


def worker_claim() -> str:
    """The statement `claim_job` sends, its parameters as the probe states them."""

    connection = mock.MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchone.return_value = None
    db.claim_job(connection, worker_id="probe", lease_seconds=30)
    sql: str = cursor.execute.call_args.args[0]
    parameters: dict[str, Any] = cursor.execute.call_args.args[1]
    sql = sql.replace("%(worker_id)s", f"'{parameters['worker_id']}'")
    sql = sql.replace("%(lease_seconds)s", str(parameters["lease_seconds"]))
    return sql[: sql.index("returning")]


def verify_probe() -> str:
    text = VERIFY.read_text()
    found = re.search(
        r'allow "\$WORKER_USER" "may run the claim as written" \\\n\s*"(.*?)" \\\n\s*""',
        text,
        re.DOTALL,
    )
    if found is None:
        raise AssertionError("03-verify no longer states its claim probe in the shape this reads")
    return found.group(1)


class TheProbeIsTheClaim(unittest.TestCase):
    def test_the_same_statement_but_for_its_constants_and_its_answer(self) -> None:
        self.assertEqual(words(verify_probe()), words(worker_claim()))


if __name__ == "__main__":
    unittest.main()
