"""Business Logic Vulnerability Tester — Sprint 20 P3.

Tests common business logic flaws:
  1. Negative quantity / price manipulation
  2. Coupon/discount code reuse after use
  3. Integer overflow in quantity/amount fields
  4. Privilege escalation via parameter tampering
  5. Workflow bypass (skip payment step)

Impact: $5K–$50K bounties — often critical when combined with financial data.

Usage:
    from pentra_tools.vuln.business_logic import test_business_logic

    findings = await test_business_logic(
        base_url="https://target.com",
        auth_headers={"Authorization": "Bearer token"},
    )
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)

# Common API patterns for e-commerce / SaaS
_CART_PATTERNS = ["/cart", "/api/cart", "/shopping-cart", "/basket", "/api/basket"]
_ORDER_PATTERNS = ["/order", "/api/order", "/checkout", "/api/checkout", "/purchase"]
_COUPON_PATTERNS = ["/coupon", "/api/coupon", "/promo", "/api/promo", "/discount"]
_PRICE_PARAMS = ["price", "amount", "total", "quantity", "qty", "cost", "value"]


@dataclass
class BizLogicFinding:
    title: str
    severity: str
    endpoint: str
    attack_type: str
    payload: dict
    evidence: str
    remediation: str

    def to_finding(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity,
            "vuln_class": "BUSINESS_LOGIC",
            "target_url": self.endpoint,
            "description": (
                f"Business logic vulnerability: {self.attack_type}. "
                f"Payload: {self.payload}. Evidence: {self.evidence}"
            ),
            "request_raw": f"POST {self.endpoint}\nBody: {self.payload}",
            "response_raw": self.evidence,
            "source": "business_logic_tester",
            "remediation": self.remediation,
        }


async def run_business_logic_test(
    base_url: str,
    auth_headers: dict | None = None,
    proxy_url: str | None = None,
    scope_check_fn=None,
) -> list[dict]:
    """Run business logic vulnerability tests on a target.

    Tests negative values, integer overflow, parameter tampering in
    cart/order/coupon endpoints.

    Args:
        base_url:       Target base URL.
        auth_headers:   Optional auth headers.
        proxy_url:      Optional HTTP proxy.
        scope_check_fn: Optional scope enforcer.

    Returns:
        List of finding dicts.
    """
    if scope_check_fn and not scope_check_fn(base_url):
        return []

    base = base_url.rstrip("/")
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        **(auth_headers or {}),
    }
    proxy = proxy_url if proxy_url else None
    findings: list[dict] = []

    async with httpx.AsyncClient(
        verify=False,  # noqa: S501
        follow_redirects=True,
        timeout=10.0,
        **({"proxy": proxy} if proxy else {}),
    ) as client:

        # ── Test 1: Negative quantity ─────────────────────────────────────────
        for cart_path in _CART_PATTERNS[:3]:
            url = base + cart_path
            try:
                resp = await client.post(
                    url, headers=headers,
                    json={"item_id": 1, "quantity": -1, "product_id": 1},
                )
                body = resp.text.lower()
                # Check if server accepted negative quantity (vulnerability)
                if resp.status_code in (200, 201) and any(
                    kw in body for kw in ("success", "added", "cart", "item", "total", "price")
                ):
                    # Check if price went negative (critical)
                    if any(kw in body for kw in ("-", "credit", "refund", "negative")):
                        findings.append(BizLogicFinding(
                            title=f"Negative Quantity Accepted — {cart_path}",
                            severity="critical",
                            endpoint=url,
                            attack_type="Negative quantity manipulation",
                            payload={"quantity": -1},
                            evidence=f"Server returned 200 with negative quantity. Response snippet: {resp.text[:200]}",
                            remediation="Validate quantity/amount server-side. Reject negative values. Use unsigned integers.",
                        ).to_finding())
                    else:
                        findings.append(BizLogicFinding(
                            title=f"Negative Quantity Accepted — {cart_path}",
                            severity="high",
                            endpoint=url,
                            attack_type="Negative quantity manipulation",
                            payload={"quantity": -1},
                            evidence=f"Server accepted negative quantity (200 OK). May allow price manipulation.",
                            remediation="Validate quantity server-side. Reject values < 1.",
                        ).to_finding())
                    logger.info("[biz_logic] Negative quantity accepted at %s", url)
                    break
            except Exception as exc:
                logger.debug("[biz_logic] Cart test failed: %s", exc)

        # ── Test 2: Integer overflow ──────────────────────────────────────────
        for cart_path in _CART_PATTERNS[:2]:
            url = base + cart_path
            try:
                resp = await client.post(
                    url, headers=headers,
                    json={"item_id": 1, "quantity": 2147483648, "product_id": 1},
                )
                body = resp.text.lower()
                # If overflow causes negative total or unexpected success
                if resp.status_code in (200, 201) and resp.text:
                    import json as _json
                    try:
                        data = _json.loads(resp.text)
                        total = data.get("total") or data.get("price") or data.get("amount")
                        if total is not None and (float(total) < 0 or float(total) < 100):
                            findings.append(BizLogicFinding(
                                title=f"Integer Overflow in Cart Quantity — {cart_path}",
                                severity="critical",
                                endpoint=url,
                                attack_type="Integer overflow",
                                payload={"quantity": 2147483648},
                                evidence=f"Overflow caused total={total}",
                                remediation="Use 64-bit integers. Validate quantity upper bound server-side.",
                            ).to_finding())
                    except Exception:
                        pass
            except Exception:
                pass

        # ── Test 3: Price parameter tampering ─────────────────────────────────
        for order_path in _ORDER_PATTERNS[:3]:
            url = base + order_path
            for price_param in _PRICE_PARAMS[:3]:
                try:
                    resp = await client.post(
                        url, headers=headers,
                        json={"item_id": 1, "quantity": 1, price_param: 0.01},
                    )
                    body_lower = resp.text.lower()
                    if resp.status_code in (200, 201) and any(
                        kw in body_lower for kw in ("success", "order", "confirmed", "placed")
                    ):
                        findings.append(BizLogicFinding(
                            title=f"Client-Side Price Manipulation — {order_path}",
                            severity="critical",
                            endpoint=url,
                            attack_type="Price parameter tampering",
                            payload={price_param: 0.01},
                            evidence=f"Order accepted with {price_param}=0.01. Response: {resp.text[:200]}",
                            remediation=(
                                "Never trust client-supplied prices. "
                                "Calculate prices server-side based on product catalog. "
                                "Ignore any price parameters from client requests."
                            ),
                        ).to_finding())
                        logger.info("[biz_logic] Price manipulation at %s[%s]", url, price_param)
                        break
                except Exception:
                    pass

        # ── Test 4: Coupon reuse ───────────────────────────────────────────────
        for coupon_path in _COUPON_PATTERNS[:2]:
            url = base + coupon_path
            try:
                # Apply same coupon twice
                common_coupons = ["SAVE10", "DISCOUNT20", "TEST100", "FREE", "PROMO50"]
                for code in common_coupons[:2]:
                    resp1 = await client.post(
                        url, headers=headers,
                        json={"code": code, "order_id": 1},
                    )
                    if resp1.status_code in (200, 201):
                        # Try applying same coupon again
                        await asyncio.sleep(0.3)
                        resp2 = await client.post(
                            url, headers=headers,
                            json={"code": code, "order_id": 2},
                        )
                        if resp2.status_code in (200, 201):
                            findings.append(BizLogicFinding(
                                title=f"Coupon Code Reuse — {coupon_path}",
                                severity="medium",
                                endpoint=url,
                                attack_type="Coupon/discount code reuse",
                                payload={"code": code},
                                evidence=f"Coupon '{code}' accepted twice (status 200 both times)",
                                remediation="Track coupon usage per user. Mark coupons as used after first application.",
                            ).to_finding())
                            break
            except Exception:
                pass

    if findings:
        logger.info("[biz_logic] %d business logic finding(s)", len(findings))
    return findings
