"""Tests for PayloadMutator — 20 tests covering all categories and WAF types."""
from __future__ import annotations
import urllib.parse
import pytest
from pentra_tools.mutation.payload_mutator import PayloadMutator, MutationResult


@pytest.fixture
def mutator():
    return PayloadMutator()


# ── MutationResult behaviour ──────────────────────────────────────────────────

def test_mutate_returns_mutation_result(mutator):
    result = mutator.mutate("' OR 1=1--")
    assert isinstance(result, MutationResult)


def test_original_always_first_in_all_payloads(mutator):
    payload = "1' AND SLEEP(5)--"
    result = mutator.mutate(payload, waf_type="cloudflare")
    assert result.all_payloads[0] == payload


def test_no_duplicates_in_output(mutator):
    result = mutator.mutate("' OR 1=1--", waf_type="cloudflare")
    payloads = result.all_payloads
    assert len(payloads) == len(set(payloads)), "Duplicates found in output"


# ── URL Encoding ──────────────────────────────────────────────────────────────

def test_url_encoding_single_encode(mutator):
    payload = "' OR 1=1"
    result = mutator.mutate(payload)
    encoded = urllib.parse.quote(payload, safe="")
    assert encoded in result.all_payloads


def test_url_encoding_double_encode(mutator):
    payload = "' OR 1=1"
    result = mutator.mutate(payload)
    encoded = urllib.parse.quote(payload, safe="")
    double = urllib.parse.quote(encoded, safe="")
    assert double in result.all_payloads


def test_url_encoding_partial_encode(mutator):
    payload = "' OR 1=1"
    result = mutator.mutate(payload)
    # Partial: only quotes and spaces encoded
    partial = payload.replace("'", "%27").replace(" ", "%20")
    assert partial in result.all_payloads


# ── Case Variation ────────────────────────────────────────────────────────────

def test_case_variation_sql_keywords(mutator):
    payload = "UNION SELECT 1"
    result = mutator.mutate(payload)
    variants = result.all_payloads
    # At least one variant should have mixed or lower case
    has_case_variant = any(
        v != payload and (v.lower() == payload.lower())
        for v in variants[1:]
    )
    assert has_case_variant, f"No case variant found in {variants}"


def test_case_variation_lowercase(mutator):
    payload = "UNION SELECT 1 FROM users"
    result = mutator.mutate(payload)
    assert payload.lower() in result.all_payloads


# ── Comment Injection ─────────────────────────────────────────────────────────

def test_comment_injection_block_comment(mutator):
    payload = "UNION SELECT 1"
    result = mutator.mutate(payload)
    assert "UNION/**/SELECT/**/1" in result.all_payloads


def test_comment_injection_tab(mutator):
    payload = "UNION SELECT 1"
    result = mutator.mutate(payload)
    assert "UNION%09SELECT%091" in result.all_payloads


def test_comment_injection_newline(mutator):
    payload = "UNION SELECT 1"
    result = mutator.mutate(payload)
    assert "UNION%0aSELECT%0a1" in result.all_payloads


# ── Cloudflare Bypasses ───────────────────────────────────────────────────────

def test_cloudflare_unicode_apostrophe(mutator):
    payload = "' OR 1=1--"
    result = mutator.mutate(payload, waf_type="cloudflare")
    # Unicode fullwidth apostrophe substitution
    has_unicode_apos = any("＇" in p or "＇" in p for p in result.all_payloads)
    assert has_unicode_apos, "No unicode apostrophe variant found"


def test_cloudflare_comment_suffix(mutator):
    payload = "1' AND 1=1--"
    result = mutator.mutate(payload, waf_type="cloudflare")
    assert "1' AND 1=1--+-" in result.all_payloads


def test_cloudflare_carriage_return(mutator):
    payload = "UNION SELECT 1"
    result = mutator.mutate(payload, waf_type="cloudflare")
    assert "UNION\rSELECT\r1" in result.all_payloads


# ── Akamai Bypasses ───────────────────────────────────────────────────────────

def test_akamai_operator_replacement(mutator):
    payload = "1 AND 1=1"
    result = mutator.mutate(payload, waf_type="akamai")
    assert "1 && 1=1" in result.all_payloads


# ── F5 Bypasses ───────────────────────────────────────────────────────────────

def test_f5_unicode_escape(mutator):
    payload = "' OR 1=1"
    result = mutator.mutate(payload, waf_type="f5")
    assert "%u0027 OR 1=1" in result.all_payloads


def test_f5_null_byte(mutator):
    payload = "' OR 1=1"
    result = mutator.mutate(payload, waf_type="f5")
    assert "'%00 OR 1=1" in result.all_payloads


# ── Imperva Bypasses ──────────────────────────────────────────────────────────

def test_imperva_operator_substitution(mutator):
    payload = "1=1"
    result = mutator.mutate(payload, waf_type="imperva")
    assert "1 LIKE 1" in result.all_payloads


# ── Generic Fallback ──────────────────────────────────────────────────────────

def test_generic_fallback_min_3_variants(mutator):
    payload = "' OR 1=1 UNION SELECT 1"
    result = mutator.mutate(payload, waf_type=None)
    # Original + at least 3 generic bypass variants
    assert len(result.all_payloads) >= 4


def test_none_waf_uses_generic(mutator):
    payload = "' OR 1=1"
    result_none = mutator.mutate(payload, waf_type=None)
    result_generic = mutator.mutate(payload, waf_type="generic")
    # Both should produce same number of payloads (same code path)
    assert len(result_none.all_payloads) == len(result_generic.all_payloads)
