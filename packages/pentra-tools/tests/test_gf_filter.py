from pentra_tools.recon.gf_filter import apply_gf_patterns, prioritize_endpoints_for_vuln_hunt


def test_sqli_pattern_matches_integer_param():
    urls = ["http://target.com/products.aspx?id=1"]
    matches = apply_gf_patterns(urls)
    assert len(matches) == 1
    assert matches[0].matched_pattern == "sqli_int"
    assert matches[0].priority == 1


def test_lfi_pattern_matches_file_param():
    urls = ["http://target.com/view?page=home"]
    matches = apply_gf_patterns(urls, patterns=["lfi"])
    assert any(m.matched_pattern == "lfi" for m in matches)


def test_ssrf_pattern_matches_url_param():
    urls = ["http://target.com/fetch?url=http://internal"]
    matches = apply_gf_patterns(urls, patterns=["ssrf"])
    assert len(matches) == 1
    assert matches[0].priority == 1


def test_backup_extension_priority_1():
    urls = ["http://target.com/config.bak", "http://target.com/db.sql"]
    matches = apply_gf_patterns(urls, patterns=["interesting_ext"])
    assert len(matches) == 2
    assert all(m.priority == 1 for m in matches)


def test_priority_ordering_critical_first():
    urls = [
        "http://t.com/search?q=test",        # xss → priority 2
        "http://t.com/products?id=1",         # sqli_int → priority 1
        "http://t.com/view?path=/etc",        # path_traversal → priority 3
    ]
    matches = apply_gf_patterns(urls)
    priorities = [m.priority for m in matches]
    assert priorities == sorted(priorities), "Should be sorted priority asc"


def test_prioritize_enriches_endpoint_with_vuln_hint():
    endpoints = [
        {"url": "http://t.com/products?id=1", "method": "GET"},
        {"url": "http://t.com/about", "method": "GET"},
    ]
    result = prioritize_endpoints_for_vuln_hunt(endpoints)
    matched = next((e for e in result if e.get("gf_pattern")), None)
    assert matched is not None
    assert matched["vuln_hint"] != ""
    assert matched["gf_priority"] == 1


def test_unmatched_endpoints_at_end():
    endpoints = [
        {"url": "http://t.com/about"},            # no match
        {"url": "http://t.com/page?id=1"},        # sqli_int match
    ]
    result = prioritize_endpoints_for_vuln_hunt(endpoints)
    assert result[0].get("gf_pattern") is not None, "Matched should be first"
    assert result[-1].get("gf_pattern") is None, "Unmatched should be last"
