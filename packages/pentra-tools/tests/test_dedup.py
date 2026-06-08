from pentra_tools.recon.dedup import smart_dedup_endpoints


def test_dedup_same_content_fingerprint():
    """Dua endpoint dengan content_length + page_title sama harus di-dedup."""
    endpoints = [
        {"url": "http://t.com/products?id=1", "content_length": 1234, "page_title": "Products"},
        {"url": "http://t.com/products?id=2", "content_length": 1234, "page_title": "Products"},
    ]
    result = smart_dedup_endpoints(endpoints)
    assert len(result) == 1


def test_dedup_different_content_kept():
    """Dua endpoint dengan content berbeda harus keduanya ada."""
    endpoints = [
        {"url": "http://t.com/user/1", "content_length": 500, "page_title": "User Alice"},
        {"url": "http://t.com/user/2", "content_length": 520, "page_title": "User Bob"},
    ]
    result = smart_dedup_endpoints(endpoints)
    assert len(result) == 2


def test_dedup_no_fingerprint_url_fallback():
    """Tanpa fingerprint, fallback ke URL path dedup."""
    endpoints = [
        {"url": "http://t.com/page?id=1"},
        {"url": "http://t.com/page?id=2"},
        {"url": "http://t.com/other"},
    ]
    result = smart_dedup_endpoints(endpoints)
    # /page muncul sekali, /other sekali
    assert len(result) == 2
