"""pentra-report — Report generation for Pentra AI.

Exports:
    ReportGenerator  — main entry point
    ReportFormat     — enum: markdown | html | pdf | h1
    ReportData       — input data model
"""

from pentra_report.generator import ReportData, ReportFormat, ReportGenerator

__all__ = ["ReportGenerator", "ReportFormat", "ReportData"]
