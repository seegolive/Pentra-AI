"""Tests for tasks.maintenance module."""
from __future__ import annotations

import subprocess
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_completed_proc(stdout="", stderr="", returncode=0):
    proc = MagicMock()
    proc.stdout = stdout
    proc.stderr = stderr
    proc.returncode = returncode
    return proc


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestUpdateNucleiTemplatesSuccess:
    def test_returns_success_status(self, tmp_path):
        with (
            patch("app.tasks.maintenance.subprocess.run") as mock_run,
            patch("app.tasks.maintenance._count_nuclei_templates", side_effect=[10, 15]),
            patch("app.tasks.maintenance.asyncio.run"),
        ):
            mock_run.return_value = _make_completed_proc(stdout="Updated templates")
            from app.tasks.maintenance import update_nuclei_templates
            result = update_nuclei_templates.run()

        assert result["status"] == "success"
        assert result["new_templates"] == 5
        assert result["templates_before"] == 10
        assert result["templates_after"] == 15
        assert "timestamp" in result

    def test_new_templates_count_is_non_negative(self):
        """If count_after < count_before (edge case), new_templates is 0."""
        with (
            patch("app.tasks.maintenance.subprocess.run") as mock_run,
            patch("app.tasks.maintenance._count_nuclei_templates", side_effect=[20, 15]),
            patch("app.tasks.maintenance.asyncio.run"),
        ):
            mock_run.return_value = _make_completed_proc()
            from app.tasks.maintenance import update_nuclei_templates
            result = update_nuclei_templates.run()

        assert result["new_templates"] == 0

    def test_stdout_truncated_to_500_chars(self):
        long_output = "x" * 2000
        with (
            patch("app.tasks.maintenance.subprocess.run") as mock_run,
            patch("app.tasks.maintenance._count_nuclei_templates", return_value=5),
            patch("app.tasks.maintenance.asyncio.run"),
        ):
            mock_run.return_value = _make_completed_proc(stdout=long_output)
            from app.tasks.maintenance import update_nuclei_templates
            result = update_nuclei_templates.run()

        assert len(result["stdout"]) <= 500


class TestUpdateNucleiTemplatesTimeout:
    def test_returns_timeout_status(self):
        with patch("app.tasks.maintenance.subprocess.run", side_effect=subprocess.TimeoutExpired("nuclei", 300)):
            from app.tasks.maintenance import update_nuclei_templates
            result = update_nuclei_templates.run()

        assert result["status"] == "timeout"
        assert "timestamp" in result


class TestUpdateNucleiTemplatesNotFound:
    def test_returns_nuclei_not_found_status(self):
        with patch("app.tasks.maintenance.subprocess.run", side_effect=FileNotFoundError("nuclei")):
            from app.tasks.maintenance import update_nuclei_templates
            result = update_nuclei_templates.run()

        assert result["status"] == "nuclei_not_found"
        assert "timestamp" in result


class TestCountTemplates:
    def test_counts_non_bracket_lines(self):
        mock_output = "template1\ntemplate2\n[INFO] something\ntemplate3\n"
        with patch(
            "app.tasks.maintenance.subprocess.run",
            return_value=_make_completed_proc(stdout=mock_output),
        ):
            from app.tasks.maintenance import _count_nuclei_templates
            count = _count_nuclei_templates()

        assert count == 3

    def test_returns_zero_on_exception(self):
        with patch("app.tasks.maintenance.subprocess.run", side_effect=OSError("fail")):
            from app.tasks.maintenance import _count_nuclei_templates
            count = _count_nuclei_templates()

        assert count == 0


class TestBroadcastCalledOnSuccess:
    def test_broadcast_called_after_success(self):
        with (
            patch("app.tasks.maintenance.subprocess.run") as mock_run,
            patch("app.tasks.maintenance._count_nuclei_templates", return_value=10),
            patch("app.tasks.maintenance.asyncio.run") as mock_asyncio_run,
        ):
            mock_run.return_value = _make_completed_proc()
            from app.tasks.maintenance import update_nuclei_templates
            update_nuclei_templates.run()

        # asyncio.run should have been called to trigger the broadcast coroutine
        mock_asyncio_run.assert_called_once()

    def test_broadcast_not_called_on_timeout(self):
        with (
            patch("app.tasks.maintenance.subprocess.run", side_effect=subprocess.TimeoutExpired("nuclei", 300)),
            patch("app.tasks.maintenance.asyncio.run") as mock_asyncio_run,
        ):
            from app.tasks.maintenance import update_nuclei_templates
            update_nuclei_templates.run()

        mock_asyncio_run.assert_not_called()
