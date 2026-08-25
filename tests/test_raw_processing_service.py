"""Tests for front-end-neutral raw transcript processing."""
from pathlib import Path
from unittest.mock import MagicMock, patch

from gui.raw_frame import AUTO_DETECT_NOKIA
from services.raw_processing_service import RawProcessingRequest, load_raw_sources, run_raw_processing


def test_load_raw_sources_uses_device_id_for_single_text_file(tmp_path) -> None:
    source = tmp_path / "capture.txt"
    source.write_text("Nokia-4L\nshow system", encoding="utf-8")
    assert load_raw_sources(source, "SITE-01") == {
        "SITE-01": "Nokia-4L\nshow system"
    }


def test_run_raw_processing_routes_psi_to_psi_builder(tmp_path) -> None:
    source = tmp_path / "capture.txt"
    source.write_text("Nokia-4L\nshow system", encoding="utf-8")
    output = tmp_path / "report.xlsx"
    builder = MagicMock()

    def parsed(_text, device_id, _module, outputs, **_kwargs):
        outputs[device_id] = {"inventory": {"DataFrame": MagicMock()}}
        return True

    request = RawProcessingRequest(
        input_path=source,
        output_path=output,
        script_name=AUTO_DETECT_NOKIA,
        device_id="SITE-01",
        customer="Customer",
    )
    with patch("services.raw_processing_service._parse_device", side_effect=parsed):
        outcome = run_raw_processing(
            request, builder=builder, db_cache=MagicMock()
        )

    assert outcome.devices_found == 1
    assert outcome.devices_parsed == 1
    assert outcome.family == "psi"
    builder.build_psi_report_workbook.assert_called_once()
    args, kwargs = builder.build_psi_report_workbook.call_args
    assert args[1] == str(output)
    assert kwargs["customer"] == "Customer"


def test_empty_folder_is_rejected(tmp_path) -> None:
    request = RawProcessingRequest(
        input_path=tmp_path,
        output_path=tmp_path / "report.xlsx",
    )
    try:
        run_raw_processing(request, builder=MagicMock(), db_cache=MagicMock())
    except RuntimeError as exc:
        assert "No raw transcript" in str(exc)
    else:
        raise AssertionError("empty folder should fail")
