"""Tests for the Qt-facing BOM Build service boundary."""
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from services.bom_build_service import run_bom_build


def test_run_bom_build_delegates_to_production_engine(tmp_path) -> None:
    source = tmp_path / "inventory.xlsx"
    source.touch()
    output = tmp_path / "inventory.BOM.xlsx"
    builder = MagicMock()

    with patch("services.bom_build_service.BomFrame._build", return_value=str(output)) as build:
        result = run_bom_build(source, builder=builder)

    assert result == output
    build.assert_called_once_with(str(source))


def test_run_bom_build_rejects_invalid_input(tmp_path) -> None:
    with pytest.raises(FileNotFoundError):
        run_bom_build(tmp_path / "missing.xlsx", builder=MagicMock())

    text_file = tmp_path / "inventory.txt"
    text_file.touch()
    with pytest.raises(ValueError, match="xlsx"):
        run_bom_build(text_file, builder=MagicMock())
