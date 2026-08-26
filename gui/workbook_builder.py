"""Compatibility import for the legacy Tk package.

The workbook engine is front-end neutral and now lives under ``services``.
"""
from services.workbook_builder import *  # noqa: F401,F403
