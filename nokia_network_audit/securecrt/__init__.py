"""SecureCRT button integration for the standalone Nokia network audit.

The module here is not imported by the audit package itself. It is loaded by
SecureCRT's embedded interpreter when the toolbar button fires, so it must stay
importable without any third-party dependency.
"""
