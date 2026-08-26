# ATLAS publication branch

The PySide6 application is published from the `ATLAS` branch. The canonical
private repository is `https://github.com/ZeroToil/ATLAS`.

Do not merge or rebase `ATLAS` onto an unrelated cleanup line that deletes the
Qt application, service boundaries, tests, templates, or RLS implementation.
Promote the audited `ATLAS` lineage directly to the new repository's `main`
branch through an explicitly reviewed repository-level cutover.

Before publishing, verify:

1. The working tree contains no operator workbooks or generated reports.
2. `python main.py` opens the Qt application.
3. `python main.py --tk-legacy` opens the fallback interface.
4. The focused Qt and workflow regression suites pass.
5. The packaged executable is smoke-tested on a Windows workstation.
