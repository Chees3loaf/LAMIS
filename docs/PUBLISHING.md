# ATLAS publication branch

The PySide6 release lineage is `LAMIS_2.0 -> ATLAS`. At the August 25, 2026
publication audit, `ATLAS` was zero commits behind and 27 commits ahead of
`LAMIS_2.0`.

Do not merge or rebase `ATLAS` onto the repository's current `main` cleanup
line. That line independently deletes the Qt application, service boundaries,
tests, templates, and RLS implementation, so it is not a compatible release
base. Publish `ATLAS` from its existing `LAMIS_2.0` ancestry, or first replace
`main` through an explicitly reviewed repository-level cutover.

Before publishing, verify:

1. The working tree contains no operator workbooks or generated reports.
2. `python main.py` opens the Qt application.
3. `python main.py --tk-legacy` opens the fallback interface.
4. The focused Qt and workflow regression suites pass.
5. The packaged executable is smoke-tested on a Windows workstation.
