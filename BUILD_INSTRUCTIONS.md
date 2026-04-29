# LAMIS Build & Deployment Guide

This guide covers building LAMIS into a professional Windows installer.

## Prerequisites

### 1. Install NSIS (Nullsoft Scriptable Install System)
- Download: https://nsis.sourceforge.io/Download
- Version: 3.x or later
- After install, verify: `makensis /version` in command prompt

### 2. Verify All Dependencies
```bash
pip install -r requirements.txt
```

For **hardened, supply-chain-verified installs** (recommended for production
builds), use the hash-pinned lock file instead:

```bash
pip install --require-hashes -r requirements.lock
```

Regenerate the lock file after upgrading any package in `requirements.txt`:

```bash
python scripts/generate_requirements_lock.py
```

The lock file is platform-specific (it pins wheel hashes for the active Python
version and OS). Commit the regenerated file alongside the corresponding
`requirements.txt` change.

### 3. Prepare Icon (Optional but Recommended)
- Create or provide `icon.ico` in the project root (256×256 pixels minimum)
- If not present, build will proceed without icon

## Build Process

### Step 1: Build Onedir Executable

```bash
# Simple: build using provided script
build.bat

# Or manual with full control:
pyinstaller --onedir --windowed --name "LAMIS" ^
  --add-data "L.A.M.I.S Logo.png:." ^
  --add-data "data:data" ^
  --collect-all paramiko ^
  --collect-all openpyxl ^
  --collect-all pandas ^
  --collect-all PIL ^
  --icon icon.ico ^
  main.py
```

**Output:** `dist/LAMIS/` folder containing:
- `LAMIS.exe` — main executable
- All dependencies (numpy, pandas, paramiko, etc.)
- Bundled `data/` folder with templates
- Bundled `L.A.M.I.S Logo.png`

### Step 2: Test Executable Locally

```bash
# Test the built executable
dist/LAMIS/LAMIS.exe
```

Verify:
- ✅ GUI loads correctly
- ✅ Logo displays on splash screen
- ✅ Can scan devices (if network available)
- ✅ Can generate inventory workbooks
- ✅ Packing slip modes work

### Step 3: Build Installer

```bash
# Install NSIS (one-time)
choco install nsis -y
# or download from https://nsis.sourceforge.io/Download

# Build installer
makensis LAMIS.nsi
```

**Output:** `dist/LAMIS_Setup.exe` (~120-150MB)

### Step 4: Test Installer

```bash
# Run installer
dist/LAMIS_Setup.exe

# Uninstall and verify
# Control Panel → Programs → Programs and Features → LAMIS → Uninstall
```

Verify:
- ✅ Installer starts cleanly
- ✅ Installs to `C:\Program Files\LAMIS\`
- ✅ Desktop shortcut created
- ✅ Start Menu shortcuts created
- ✅ Uninstaller works cleanly

## Deployment

### For Internal Team (No Signing Needed)

Simply build and share:

```bash
# Build installer
build.bat
makensis LAMIS.nsi
```

**Distribution:**
- Email: `dist/LAMIS_Setup.exe`
- Shared drive: `\\company\software\LAMIS_Setup.exe`
- Company portal or wiki

**First Run:**
- Users may see: "Windows protected your PC - Unknown publisher"
- They click: **More info** → **Run anyway** (1 extra click, normal for internal tools)
- After first run, Windows trusts it

---

### For External Distribution (Professional Deployment)

If you later distribute to external users, add code signing (see **Code Signing** section below)

## Troubleshooting

### Build Issues

**Issue:** `PyInstaller not found`
```bash
pip install pyinstaller
```

**Issue:** `Data files not found`
- Verify `L.A.M.I.S Logo.png` exists in project root
- Verify `data/` folder contains `.xlsx` files
- Run `build.bat` from project root directory

**Issue:** Icon not appearing
- Ensure `icon.ico` is in project root
- Verify dimensions (at least 256×256)
- Rebuild with `build.bat`

### Runtime Issues

**Issue:** `Logo doesn't display in built exe`
- Root cause: Resource path mismatch in `main.py`
- Fix: Ensure bundled file is at `L.A.M.I.S Logo.png` (exact name)
- Verify in built exe: `dist/LAMIS/L.A.M.I.S Logo.png` exists

**Issue:** Templates missing when generating inventory**
- Verify: `dist/LAMIS/data/` contains all `.xlsx` files
- Check: SQLite database (`network_inventory.db`) exists
- Rebuild if missing

**Issue:** Slow startup (3-5 seconds)**
- Normal for onedir with dependencies
- First launch creates Python bytecode cache
- Subsequent launches faster

### Installer Issues

**Issue:** `makensis command not found`
- NSIS not installed or not in PATH
- Install from: https://nsis.sourceforge.io/Download
- Restart command prompt after install

**Issue:** `Cannot find dist/LAMIS`
- Run `build.bat` first to generate dist folder
- Verify build completed with: `dir dist/LAMIS/LAMIS.exe`

## Cleanup

```bash
# Clean old builds before rebuilding
build.bat --clean

# Or manually
rmdir /s /q dist
rmdir /s /q build
del LAMIS.spec
```

## File Checklist

Before distributing, verify these files exist:

```
LAMIS/
├── dist/LAMIS_Setup.exe              ← Installer (ready for distribution)
├── dist/LAMIS/                       ← Built application (testing)
│   ├── LAMIS.exe
│   ├── L.A.M.I.S Logo.png
│   ├── data/
│   │   ├── network_inventory.db
│   │   ├── LAMIS_Packing_Slip.xlsx
│   │   ├── LAMIS_Consolidated_Packing_Slip.xlsx
│   │   └── Device_Report_Template.xlsx
│   └── _internal/                    ← All dependencies
├── build.bat                         ← Build script
├── LAMIS.nsi                         ← Installer script
└── icon.ico                          ← (Optional, for branding)
```

## Version Updates

When releasing a new version:
1. Update version in `config.py` (if applicable)
2. Update version in `LAMIS.nsi` (VIProductVersion)
3. Run `build.bat --clean` to force rebuild
4. Build installer: `makensis LAMIS.nsi`
5. Test installer
6. Rename: `LAMIS_Setup.exe` → `LAMIS_Setup_v1.0.0.exe` (for releases)

## Code Signing (For IT Department Trust)

Code signing prevents Windows Defender/SmartScreen warnings and tells IT that LAMIS is from a trusted publisher. **Required if your IT department enforces signed software policies.**

### Prerequisites

**1. Get a Code Signing Certificate**

Contact your IT department first — they may already have one via:
- Internal PKI / Active Directory Certificate Services (free)
- Company DigiCert/Sectigo subscription (ask IT)

If purchasing independently:
- **DigiCert** — https://www.digicert.com/code-signing (~$150-300/year)
- **Sectigo** — https://sectigo.com/ssl-certificates/code-signing

**2. Install Windows SDK (for signtool.exe)**

```bash
choco install windows-sdk -y
```

Or download: https://aka.ms/buildtools

**3. Have your .pfx certificate file ready**

Your certificate will be provided as a `.pfx` file with a password.

---

### Build & Sign (All-in-One)

```bash
# Build + sign everything in one command
build.bat --sign "certs\LightRiver_codesign.pfx"

# Clean build + sign
build.bat --clean --sign "certs\LightRiver_codesign.pfx"
```

Enter password when prompted. Output:
- `dist/LAMIS/LAMIS.exe` — signed executable
- `dist/LAMIS_Setup.exe` — signed installer (no SmartScreen warning)

---

### Sign Separately (If Already Built)

```bash
# Sign both exe and installer
sign.bat "certs\LightRiver_codesign.pfx"

# Sign only the installer
sign.bat "certs\LightRiver_codesign.pfx" --installer-only
```

---

### What IT Will See

After signing, Windows shows:
- ✅ **Verified Publisher:** Lightriver Technologies
- ✅ **No SmartScreen warning**
- ✅ **Passes Group Policy enforcement** (if configured for signed code only)

---

### Storing the Certificate Securely

- Keep `.pfx` file in a secure, non-committed location (not in git repo)
- Add `certs/` to `.gitignore`
- IT may prefer storing the cert in **Windows Certificate Store** instead of a file — ask them

```bash
# Add to .gitignore
echo certs/ >> .gitignore
```

## Support Resources

- **PyInstaller Docs:** https://pyinstaller.org/en/stable/
- **NSIS Docs:** https://nsis.sourceforge.io/Docs/
- **Python Packaging:** https://packaging.python.org/
