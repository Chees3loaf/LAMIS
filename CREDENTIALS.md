# Secure Credential Management

ATLAS now supports secure credential storage using encrypted configuration files.

## Setup

### Option 1: Using Command Line (Recommended for Automation)

```bash
python -c "from utils.credentials import setup_credentials_config; setup_credentials_config('admin', 'yourpassword')"
```

This will:
1. Create `credentials_config.json` with encrypted credentials
2. Create `.creds_key` with the encryption key (git-ignored)
3. Set appropriate file permissions (600 - owner read/write only)

### Option 2: Manual Configuration

1. Get the encryption key:
```bash
python -c "from utils.credentials import _get_or_create_key; print(_get_or_create_key().decode())"
```

2. Create `credentials_config.json`:
```json
{
  "credentials": {
    "username": "admin",
    "password": "[ENCRYPTED_PASSWORD_HERE]",
    "encrypted": true
  }
}
```

## How It Works

1. **Encryption**: Passwords are encrypted using Fernet (symmetric encryption from `cryptography` library)
2. **Key Management**: Encryption key is stored in `.creds_key` (git-ignored)
3. **Credential Loading**: The app checks for encrypted credentials in this order:
   - `credentials_config.json` (if present)
   - Windows Credential Manager (keyring)
   - Returns (None, None) if neither found

## Security Notes

- **Never commit** `credentials_config.json` or `.creds_key` to version control
- Both files are already in `.gitignore`
- File permissions are set to 600 (owner read/write only)
- Encryption key is unique per installation
- Credentials are decrypted in memory only when needed

## Changing Credentials

To update credentials:
```bash
python -c "from utils.credentials import setup_credentials_config; setup_credentials_config('newuser', 'newpassword')"
```

## Deleting Credentials

```bash
python -c "from utils.credentials import delete_credentials_config; delete_credentials_config()"
```

## Fallback to Credential Manager

If no config file is present, the app will fall back to Windows Credential Manager (if credentials were previously stored there). This ensures backward compatibility.
