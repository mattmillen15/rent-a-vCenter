# rent-a-vcenter

vCenter SAML golden ticket attack — forge an admin session from a stolen `data.mdb` backup file, enumerate VMs, snapshot guest memory, and extract credentials without knowing any password.

## Attack chain

```
data.mdb (from backup share, vCenter backup, or datastore)
    │
    ▼
Extract IdP signing key + solution user creds
    │
    ▼
Forge SAML admin assertion  →  VSPHERE-UI-JSESSIONID
    │
    ▼
WS-Trust STS exchange  →  vmware_soap_session (passwordless)
    │
    ▼
Enumerate VMs via SOAP PropertyCollector
    │
    ▼
Snapshot guest memory (CreateSnapshot_Task)
    │
    ▼
Download .vmem + .vmsn via datastore HTTPS browser
    │
    ▼
vmkatz → NT hashes, plaintext passwords, Kerberos tickets
```

## Usage

```
python3 vcenter_pwn.py TARGET --local-path PATH [options]

positional:
  TARGET                vCenter IP or hostname

required:
  --local-path PATH     data.mdb file, directory, or archive containing it

options:
  --smb //HOST/SHARE    SMB share to crawl for backup files
  --out DIR             Output directory (default: ./loot)
  --timeout SECONDS     Snapshot task timeout (default: 600)
  -u USER               SSO username (default: administrator)
  -p PASS               vCenter admin password (optional fallback)
  -d DOMAIN             SSO domain (default: extracted from data.mdb)
  -y, --yes             Non-interactive: auto-select all VMs
  -v, --verbose         Verbose output
```

## What it does

1. Extracts the IdP SAML signing key and solution user certificate from `data.mdb`
2. Forges a signed SAML assertion for the vCenter SSO admin account
3. Exchanges it for an authenticated UI session (no password required)
4. Optionally uses the solution user cert for a full SOAP/VIM session
5. Lists running VMs, lets you pick which to dump
6. Checks for existing snapshots on the VM — reuse one or create a new memory snapshot
7. Downloads `.vmem` + `.vmsn` via the datastore HTTPS browser with parallel workers
8. Runs `vmkatz` against the `.vmsn` to extract credentials from LSASS
9. Removes snapshots from the datastore after successful download

## Requirements

```
pip install -r requirements.txt
```

Credential extraction requires [vmkatz](https://github.com/nikaiw/VMkatz) — build from source with Rust:

```bash
git clone https://github.com/nikaiw/VMkatz
cd VMkatz
cargo build --release
cp target/release/vmkatz ~/.local/bin/
```

## Notes

- The `data.mdb` file is VMware's vmdir database, typically found in vCenter backups, NFS datastore backups, or directly at `/storage/db/vmware-vmdir/data.mdb` on the VCSA
- Works against vCenter 6.x, 7.x, and 8.x
- The SAML golden ticket path is passwordless — no SSO admin password needed
- Snapshot removal only happens after `.vmem` is confirmed on disk
