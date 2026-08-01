# rent-a-vCenter

vCenter SAML golden ticket — forge an admin session from a stolen `data.mdb`, enumerate VMs, snapshot memory, and pull credentials. No password required.

## Usage

```
python3 rent-a-vcenter.py TARGET [--local-path PATH | --smb //HOST/SHARE] [options]

positional:
  TARGET                vCenter IP or hostname

source (one required):
  --local-path PATH     data.mdb file, directory, or archive
  --smb //HOST/SHARE    SMB share to crawl for backup files
  --smb-user USER
  --smb-pass PASS

options:
  --out DIR             output directory (default: ./loot)
  --timeout SECONDS     snapshot task timeout (default: 600)
  -d DOMAIN             SSO domain (default: extracted from data.mdb)
  -p PASS               vCenter admin password (optional fallback)
  -y                    non-interactive
  -v                    verbose
```

## Requirements

```
pip install -r requirements.txt
```

Credential extraction requires [vmkatz](https://github.com/nikaiw/VMkatz):

```bash
git clone https://github.com/nikaiw/VMkatz && cd VMkatz
cargo build --release
cp target/release/vmkatz ~/.local/bin/
```

## Notes

- `data.mdb` is the vmdir database — found in vCenter backups or at `/storage/db/vmware-vmdir/data.mdb` on the VCSA
- Tested against vCenter 6.x, 7.x, 8.x
- SAML golden ticket path is fully passwordless
