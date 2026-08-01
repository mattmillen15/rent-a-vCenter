# rent-a-vCenter

vCenter SAML golden ticket — forge an admin session from a stolen `data.mdb`, enumerate VMs, snapshot memory, and pull credentials. No password required.

## Usage

```
python3 rent-a-vcenter.py TARGET [--local-path PATH | -t HOST] [options]

positional:
  TARGET                vCenter IP or hostname

source (one required):
  --local-path PATH     data.mdb file, directory, or archive
  -t HOST               SMB target — bare host enumerates all shares,
                        or full UNC path (\\host\share\path)

options:
  -u USER               username for SMB auth / SSO fallback
  -p PASS               password for SMB auth / SSO fallback
  -d DOMAIN             domain for SMB auth / SSO override
  --out DIR             output directory (default: ./loot)
  --timeout SECONDS     snapshot task timeout (default: 600)
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
