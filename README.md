# rent-a-vCenter

vCenter SAML golden ticket — forge an admin session from a stolen `data.mdb`, enumerate VMs, snapshot memory, and pull credentials. No password required.

## Usage

```
python3 rent-a-vcenter.py (--local-path PATH | -t HOST) [options]

source (one required):
  --local-path PATH     data.mdb file, directory, or archive
  -t HOST               SMB target — bare host enumerates all shares,
                        or full UNC path (\\host\share\path)
                        vCenter address is extracted from data.mdb automatically

options:
  -u USER               username for SMB auth / SSO fallback
  -p PASS               password for SMB auth / SSO fallback
  -d DOMAIN             domain for SMB auth / SSO override
  --out DIR             output directory (default: ./loot)
  --timeout SECONDS     snapshot task timeout (default: 600)
  -v                    verbose
```

## Setup

```bash
./install.sh
```

Installs Python dependencies, builds [vmkatz](https://github.com/nikaiw/VMkatz) from source, and drops a `rent-a-vcenter` launcher into `~/.local/bin` so you can run it from anywhere.

Requires Python 3.8+ and Rust/cargo (installer will pull Rust via rustup if missing).

## Notes

- `data.mdb` is the vmdir database — found in vCenter backups or at `/storage/db/vmware-vmdir/data.mdb` on the VCSA
- Tested against vCenter 6.x, 7.x, 8.x
- SAML golden ticket path is fully passwordless
