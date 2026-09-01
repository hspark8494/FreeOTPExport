#!/usr/bin/env python3
"""
freeotp_export.py - Convert a FreeOTP (Android) backup back into otpauth:// URIs and QR codes.

Accepted inputs:
  * externalBackup.xml written by the app's Backup menu. Despite the extension it is a
    Java-serialized HashMap (ObjectOutputStream), not XML.
  * shared_prefs/tokenBackup.xml pulled from the device (real SharedPreferences XML).

Decryption mirrors encryptor/MasterKey.java, encryptor/EncryptedKey.java and TokenPersistence.java:
  password  -> PBKDF2-HMAC-SHA512(salt, iterations)   -> password key
  password key -> AES-GCM (AAD = "AES")              -> master key
  master key   -> AES-GCM (AAD = "HmacSHA1" etc.)    -> token HMAC secret -> Base32 -> otpauth://

Dependencies: cryptography (required), segno (QR output).
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import html
import io
import json
import os
import re
import struct
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import quote

# --------------------------------------------------------------------------- #
# Java serialization reader (enough for HashMap<String, String|Boolean|Number>)
# --------------------------------------------------------------------------- #

TC_NULL, TC_REFERENCE, TC_CLASSDESC, TC_OBJECT, TC_STRING, TC_ARRAY, TC_CLASS = (
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76)
TC_BLOCKDATA, TC_ENDBLOCKDATA, TC_RESET, TC_BLOCKDATALONG = 0x77, 0x78, 0x79, 0x7A
TC_EXCEPTION, TC_LONGSTRING, TC_PROXYCLASSDESC, TC_ENUM = 0x7B, 0x7C, 0x7D, 0x7E
BASE_WIRE_HANDLE = 0x7E0000
SC_WRITE_METHOD, SC_SERIALIZABLE, SC_EXTERNALIZABLE, SC_BLOCK_DATA = 1, 2, 4, 8

BOXED = {
    "java.lang.Boolean", "java.lang.Integer", "java.lang.Long", "java.lang.Float",
    "java.lang.Double", "java.lang.Short", "java.lang.Byte", "java.lang.Character",
}
MAP_CLASSES = {"java.util.HashMap", "java.util.LinkedHashMap", "java.util.Hashtable",
               "java.util.TreeMap", "java.util.concurrent.ConcurrentHashMap"}


@dataclass
class _ClassDesc:
    name: str
    flags: int
    fields: list
    super_desc: Optional["_ClassDesc"]


@dataclass
class _JavaObject:
    cls: str
    fields: dict = field(default_factory=dict)
    annotations: list = field(default_factory=list)


class _BlockData(bytes):
    pass


class JavaDeserializer:
    def __init__(self, data: bytes):
        self.f = io.BytesIO(data)
        self.handles: list = []

    def _read(self, n: int) -> bytes:
        b = self.f.read(n)
        if len(b) != n:
            raise ValueError("Unexpected end of Java serialization stream")
        return b

    def _u1(self): return self._read(1)[0]
    def _u2(self): return struct.unpack(">H", self._read(2))[0]
    def _i4(self): return struct.unpack(">i", self._read(4))[0]
    def _i8(self): return struct.unpack(">q", self._read(8))[0]

    @staticmethod
    def _decode_mutf8(b: bytes) -> str:
        s = b.replace(b"\xc0\x80", b"\x00").decode("utf-8", errors="surrogatepass")
        return s.encode("utf-16", "surrogatepass").decode("utf-16")

    def _utf(self) -> str:
        return self._decode_mutf8(self._read(self._u2()))

    def _long_utf(self) -> str:
        return self._decode_mutf8(self._read(self._i8()))

    def _new_handle(self, obj) -> int:
        self.handles.append(obj)
        return len(self.handles) - 1

    def read_stream(self):
        if self._u2() != 0xACED or self._u2() != 5:
            raise ValueError("Not a Java serialization stream (missing AC ED 00 05)")
        return self.read_content()

    def read_content(self, tc: Optional[int] = None):
        if tc is None:
            tc = self._u1()
        if tc == TC_NULL:
            return None
        if tc == TC_REFERENCE:
            return self.handles[self._i4() - BASE_WIRE_HANDLE]
        if tc == TC_STRING:
            s = self._utf()
            self._new_handle(s)
            return s
        if tc == TC_LONGSTRING:
            s = self._long_utf()
            self._new_handle(s)
            return s
        if tc in (TC_CLASSDESC, TC_PROXYCLASSDESC):
            return self._read_classdesc(tc)
        if tc == TC_OBJECT:
            return self._read_object()
        if tc == TC_ARRAY:
            return self._read_array()
        if tc == TC_ENUM:
            self._read_classdesc()
            h = self._new_handle(None)
            name = self.read_content()
            self.handles[h] = name
            return name
        if tc == TC_CLASS:
            desc = self._read_classdesc()
            self._new_handle(desc)
            return desc
        if tc == TC_BLOCKDATA:
            return _BlockData(self._read(self._u1()))
        if tc == TC_BLOCKDATALONG:
            return _BlockData(self._read(self._i4()))
        if tc == TC_RESET:
            self.handles.clear()
            return self.read_content()
        if tc == TC_EXCEPTION:
            raise ValueError("Serialization stream contains TC_EXCEPTION")
        raise ValueError(f"Unsupported Java serialization type code 0x{tc:02x}")

    def _read_classdesc(self, tc: Optional[int] = None) -> Optional[_ClassDesc]:
        if tc is None:
            tc = self._u1()
        if tc == TC_NULL:
            return None
        if tc == TC_REFERENCE:
            return self.handles[self._i4() - BASE_WIRE_HANDLE]
        if tc == TC_PROXYCLASSDESC:
            desc = _ClassDesc("$Proxy", SC_SERIALIZABLE, [], None)
            self._new_handle(desc)
            for _ in range(self._i4()):
                self._utf()
            self._skip_annotations()
            desc.super_desc = self._read_classdesc()
            return desc
        if tc != TC_CLASSDESC:
            raise ValueError(f"Expected classDesc, got 0x{tc:02x}")
        name = self._utf()
        self._i8()  # serialVersionUID
        desc = _ClassDesc(name, 0, [], None)
        self._new_handle(desc)
        desc.flags = self._u1()
        for _ in range(self._u2()):
            typecode = chr(self._u1())
            fname = self._utf()
            if typecode in "L[":
                self.read_content()  # field type name
            desc.fields.append((typecode, fname))
        self._skip_annotations()
        desc.super_desc = self._read_classdesc()
        return desc

    def _skip_annotations(self):
        while True:
            tc = self._u1()
            if tc == TC_ENDBLOCKDATA:
                return
            self.read_content(tc)

    def _read_annotations(self) -> list:
        items = []
        while True:
            tc = self._u1()
            if tc == TC_ENDBLOCKDATA:
                return items
            items.append(self.read_content(tc))

    def _read_prim(self, typecode: str):
        return {
            "B": lambda: struct.unpack(">b", self._read(1))[0],
            "C": lambda: chr(self._u2()),
            "D": lambda: struct.unpack(">d", self._read(8))[0],
            "F": lambda: struct.unpack(">f", self._read(4))[0],
            "I": self._i4,
            "J": self._i8,
            "S": lambda: struct.unpack(">h", self._read(2))[0],
            "Z": lambda: self._u1() != 0,
        }[typecode]()

    def _read_object(self):
        desc = self._read_classdesc()
        obj = _JavaObject(desc.name)
        h = self._new_handle(obj)

        chain = []
        d = desc
        while d is not None:
            chain.append(d)
            d = d.super_desc
        for d in reversed(chain):
            if d.flags & SC_SERIALIZABLE:
                for typecode, fname in d.fields:
                    obj.fields[fname] = (self._read_prim(typecode) if typecode not in "L["
                                         else self.read_content())
                if d.flags & SC_WRITE_METHOD:
                    obj.annotations.extend(self._read_annotations())
            elif d.flags & SC_EXTERNALIZABLE:
                if not d.flags & SC_BLOCK_DATA:
                    raise ValueError("Legacy Externalizable format is not supported")
                obj.annotations.extend(self._read_annotations())

        result = self._simplify(obj)
        self.handles[h] = result
        return result

    def _read_array(self):
        desc = self._read_classdesc()
        arr: list = []
        h = self._new_handle(arr)
        n = self._i4()
        comp = desc.name[1]
        if comp in "L[":
            arr.extend(self.read_content() for _ in range(n))
        elif comp == "B":
            b = bytes(self._read(n))
            self.handles[h] = b
            return b
        else:
            arr.extend(self._read_prim(comp) for _ in range(n))
        return arr

    @staticmethod
    def _simplify(obj: _JavaObject):
        if obj.cls in BOXED:
            return obj.fields.get("value")
        if obj.cls in MAP_CLASSES:
            items = [x for x in obj.annotations if not isinstance(x, _BlockData)]
            if len(items) % 2:
                raise ValueError("Malformed Map entries in serialization stream")
            return {items[i]: items[i + 1] for i in range(0, len(items), 2)}
        return obj


# --------------------------------------------------------------------------- #
# Backup loading
# --------------------------------------------------------------------------- #

def load_backup(path: str) -> dict[str, Any]:
    with open(path, "rb") as fh:
        data = fh.read()

    if data[:2] == b"\xac\xed":
        m = JavaDeserializer(data).read_stream()
        if not isinstance(m, dict):
            raise ValueError("Top-level serialized object is not a Map")
        return m

    root = ET.fromstring(data)
    out: dict[str, Any] = {}
    for el in root:
        name = el.get("name")
        if name is None:
            continue
        if el.tag == "string":
            out[name] = el.text or ""
        elif el.tag == "boolean":
            out[name] = el.get("value") == "true"
        elif el.tag in ("int", "long"):
            out[name] = int(el.get("value"))
        elif el.tag == "float":
            out[name] = float(el.get("value"))
    return out


# --------------------------------------------------------------------------- #
# Decryption
# --------------------------------------------------------------------------- #

def _jbytes(v) -> bytes:
    """Gson serializes byte[] as a list of signed ints."""
    if isinstance(v, str):
        return base64.b64decode(v)
    return bytes(b & 0xFF for b in v)


def _der_len(buf: bytes, i: int) -> tuple[int, int]:
    n = buf[i]
    i += 1
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(buf[i:i + k], "big")
        i += k
    return n, i


def parse_gcm_parameters(der: bytes) -> tuple[bytes, int]:
    """RFC 5084 GCMParameters ::= SEQUENCE { nonce OCTET STRING, tagLen INTEGER DEFAULT 12 }"""
    if der[0] != 0x30:
        raise ValueError("GCM parameters are not a DER SEQUENCE")
    _, i = _der_len(der, 1)
    if der[i] != 0x04:
        raise ValueError("GCM parameters missing nonce OCTET STRING")
    n, i = _der_len(der, i + 1)
    nonce = der[i:i + n]
    i += n
    tag_len = 12
    if i < len(der) and der[i] == 0x02:
        n, i = _der_len(der, i + 1)
        tag_len = int.from_bytes(der[i:i + n], "big")
    return nonce, tag_len


def aes_gcm_decrypt(key: bytes, params_der: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    nonce, tag_len = parse_gcm_parameters(params_der)
    ct, tag = ciphertext[:-tag_len], ciphertext[-tag_len:]
    dec = Cipher(algorithms.AES(key), modes.GCM(nonce, tag, min_tag_length=tag_len)).decryptor()
    dec.authenticate_additional_data(aad)
    return dec.update(ct) + dec.finalize()


def decrypt_encrypted_key(ek: dict, key: bytes) -> bytes:
    if ek.get("mCipher", "AES/GCM/NoPadding") != "AES/GCM/NoPadding":
        raise ValueError(f"Unsupported cipher: {ek.get('mCipher')}")
    return aes_gcm_decrypt(key, _jbytes(ek["mParameters"]), _jbytes(ek["mCipherText"]),
                           ek["mToken"].encode("utf-8"))


def derive_master_key(master: dict, password: str) -> bytes:
    salt = _jbytes(master["mSalt"])
    m = re.search(r"HmacSHA(\d+)", master.get("mAlgorithm", "PBKDF2withHmacSHA512"))
    digest = "sha" + (m.group(1) if m else "512")
    pwd_key = hashlib.pbkdf2_hmac(digest, password.encode("utf-8"), salt,
                                  int(master["mIterations"]), dklen=len(salt))
    return decrypt_encrypted_key(master["mEncryptedKey"], pwd_key)


# --------------------------------------------------------------------------- #
# Tokens
# --------------------------------------------------------------------------- #

STEAM_ALPHABET = "23456789BCDFGHJKMNPQRTVWXY"
TEMPLATE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "template.html")


@dataclass
class OtpToken:
    uuid: str
    type: str
    issuer: Optional[str]
    label: str
    secret: bytes
    algorithm: str
    digits: int
    period: int
    counter: Optional[int]
    extras: dict

    @property
    def secret_b32(self) -> str:
        return base64.b32encode(self.secret).decode("ascii").rstrip("=")

    @property
    def display_name(self) -> str:
        return f"{self.issuer} ({self.label})" if self.issuer else self.label

    def uri(self, include_extras: bool = False) -> str:
        label = f"{self.issuer}:{self.label}" if self.issuer else self.label
        params = [("secret", self.secret_b32)]
        if self.issuer:
            params.append(("issuer", self.issuer))
        params += [("algorithm", self.algorithm), ("digits", str(self.digits))]
        if self.type == "TOTP":
            params.append(("period", str(self.period)))
        else:
            params.append(("counter", str(self.counter or 0)))
        if include_extras:
            params += [(k, str(v).lower() if isinstance(v, bool) else str(v))
                       for k, v in self.extras.items() if v is not None]
        q = "&".join(f"{k}={quote(v, safe='')}" for k, v in params)
        return f"otpauth://{self.type.lower()}/{quote(label, safe='@:')}?{q}"

    def code(self, now: Optional[float] = None) -> str:
        if self.type == "TOTP":
            moving = int((now if now is not None else time.time()) // self.period)
        else:
            moving = self.counter or 0
        digest = getattr(hashlib, self.algorithm.lower())
        mac = hmac.new(self.secret, struct.pack(">Q", moving), digest).digest()
        off = mac[-1] & 0x0F
        binary = struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF
        if self.issuer == "Steam":
            out = []
            for _ in range(self.digits):
                out.append(STEAM_ALPHABET[binary % len(STEAM_ALPHABET)])
                binary //= len(STEAM_ALPHABET)
            return "".join(out)
        return str(binary % (10 ** self.digits)).zfill(self.digits)


def extract_tokens(backup: dict[str, Any], password: str) -> list[OtpToken]:
    if "masterKey" not in backup:
        raise ValueError("No masterKey entry found; is this a FreeOTP backup?")
    master = json.loads(backup["masterKey"])
    try:
        master_key = derive_master_key(master, password)
    except Exception as e:
        raise ValueError("Wrong password or corrupted backup") from e

    tokens: list[OtpToken] = []
    for key, val in backup.items():
        if key == "masterKey" or key.endswith("-token") or not isinstance(val, str):
            continue
        try:
            wrapper = json.loads(val)
        except json.JSONDecodeError:
            continue
        if not isinstance(wrapper, dict) or "key" not in wrapper:
            continue
        ek = wrapper["key"]
        if isinstance(ek, str):
            ek = json.loads(ek)
        token_json = backup.get(key + "-token")
        if token_json is None:
            print(f"[warn] {key}: missing {key}-token metadata, skipped", file=sys.stderr)
            continue
        meta = json.loads(token_json)

        issuer = meta.get("issuerExt") or meta.get("issuerInt")
        tokens.append(OtpToken(
            uuid=key,
            type=(meta.get("type") or "TOTP").upper(),
            issuer=issuer,
            label=meta.get("label") or "",
            secret=decrypt_encrypted_key(ek, master_key),
            algorithm=(meta.get("algo") or "SHA1").upper(),
            digits=int(meta.get("digits") or (5 if issuer == "Steam" else 6)),
            period=int(meta.get("period") or 30),
            counter=meta.get("counter"),
            extras={k: meta.get(k) for k in ("lock", "color", "image")},
        ))

    tokens.sort(key=lambda t: ((t.issuer or "").lower(), t.label.lower()))
    return tokens


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #

def _safe_name(s: str) -> str:
    s = re.sub(r"[^\w.\-@ ]+", "_", s, flags=re.UNICODE).strip(" ._")
    return s[:60] or "token"


def _qr(uri: str):
    try:
        import segno
    except ImportError:
        sys.exit("QR output requires segno:  pip install segno")
    return segno.make(uri, error="m")


def render_html(tokens: list[OtpToken], include_extras: bool, title: str) -> str:
    with open(TEMPLATE_PATH, encoding="utf-8") as fh:
        template = fh.read()
    cards, data = [], []
    for i, t in enumerate(tokens):
        uri = t.uri(include_extras)
        svg = _qr(uri).svg_inline(omitsize=True, border=2, svgclass=None, lineclass=None)
        search = html.escape(f"{t.issuer or ''} {t.label}".lower(), quote=True)
        cards.append(
            f'<div class="card" data-i="{i}" data-search="{search}">{svg}'
            f'<div class="meta"><div class="issuer">{html.escape(t.issuer or t.label)}</div>'
            f'<div class="label">{html.escape(t.label if t.issuer else "")}</div>'
            f'<span class="badge">{t.type}</span></div></div>')
        data.append({"type": t.type, "issuer": t.issuer, "label": t.label, "secret": t.secret_b32,
                     "algorithm": t.algorithm, "digits": t.digits, "period": t.period,
                     "counter": t.counter, "uri": uri})
    tokens_json = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    return (template
            .replace("__TITLE__", html.escape(title))
            .replace("__COUNT__", str(len(tokens)))
            .replace("__DATE__", time.strftime("%Y-%m-%d"))
            .replace("__CARDS__", "\n".join(cards))
            .replace("__TOKENS__", tokens_json))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Convert a FreeOTP backup (externalBackup.xml / tokenBackup.xml) into otpauth URIs and QR codes.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples
  python freeotp_export.py externalBackup.xml                  write externalBackup.html and list tokens
  python freeotp_export.py externalBackup.xml --html otp.html  choose the HTML file name
  python freeotp_export.py externalBackup.xml --qr             also draw QR codes in the terminal
  python freeotp_export.py externalBackup.xml -o qr_out        also write one PNG per token + uris.txt
  python freeotp_export.py externalBackup.xml --json           print JSON instead
""")
    ap.add_argument("backup", help="path to externalBackup.xml or tokenBackup.xml")
    ap.add_argument("-p", "--password", help="backup password (prompted if omitted)")
    ap.add_argument("--qr", action="store_true", help="draw QR codes in the terminal")
    ap.add_argument("-o", "--out", metavar="DIR", help="write per-token QR images and uris.txt to DIR")
    ap.add_argument("--html", metavar="FILE", help="HTML output path (default: <backup name>.html)")
    ap.add_argument("--title", default="OTP Tokens", help="page title for --html")
    ap.add_argument("--format", default="png", choices=["png", "svg", "pdf", "eps", "txt"],
                    help="image format for --out (default png)")
    ap.add_argument("--scale", type=int, default=8, help="module size for --out images (default 8)")
    ap.add_argument("--extras", action="store_true", help="include FreeOTP-only params (lock/color/image) in URIs")
    ap.add_argument("--json", action="store_true", help="print tokens as JSON and exit")
    ap.add_argument("--filter", metavar="TEXT", help="only tokens whose issuer/label contains TEXT")
    args = ap.parse_args(argv)

    backup = load_backup(args.backup)
    password = args.password if args.password is not None else getpass.getpass("FreeOTP backup password: ")
    tokens = extract_tokens(backup, password)
    if args.filter:
        f = args.filter.lower()
        tokens = [t for t in tokens if f in (t.issuer or "").lower() or f in t.label.lower()]
    if not tokens:
        print("No tokens found.", file=sys.stderr)
        return 1

    if args.json:
        json.dump([{
            "uuid": t.uuid, "type": t.type, "issuer": t.issuer, "label": t.label,
            "secret_base32": t.secret_b32, "algorithm": t.algorithm, "digits": t.digits,
            "period": t.period, "counter": t.counter, "uri": t.uri(args.extras),
        } for t in tokens], sys.stdout, ensure_ascii=False, indent=2)
        print()
        return 0

    html_path = args.html or os.path.splitext(args.backup)[0] + ".html"
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(render_html(tokens, args.extras, args.title))
    print(f"{len(tokens)} tokens -> {html_path}\n")

    if args.out:
        os.makedirs(args.out, exist_ok=True)
        with open(os.path.join(args.out, "uris.txt"), "w", encoding="utf-8") as fh:
            for i, t in enumerate(tokens, 1):
                fn = f"{i:02d}_{_safe_name(t.issuer or '')}_{_safe_name(t.label)}.{args.format}"
                _qr(t.uri(args.extras)).save(os.path.join(args.out, fn), scale=args.scale, border=2)
                fh.write(t.uri(args.extras) + "\n")
        print(f"{len(tokens)} tokens -> {args.out}/ (QR {args.format} + uris.txt)\n")

    for i, t in enumerate(tokens, 1):
        info = f"{t.algorithm}, {t.digits} digits, " + (
            f"{t.period}s" if t.type == "TOTP" else f"counter={t.counter}")
        print(f"[{i:02d}] {t.type}  {t.display_name}   [{info}]   code: {t.code()}")
        print(f"     {t.uri(args.extras)}")
        if args.qr:
            _qr(t.uri(args.extras)).terminal(compact=True, border=1)
        print()
    return 0


if __name__ == "__main__":
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8")
        except Exception:
            pass
    try:
        sys.exit(main())
    except (ValueError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(2)
