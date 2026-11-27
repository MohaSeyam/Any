#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
أداة الإدارة وإصدار التراخيص اليدوية (الإصدار المحصن V2 — Ed25519 + RSA-OAEP + Argon2id)
=======================================================================================
المزايا الأمنية في V2:
- لا يظهر مفتاح تشفير قاعدة البيانات (DEK) كنص مكشوف أبداً داخل شهادة الترخيص (LIC2)!
- يُشفّر المفتاح غير متماثل عبر RSA-2048 OAEP(SHA-256, MGF1-SHA1) بالمفتاح العام المولّد داخل
  شريحة Android Keystore الخاصة بالهاتف المستهدف حصراً.
"""

import argparse
import base64
import json
import re
import secrets
import sys
import time
import uuid
from pathlib import Path

from argon2.low_level import Type as Argon2Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

try:
    import qrcode
    HAS_QRCODE = True
except ImportError:
    HAS_QRCODE = False

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
PRIVATE_KEY_FILE = SCRIPT_DIR / "admin_ed25519_private.hex"
KOTLIN_CONFIG_FILE = (
    PROJECT_ROOT
    / "app/src/main/java/com/securedb/kiosk/security/CryptoEngine.kt"
)

DEFAULT_PROTOTYPE_SEED_HEX = (
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
)

ARGON2_MEMORY_KB = 65536  # 64 MB
ARGON2_ITERATIONS = 3
ARGON2_PARALLELISM = 2


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    cleaned = re.sub(r"\s+", "", text)
    pad = "=" * ((4 - len(cleaned) % 4) % 4)
    return base64.urlsafe_b64decode(cleaned + pad)


def load_private_key() -> Ed25519PrivateKey:
    if PRIVATE_KEY_FILE.exists():
        seed_hex = PRIVATE_KEY_FILE.read_text(encoding="utf-8").strip()
    else:
        print(
            "[!] تنبيه: يتم استخدام مفتاح التوقيع التجريبي الافتراضي. "
            "للإنتاج شغّل (python admin_tool.py init-keys) أولاً.",
            file=sys.stderr,
        )
        seed_hex = DEFAULT_PROTOTYPE_SEED_HEX
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))


def derive_argon2id_hex(password: str, salt_bytes: bytes) -> str:
    digest = hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt_bytes,
        time_cost=ARGON2_ITERATIONS,
        memory_cost=ARGON2_MEMORY_KB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=32,
        type=Argon2Type.ID,
        version=19,
    )
    return digest.hex()


def wrap_dek_for_device_keystore(rsa_pub_der_b64: str, raw_dek_32: bytes) -> str:
    """تشفير مفتاح القاعدة بالمفتاح العام لشريحة Android Keystore الخاصة بالجهاز (RSA-OAEP SHA-256 / MGF1-SHA1)."""
    pub_der = b64url_decode(rsa_pub_der_b64)
    pub_key = serialization.load_der_public_key(pub_der)
    ciphertext = pub_key.encrypt(
        raw_dek_32,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return b64url_encode(ciphertext)


def save_qr_if_available(token: str, out_path: Path) -> None:
    if not HAS_QRCODE:
        return
    img = qrcode.make(token)
    img.save(out_path)
    print(f"[+] تم حفظ رمز QR للمسح المباشر بالكاميرا في: {out_path}")


def cmd_init_keys(_args: argparse.Namespace) -> None:
    seed = secrets.token_bytes(32)
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub_bytes = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    pub_hex = pub_bytes.hex()

    PRIVATE_KEY_FILE.write_text(seed.hex(), encoding="utf-8")
    print(f"[+] تم توليد مفتاح Ed25519 خاص جديد وحفظه سرياً في: {PRIVATE_KEY_FILE}")
    print(f"[+] المفتاح العام المقابل (Public Key Hex): {pub_hex}")

    if KOTLIN_CONFIG_FILE.exists():
        src = KOTLIN_CONFIG_FILE.read_text(encoding="utf-8")
        updated = re.sub(
            r'(ADMIN_ED25519_PUBLIC_KEY_HEX\s*=\s*\n?\s*")[0-9a-fA-F]{64}(")',
            rf"\g<1>{pub_hex}\g<2>",
            src,
        )
        KOTLIN_CONFIG_FILE.write_text(updated, encoding="utf-8")
        print(f"[+] تم تحديث المفتاح العام داخل كود التطبيق تلقائياً: {KOTLIN_CONFIG_FILE}")


def build_license_token(
    req_token: str,
    admin_password: str,
    valid_days: float,
    dek_hex: str = "",
    priv_key: Ed25519PrivateKey | None = None,
) -> tuple[str, str]:
    clean = re.sub(r"\s+", "", req_token)
    if not clean.startswith("REQ2."):
        raise ValueError("المفتاح الأولي يجب أن يبدأ بـ REQ2.")
    if valid_days <= 0:
        raise ValueError("مدة الصلاحية (--valid-days) يجب أن تكون أكبر من صفر.")

    req_json = json.loads(b64url_decode(clean[5:]).decode("utf-8"))
    if req_json.get("type") != "ACTIVATE_REQ":
        raise ValueError("نوع الطلب ليس طلب تفعيل صالحاً.")

    device_id = req_json["deviceId"]
    nonce = req_json["nonce"]
    rsa_pub_b64 = req_json["rsaPub"]

    if dek_hex:
        raw_dek = bytes.fromhex(dek_hex)
        if len(raw_dek) != 32:
            raise ValueError("طول مفتاح القاعدة (--dek-hex) يجب أن يكون 64 خانة سداسية عشرية (32 بايت).")
        wrapped_dek_b64 = wrap_dek_for_device_keystore(rsa_pub_b64, raw_dek)
    elif req_json.get("encLabDek"):
        wrapped_dek_b64 = req_json["encLabDek"]
    else:
        raise ValueError(
            "لم يتم العثور على مفتاح قاعدة البيانات! اضغط زر (إنشاء قاعدة بيانات مشفرة تجريبية) "
            "في التطبيق قبل نسخ المفتاح الأولي، أو مرر مفتاح قاعدة الـ 100GB عبر --dek-hex."
        )

    admin_salt = secrets.token_bytes(16)
    admin_verifier_hex = derive_argon2id_hex(admin_password, admin_salt)

    now_ms = int(time.time() * 1000)
    expires_ms = now_ms + int(valid_days * 86400 * 1000)

    payload_obj = {
        "v": 2,
        "type": "LICENSE",
        "licenseId": f"LIC-{uuid.uuid4().hex[:10].upper()}",
        "deviceId": device_id,
        "nonce": nonce,
        "issuedAtMs": now_ms,
        "expiresAtMs": expires_ms,
        "wrappedDekB64": wrapped_dek_b64,
        "adminSaltHex": admin_salt.hex(),
        "adminVerifierHex": admin_verifier_hex,
        "argonMemKb": ARGON2_MEMORY_KB,
        "argonIter": ARGON2_ITERATIONS,
    }

    payload_bytes = json.dumps(payload_obj, separators=(",", ":")).encode("utf-8")
    signer = priv_key or load_private_key()
    sig_bytes = signer.sign(payload_bytes)
    return f"LIC2.{b64url_encode(payload_bytes)}.{b64url_encode(sig_bytes)}", device_id


def build_unlock_token(
    challenge_token: str,
    admin_password: str,
    extend_days: float = 0.0,
    priv_key: Ed25519PrivateKey | None = None,
) -> tuple[str, str]:
    clean = re.sub(r"\s+", "", challenge_token)
    if not clean.startswith("UNLKREQ2."):
        raise ValueError("كود تحدي الفتح الحضوري يجب أن يبدأ بـ UNLKREQ2.")
    if extend_days < 0:
        raise ValueError("مدة التمديد (--extend-days) لا يمكن أن تكون سالبة.")

    req_json = json.loads(b64url_decode(clean[9:]).decode("utf-8"))
    if req_json.get("type") != "UNLOCK_REQ":
        raise ValueError("كود التحدي غير صالح.")

    device_id = req_json["deviceId"]
    nonce = req_json["nonce"]

    admin_salt = secrets.token_bytes(16)
    admin_verifier_hex = derive_argon2id_hex(admin_password, admin_salt)
    now_ms = int(time.time() * 1000)
    new_expires_ms = now_ms + int(extend_days * 86400 * 1000) if extend_days > 0 else 0

    payload_obj = {
        "v": 2,
        "type": "UNLOCK",
        "deviceId": device_id,
        "nonce": nonce,
        "adminCurrentTimeMs": now_ms,
        "newExpiresAtMs": new_expires_ms,
        "adminSaltHex": admin_salt.hex(),
        "adminVerifierHex": admin_verifier_hex,
        "argonMemKb": ARGON2_MEMORY_KB,
        "argonIter": ARGON2_ITERATIONS,
    }

    payload_bytes = json.dumps(payload_obj, separators=(",", ":")).encode("utf-8")
    signer = priv_key or load_private_key()
    sig_bytes = signer.sign(payload_bytes)
    return f"UNLK2.{b64url_encode(payload_bytes)}.{b64url_encode(sig_bytes)}", device_id


def cmd_issue_license(args: argparse.Namespace) -> None:
    try:
        token, device_id = build_license_token(
            req_token=args.request,
            admin_password=args.admin_password,
            valid_days=args.valid_days,
            dek_hex=args.dek_hex,
        )
    except Exception as exc:
        sys.exit(f"[-] خطأ: {exc}")

    print("\n" + "=" * 72)
    print(f"[+] تم إصدار مفتاح الترخيص المحصن (RSA-OAEP + Ed25519) للجهاز: {device_id}")
    print(f"[+] صالح لمدة: {args.valid_days} يوم")
    print("=" * 72)
    print("\nمفتاح الترخيص اليدوي:\n")
    print(token)
    print("\n" + "=" * 72)
    save_qr_if_available(token, SCRIPT_DIR / f"license_{device_id}.png")


def cmd_unlock_device(args: argparse.Namespace) -> None:
    try:
        token, device_id = build_unlock_token(
            challenge_token=args.challenge,
            admin_password=args.admin_password,
            extend_days=args.extend_days,
        )
    except Exception as exc:
        sys.exit(f"[-] خطأ: {exc}")

    print("\n" + "=" * 72)
    print(f"[+] تم إصدار أمر الفتح الإداري الحضوري للجهاز: {device_id}")
    print("=" * 72)
    print("\nأمر الفتح الموقّع (يُدخل حضورياً على مكتب المدير مع كلمة مرور المدير):\n")
    print(token)
    print("\n" + "=" * 72)
    save_qr_if_available(token, SCRIPT_DIR / f"unlock_{device_id}.png")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="أداة إصدار التراخيص اليدوية والفتح الحضوري V2 (Ed25519 + RSA-OAEP + Argon2id)"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init-keys", help="توليد زوج مفاتيح Ed25519 جديد للإنتاج")

    p_lic = sub.add_parser("issue-license", help="إصدار ترخيص لجهاز محدد")
    p_lic.add_argument("--request", required=True, help="المفتاح الأولي من التطبيق (REQ2....)")
    p_lic.add_argument("--admin-password", required=True, help="كلمة مرور الأدمن الخاصة بالتفعيل")
    p_lic.add_argument("--valid-days", type=float, default=365.0, help="مدة صلاحية الترخيص بالأيام")
    p_lic.add_argument("--dek-hex", default="", help="مفتاح SQLCipher (64-hex) عند تجهيز قاعدة الـ 100GB خارجياً")

    p_unl = sub.add_parser("unlock-device", help="فتح جهاز مغلق نهائياً بعد فحصه فيزيائياً لدى المدير")
    p_unl.add_argument("--challenge", required=True, help="كود تحدي الفتح من شاشة الإغلاق (UNLKREQ2....)")
    p_unl.add_argument("--admin-password", required=True, help="كلمة مرور المدير التي سيدخلها بيده على الهاتف")
    p_unl.add_argument("--extend-days", type=float, default=0.0, help="تمديد الصلاحية بالأيام (اختياري)")

    args = parser.parse_args()
    if args.cmd == "init-keys":
        cmd_init_keys(args)
    elif args.cmd == "issue-license":
        cmd_issue_license(args)
    elif args.cmd == "unlock-device":
        cmd_unlock_device(args)


if __name__ == "__main__":
    main()
