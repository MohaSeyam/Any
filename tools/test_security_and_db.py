#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
حزمة الاختبارات الآلية الشاملة لأدوات التراخيص والتشفير وقاعدة البيانات بالصور والمرفقات
=======================================================================================
تختبر:
1. التوافق التشفيري لـ RSA-2048 OAEP (SHA-256 + MGF1-SHA1) بين أداة الإدارة وشريحة Android Keystore.
2. دورة إصدار الترخيص (REQ2 -> LIC2) والتحقق من توقيع Ed25519 ورفض التزوير وكلمة مرور الأدمن (Argon2id).
3. دورة الفتح الحضوري للمدير (UNLKREQ2 -> UNLK2).
4. إنشاء قاعدة البيانات المزودة بالصور وملفات PDF وفهرس FTS5، ومحاكاة البث المجزأ (SUBSTR 1-based)
   بشرائح 512KB لمرفق أكبر من 2.7MB والتحقق من بصمة SHA-256!
"""

import hashlib
import json
import secrets
import sqlite3
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import admin_tool
import create_sample_db


class SecureDbSuiteTests(unittest.TestCase):

    def setUp(self) -> None:
        self.admin_seed = secrets.token_bytes(32)
        self.admin_priv = Ed25519PrivateKey.from_private_bytes(self.admin_seed)
        self.admin_pub = self.admin_priv.public_key()

        # محاكاة زوج مفاتيح شريحة Android Keystore للجهاز (RSA-2048)
        self.device_rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.device_rsa_pub_der = self.device_rsa_priv.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def test_license_roundtrip_rsa_oaep_ed25519_and_tamper_rejection(self) -> None:
        raw_dek = secrets.token_bytes(32)
        req_payload = {
            "v": 2,
            "type": "ACTIVATE_REQ",
            "deviceId": "DEV-ABCDEF0123456789",
            "nonce": "aabbccddeeff001122334455",
            "rsaPub": admin_tool.b64url_encode(self.device_rsa_pub_der),
        }
        req_token = "REQ2." + admin_tool.b64url_encode(json.dumps(req_payload).encode("utf-8"))

        lic_token, dev_id = admin_tool.build_license_token(
            req_token=req_token,
            admin_password="Admin#StrongPassword99",
            valid_days=90,
            dek_hex=raw_dek.hex(),
            priv_key=self.admin_priv,
        )
        self.assertEqual(dev_id, "DEV-ABCDEF0123456789")
        self.assertTrue(lic_token.startswith("LIC2."))

        # تأكيد أن المفتاح الخام DEK غير موجود نصياً داخل التوكن!
        body_b64, sig_b64 = lic_token[5:].split(".")
        payload_bytes = admin_tool.b64url_decode(body_b64)
        sig_bytes = admin_tool.b64url_decode(sig_b64)
        self.assertNotIn(raw_dek.hex().encode("utf-8"), payload_bytes)

        # التحقق من توقيع Ed25519
        self.admin_pub.verify(sig_bytes, payload_bytes)

        # فك تغليف RSA-OAEP(SHA-256, MGF1-SHA1) كما تفعل شريحة Android Keystore
        payload_json = json.loads(payload_bytes.decode("utf-8"))
        wrapped_dek = admin_tool.b64url_decode(payload_json["wrappedDekB64"])
        unwrapped_dek = self.device_rsa_priv.decrypt(
            wrapped_dek,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        self.assertEqual(raw_dek, unwrapped_dek)

        # التأكد من رفض أي تعديل في الحمولة الموقعة
        tampered = bytearray(payload_bytes)
        tampered[10] ^= 0x01
        with self.assertRaises(Exception):
            self.admin_pub.verify(sig_bytes, bytes(tampered))

    def test_physical_unlock_token_roundtrip(self) -> None:
        challenge_obj = {
            "v": 2,
            "type": "UNLOCK_REQ",
            "deviceId": "DEV-9988776655443322",
            "nonce": "11223344556677889900aabb",
        }
        challenge_token = "UNLKREQ2." + admin_tool.b64url_encode(
            json.dumps(challenge_obj).encode("utf-8")
        )
        unlock_token, dev_id = admin_tool.build_unlock_token(
            challenge_token=challenge_token,
            admin_password="ManagerPhysicalKey#2026",
            extend_days=30,
            priv_key=self.admin_priv,
        )
        self.assertEqual(dev_id, "DEV-9988776655443322")
        body_b64, sig_b64 = unlock_token[6:].split(".")
        payload_bytes = admin_tool.b64url_decode(body_b64)
        self.admin_pub.verify(admin_tool.b64url_decode(sig_b64), payload_bytes)

    def test_db_schema_fts5_and_chunked_2_8mb_blob_streaming(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_attachments.db"
            create_sample_db.build_database(rows=30, output_plain=db_path)

            conn = sqlite3.connect(str(db_path))
            cur = conn.cursor()

            # إدراج مرفق ضخم بحجم 2.85 ميجابايت (> 2MB CursorWindow) لاختبار خوارزمية البث المجزأ SUBSTR
            big_blob = secrets.token_bytes(2_850_000)
            expected_sha = hashlib.sha256(big_blob).hexdigest()
            cur.execute(
                "INSERT INTO record_attachments VALUES (999, 1, 'huge_map.bin', 'image/bmp', ?, ?, 'اختبار 2.85MB', NULL);",
                (len(big_blob), expected_sha),
            )
            cur.execute("INSERT INTO attachment_blobs VALUES (999, ?);", (big_blob,))
            conn.commit()

            # اختبار البحث الفوري عبر FTS5 باللغة العربية
            cur.execute(
                """
                SELECT r.code FROM catalog_fts f
                JOIN catalog_records r ON r.id = f.rowid
                WHERE catalog_fts MATCH '"المخططات"*';
                """
            )
            hits = cur.fetchall()
            self.assertTrue(len(hits) > 0)

            # محاكاة خوارزمية التطبيق للبث المجزأ (1-based SQLite SUBSTR بشرائح 512KB)
            chunk_limit = 512 * 1024
            cur.execute("SELECT LENGTH(payload_blob) FROM attachment_blobs WHERE attachment_id = 999;")
            total_len = cur.fetchone()[0]
            self.assertEqual(total_len, 2_850_000)

            reassembled = bytearray()
            hasher = hashlib.sha256()
            offset_zero = 0
            while offset_zero < total_len:
                sql_start_one_based = offset_zero + 1
                read_len = min(chunk_limit, total_len - offset_zero)
                cur.execute(
                    "SELECT SUBSTR(payload_blob, ?, ?) FROM attachment_blobs WHERE attachment_id = 999;",
                    (sql_start_one_based, read_len),
                )
                chunk = cur.fetchone()[0]
                self.assertLessEqual(len(chunk), chunk_limit)
                hasher.update(chunk)
                reassembled.extend(chunk)
                offset_zero += len(chunk)

            self.assertEqual(hasher.hexdigest(), expected_sha)
            self.assertEqual(bytes(reassembled), big_blob)
            conn.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
