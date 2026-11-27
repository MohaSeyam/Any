#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
مولد قاعدة البيانات المزودة بالصور والمرفقات وفهرس FTS5 (مجهز لهيكل 100 جيجابايت)
=================================================================================
ينشئ هيكل الجداول المفصولة عمودياً (Vertical Partitioning):
  1. catalog_records     : السجلات النصية السريعة
  2. catalog_fts         : فهرس البحث النصي الفوري FTS5 (عربي/إنجليزي)
  3. record_attachments  : بيانات المرفقات والمصغرات السريعة (<20KB) + بصمة SHA-256
  4. attachment_blobs    : جدول الكتل الثنائية المعزول للصور الضخمة وملفات PDF والمستندات
"""

import argparse
import hashlib
import mimetypes
import secrets
import sqlite3
import struct
import zlib
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent


def make_synthetic_png(width: int, height: int) -> bytes:
    """توليد صورة PNG صالحة بدون مكتبات خارجية."""
    def png_chunk(chunk_type: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", crc)

    raw_rows = bytearray()
    for y in range(height):
        raw_rows.append(0)  # Filter type 0
        for x in range(width):
            r = (x * 255) // max(1, width)
            g = (y * 255) // max(1, height)
            b = 140
            raw_rows.extend((r, g, b))

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    compressed = zlib.compress(bytes(raw_rows), level=6)
    return (
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", ihdr)
        + png_chunk(b"IDAT", compressed)
        + png_chunk(b"IEND", b"")
    )


def make_minimal_valid_pdf(title_ascii: str) -> bytes:
    """توليد ملف PDF 1.4 قياسي صالح للعرض عبر Android PdfRenderer."""
    stream = f"BT /F1 18 Tf 50 750 Td ({title_ascii}) Tj ET".encode("ascii")
    objs = [
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n",
        b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n",
        b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >> endobj\n",
        f"4 0 obj << /Length {len(stream)} >> stream\n".encode("ascii") + stream + b"\nendstream endobj\n",
        b"5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for o in objs:
        offsets.append(len(out))
        out.extend(o)
    xref_pos = len(out)
    out.extend(f"xref\n0 {len(offsets)}\n".encode("ascii"))
    out.extend(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        out.extend(f"{off:010d} 00000 n \n".encode("ascii"))
    out.extend(
        f"trailer << /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode("ascii")
    )
    return bytes(out)


def build_database(rows: int, output_plain: Path, attachments_dir: Path | None = None) -> None:
    if output_plain.exists():
        output_plain.unlink()

    conn = sqlite3.connect(str(output_plain))
    cur = conn.cursor()
    cur.execute("PRAGMA journal_mode = DELETE;")
    cur.execute("PRAGMA page_size = 16384;")

    cur.executescript(
        """
        CREATE TABLE catalog_records (
            id INTEGER PRIMARY KEY,
            code TEXT NOT NULL UNIQUE,
            category TEXT NOT NULL,
            title TEXT NOT NULL,
            details TEXT NOT NULL,
            classification TEXT NOT NULL,
            attachment_count INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX idx_catalog_code ON catalog_records(code);
        CREATE INDEX idx_catalog_category ON catalog_records(category);

        CREATE VIRTUAL TABLE catalog_fts USING fts5(
            code,
            category,
            title,
            details,
            content='catalog_records',
            content_rowid='id',
            tokenize='unicode61'
        );

        CREATE TABLE record_attachments (
            id INTEGER PRIMARY KEY,
            record_id INTEGER NOT NULL,
            file_name TEXT NOT NULL,
            mime_type TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            sha256_hex TEXT NOT NULL,
            description TEXT NOT NULL,
            thumbnail_blob BLOB,
            FOREIGN KEY(record_id) REFERENCES catalog_records(id)
        );
        CREATE INDEX idx_att_record_id ON record_attachments(record_id);

        CREATE TABLE attachment_blobs (
            attachment_id INTEGER PRIMARY KEY,
            payload_blob BLOB NOT NULL,
            FOREIGN KEY(attachment_id) REFERENCES record_attachments(id)
        );
        """
    )

    sample_png = make_synthetic_png(480, 320)
    sample_thumb = make_synthetic_png(96, 64)
    sample_pdf = make_minimal_valid_pdf("Encrypted Reference Attachment PDF")

    external_files = []
    if attachments_dir and attachments_dir.is_dir():
        external_files = [p for p in sorted(attachments_dir.iterdir()) if p.is_file()]

    categories = [
        "المخططات الهندسية المصورة",
        "المواصفات الفنية والمرفقات",
        "دليل المعدات الميدانية",
        "الوثائق المرجعية المعتمدة",
    ]
    classifications = ["سري للغاية", "مقيد - داخلي", "للقراءة الميدانية فقط"]

    next_att_id = 1
    for i in range(1, rows + 1):
        cat = categories[(i - 1) % len(categories)]
        cls = classifications[(i - 1) % len(classifications)]
        code = f"SEC-REF-{i:06d}"

        record_atts: list[tuple[str, str, str, bytes, bytes | None]] = []
        if external_files and i <= len(external_files):
            ext_file = external_files[i - 1]
            mime, _ = mimetypes.guess_type(ext_file.name)
            data = ext_file.read_bytes()
            record_atts.append(
                (ext_file.name, mime or "application/octet-stream", "مرفق مستورد من مجلد البيانات", data, None)
            )
        elif i <= 10:
            record_atts.append(
                (f"diagram_{code}.png", "image/png", "مخطط هندسي مشفر", sample_png, sample_thumb)
            )
            record_atts.append(
                (f"document_{code}.pdf", "application/pdf", "مستند PDF مرجعي مشفر", sample_pdf, None)
            )

        title = f"سجل مرجعي رقم {i} — {cat}"
        details = f"بيانات مرجعية للقراءة فقط مفهرسة بـ FTS5 ومحمية بـ SQLCipher. المرجع: {code}."

        cur.execute(
            "INSERT INTO catalog_records VALUES (?, ?, ?, ?, ?, ?, ?);",
            (i, code, cat, title, details, cls, len(record_atts)),
        )

        for fname, mime, desc, blob_bytes, thumb_bytes in record_atts:
            sha256_hex = hashlib.sha256(blob_bytes).hexdigest()
            cur.execute(
                "INSERT INTO record_attachments VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
                (next_att_id, i, fname, mime, len(blob_bytes), sha256_hex, desc, thumb_bytes),
            )
            cur.execute(
                "INSERT INTO attachment_blobs VALUES (?, ?);",
                (next_att_id, blob_bytes),
            )
            next_att_id += 1

    cur.execute("INSERT INTO catalog_fts(catalog_fts) VALUES('rebuild');")
    conn.commit()
    conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="بناء قاعدة بيانات بالصور والمرفقات وفهرس FTS5")
    parser.add_argument("--rows", type=int, default=500, help="عدد السجلات")
    parser.add_argument("--attachments-dir", type=str, default="", help="مجلد صور/مرفقات حقيقية لاستيرادها (اختياري)")
    args = parser.parse_args()

    plain_db = SCRIPT_DIR / "source_plain_temp.db"
    encrypted_db = SCRIPT_DIR / "secure_catalog.db"
    sql_script = SCRIPT_DIR / "encrypt_to_sqlcipher.sql"

    att_dir = Path(args.attachments_dir) if args.attachments_dir else None
    dek_hex = secrets.token_hex(32)
    build_database(args.rows, plain_db, att_dir)

    if encrypted_db.exists():
        encrypted_db.unlink()

    enc_path_posix = encrypted_db.as_posix().replace("'", "''")
    sql_content = (
        f"ATTACH DATABASE '{enc_path_posix}' AS encrypted KEY 'x''{dek_hex}''';\n"
        f"PRAGMA encrypted.cipher_page_size = 16384;\n"
        f"SELECT sqlcipher_export('encrypted');\n"
        f"DETACH DATABASE encrypted;\n"
    )
    sql_script.write_text(sql_content, encoding="utf-8")

    print("[+] تم تجهيز قاعدة البيانات بالصور والمرفقات وفهرس FTS5:", plain_db)
    print(f"[+] مفتاح تشفير القاعدة (256-bit DEK Hex): {dek_hex}")
    print(f'[+] أمر التشفير لملف 100GB عبر SQLCipher:\n    sqlcipher "{plain_db}" < "{sql_script}"')


if __name__ == "__main__":
    main()
