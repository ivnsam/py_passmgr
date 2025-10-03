#!/usr/bin/env python3
"""
secure_cha_argon2.py
ChaCha20-Poly1305 + Argon2id (argon2-cffi) + optional pepper + auto Argon2 tuning.

Requires:
    pip install pycryptodome argon2-cffi
"""

import argparse
import os
import sys
import struct
import getpass
import time
from typing import Tuple

from Crypto.Cipher import ChaCha20_Poly1305
from argon2.low_level import hash_secret_raw, Type

# --- Constants / defaults ---
MAGIC = b'CHP2'          # файл-идентификатор/версия
VERSION = 1
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
KEY_LEN = 32             # 256-bit ключ
MIN_PASSPHRASE_LEN = 16  # минимальная длина passphrase

# Default starting params for auto-tuning (conservative baseline)
DEFAULT_ARGON2_TIME = 2            # iterations
DEFAULT_ARGON2_MEMORY_KIB = 64 * 1024  # 64 MiB (в KiB)
DEFAULT_ARGON2_PARALLELISM = 1

# Auto-tune targets / bounds
DEFAULT_TARGET_SECONDS = 0.30
MAX_MEMORY_KIB = 1024 * 1024  # 1 GiB as upper safety bound (in KiB)
MAX_TIME_COST = 10

# Header struct: magic(4), version(1), time_cost(4), memory_kib(4), parallelism(4), salt(16), nonce(12)
_HEADER_FMT = ">4sBIII16s12s"

# --- Utilities ---
def enforce_passphrase_strength(pw: str):
    if len(pw) < MIN_PASSPHRASE_LEN:
        print(f"Ошибка: passphrase должен быть не менее {MIN_PASSPHRASE_LEN} символов.")
        sys.exit(2)

def get_pepper() -> bytes:
    p = os.getenv("FILE_ENC_PEPPER")
    return p.encode("utf-8") if p else b''

def derive_key_argon2(password: bytes, salt: bytes, time_cost: int, memory_kib: int, parallelism: int) -> bytes:
    # hash_secret_raw возвращает key_len байт
    return hash_secret_raw(secret=password,
                           salt=salt,
                           time_cost=time_cost,
                           memory_cost=memory_kib,
                           parallelism=parallelism,
                           hash_len=KEY_LEN,
                           type=Type.ID)

def pack_header(time_cost: int, memory_kib: int, parallelism: int, salt: bytes, nonce: bytes) -> bytes:
    return struct.pack(_HEADER_FMT, MAGIC, VERSION, time_cost, memory_kib, parallelism, salt, nonce)

def unpack_header(data: bytes) -> Tuple[int, int, int, bytes, bytes, int]:
    header_size = struct.calcsize(_HEADER_FMT)
    if len(data) < header_size:
        raise ValueError("Файл слишком мал или повреждён (несоответствующий заголовок).")
    magic, version, time_cost, memory_kib, parallelism, salt, nonce = struct.unpack(_HEADER_FMT, data[:header_size])
    if magic != MAGIC:
        raise ValueError("Неверный формат файла (magic mismatch).")
    if version != VERSION:
        raise ValueError(f"Неподдерживаемая версия формата: {version}")
    return time_cost, memory_kib, parallelism, salt, nonce, header_size

def secure_erase(b: bytearray):
    for i in range(len(b)):
        b[i] = 0

# --- Auto-tuner ---
def autotune_argon2(password_sample: bytes,
                    target_seconds: float = DEFAULT_TARGET_SECONDS,
                    start_mem_kib: int = DEFAULT_ARGON2_MEMORY_KIB,
                    start_time: int = DEFAULT_ARGON2_TIME,
                    parallelism: int = DEFAULT_ARGON2_PARALLELISM):
    """Простой autotune: увеличиваем memory вдвое, затем time_cost, чтобы достичь target_seconds.
       Возвращает (time_cost, memory_kib, parallelism).
    """
    mem = start_mem_kib
    time_cost = start_time
    par = parallelism

    # защита от излишнего роста
    while True:
        salt = os.urandom(SALT_LEN)
        t0 = time.perf_counter()
        try:
            _ = hash_secret_raw(secret=password_sample, salt=salt,
                                time_cost=time_cost, memory_cost=mem,
                                parallelism=par, hash_len=16, type=Type.ID)
        except Exception:
            # если память слишком высока для системы — снизим и выйдем
            break
        elapsed = time.perf_counter() - t0
        # print debug? (можно включать по флагу)
        if elapsed >= target_seconds:
            return time_cost, mem, par
        # сначала увеличим память (эффективнее против GPU)
        if mem < MAX_MEMORY_KIB:
            mem = min(mem * 2, MAX_MEMORY_KIB)
            continue
        # затем увеличим time_cost
        if time_cost < MAX_TIME_COST:
            time_cost += 1
            # reset memory back to start to prevent runaway memory with increasing time?
            # keep current mem; it's already maxed
            continue
        # если достигли лимитов — вернуть текущие
        return time_cost, mem, par

# --- Core operations ---
def encrypt_file(in_path: str, out_path: str, passphrase: str,
                 time_cost: int, memory_kib: int, parallelism: int):
    enforce_passphrase_strength(passphrase)
    pepper = get_pepper()
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    password_bytes = passphrase.encode("utf-8") + pepper

    key = derive_key_argon2(password_bytes, salt, time_cost, memory_kib, parallelism)
    key_ba = bytearray(key)
    try:
        cipher = ChaCha20_Poly1305.new(key=bytes(key_ba), nonce=nonce)
        with open(in_path, "rb") as f:
            plaintext = f.read()
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        header = pack_header(time_cost, memory_kib, parallelism, salt, nonce)
        with open(out_path, "wb") as outf:
            outf.write(header)
            outf.write(ciphertext)
            outf.write(tag)
        print(f"Файл зашифрован: {out_path}")
    finally:
        secure_erase(key_ba)

def decrypt_file(in_path: str, out_path: str, passphrase: str):
    enforce_passphrase_strength(passphrase)
    pepper = get_pepper()
    with open(in_path, "rb") as f:
        data = f.read()
    time_cost, memory_kib, parallelism, salt, nonce, hdr_len = unpack_header(data)
    if len(data) < hdr_len + TAG_LEN:
        raise ValueError("Файл повреждён или слишком мал.")
    ciphertext = data[hdr_len:-TAG_LEN]
    tag = data[-TAG_LEN:]
    password_bytes = passphrase.encode("utf-8") + pepper

    key = derive_key_argon2(password_bytes, salt, time_cost, memory_kib, parallelism)
    key_ba = bytearray(key)
    try:
        cipher = ChaCha20_Poly1305.new(key=bytes(key_ba), nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        with open(out_path, "wb") as outf:
            outf.write(plaintext)
        print(f"Файл расшифрован: {out_path}")
    finally:
        secure_erase(key_ba)

# --- Core operations (in-memory) ---
def encrypt_data(plaintext: bytes, passphrase: str,
                 time_cost: int, memory_kib: int, parallelism: int) -> bytes:
    """Шифрует данные (bytes) и возвращает bytes (header + ciphertext + tag)."""
    enforce_passphrase_strength(passphrase)
    pepper = get_pepper()
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    password_bytes = passphrase.encode("utf-8") + pepper

    key = derive_key_argon2(password_bytes, salt, time_cost, memory_kib, parallelism)
    key_ba = bytearray(key)
    try:
        cipher = ChaCha20_Poly1305.new(key=bytes(key_ba), nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        header = pack_header(time_cost, memory_kib, parallelism, salt, nonce)
        return header + ciphertext + tag
    finally:
        secure_erase(key_ba)


def decrypt_data(data: bytes, passphrase: str) -> bytes:
    """Расшифровывает данные (bytes, содержащие header+ciphertext+tag) и возвращает plaintext bytes."""
    enforce_passphrase_strength(passphrase)
    pepper = get_pepper()
    time_cost, memory_kib, parallelism, salt, nonce, hdr_len = unpack_header(data)
    if len(data) < hdr_len + TAG_LEN:
        raise ValueError("Данные повреждены или слишком малы.")
    ciphertext = data[hdr_len:-TAG_LEN]
    tag = data[-TAG_LEN:]
    password_bytes = passphrase.encode("utf-8") + pepper

    key = derive_key_argon2(password_bytes, salt, time_cost, memory_kib, parallelism)
    key_ba = bytearray(key)
    try:
        cipher = ChaCha20_Poly1305.new(key=bytes(key_ba), nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    finally:
        secure_erase(key_ba)

# --- Convenience wrappers for strings ---
def encrypt_string(plaintext: str, passphrase: str,
                   time_cost: int, memory_kib: int, parallelism: int) -> bytes:
    """
    Шифрует строку (str) → возвращает bytes (header+ciphertext+tag).
    """
    return encrypt_data(plaintext.encode("utf-8"), passphrase, time_cost, memory_kib, parallelism)


def decrypt_string(data: bytes, passphrase: str) -> str:
    """
    Расшифровывает bytes (header+ciphertext+tag) → возвращает строку (str).
    """
    plaintext_bytes = decrypt_data(data, passphrase)
    return plaintext_bytes.decode("utf-8")

# --- CLI parsing ---
def parse_args():
    ap = argparse.ArgumentParser(description="ChaCha20-Poly1305 + Argon2id (+ optional pepper) — encrypt/decrypt files")
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("-e", "--encrypt", action="store_true")
    group.add_argument("-d", "--decrypt", action="store_true")
    ap.add_argument("file", help="входной файл (или зашифрованный файл)")
    ap.add_argument("-o", "--output", required=True, help="выходной файл")
    # manual argon2 params (if any specified, require all three)
    ap.add_argument("--argon2-time", type=int, help="Argon2 time_cost (iterations)")
    ap.add_argument("--argon2-memory", type=int, help="Argon2 memory_cost (KiB)")
    ap.add_argument("--argon2-par", type=int, help="Argon2 parallelism")
    # auto options
    ap.add_argument("--auto", action="store_true", help="Автоматически подобрать Argon2 параметры (по умолчанию)")
    ap.add_argument("--target-seconds", type=float, default=DEFAULT_TARGET_SECONDS, help="Целевое время KDF в секундах при автоподборе")
    ap.add_argument("--passphrase", help="Passphrase (если не указан — вводится интерактивно)")
    return ap.parse_args()

def main():
    args = parse_args()

    # determine argon2 params mode
    manual_any = (args.argon2_time is not None) or (args.argon2_memory is not None) or (args.argon2_par is not None)
    if manual_any:
        if None in (args.argon2_time, args.argon2_memory, args.argon2_par):
            print("Если указываете ручные параметры Argon2, укажите все три: --argon2-time, --argon2-memory, --argon2-par")
            sys.exit(2)
        arg_time = args.argon2_time
        arg_mem = args.argon2_memory
        arg_par = args.argon2_par
    else:
        # auto mode (default if --auto or none specified)
        arg_time = None
        arg_mem = None
        arg_par = DEFAULT_ARGON2_PARALLELISM

    # passphrase
    if args.passphrase:
        passphrase = args.passphrase
    else:
        passphrase = getpass.getpass("Введите passphrase: ")
        passphrase2 = getpass.getpass("Подтвердите passphrase: ")
        if passphrase != passphrase2:
            print("Ошибка: passphrase не совпадают.")
            sys.exit(3)

    if arg_time is None:
        # autotune using passphrase sample (we use passphrase bytes to more accurately measure)
        print("Автоподбор параметров Argon2 (это займёт немного времени)...")
        sample = passphrase.encode("utf-8") + get_pepper()
        arg_time, arg_mem, arg_par = autotune_argon2(sample, target_seconds=args.target_seconds)
        print(f"Подобраны параметры: time={arg_time}, memory_kib={arg_mem}, parallelism={arg_par}")

    # perform encrypt/decrypt
    try:
        if args.encrypt:
            encrypt_file(args.file, args.output, passphrase, arg_time, arg_mem, arg_par)
        else:
            decrypt_file(args.file, args.output, passphrase)
    except Exception as e:
        print("Ошибка при обработке файла:", e)
        sys.exit(4)

if __name__ == "__main__":
    main()
