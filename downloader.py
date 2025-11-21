import aiohttp
import asyncio
import logging
import argparse
import json
from urllib.parse import urlencode
import hashlib
import base64
import binascii
from typing import Tuple
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


logger = logging.getLogger(__name__)


# import aiohttp
# import asyncio
# import m3u8
# from pathlib import Path
# from Crypto.Cipher import AES
# import tqdm.asyncio


# def request_headers():
#     """Return request headers (same as your original)"""
#     return {
#         "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
#     }


# async def download_book_by_m3u8_with_aiohttp(m3u8_url, book_folder, tmp_folder, book_json):
#     """
#     Downloads and decrypts HLS stream using aiohttp.

#     Args:
#         m3u8_url: URL to M3U8 playlist
#         book_folder: Path to save the book
#         tmp_folder: Path for temporary files
#         book_json: Book metadata
#     """

#     async def get_key(session: aiohttp.ClientSession, url: str) -> bytes:
#         """Fetch decryption key from URL"""
#         async with session.get(url, headers=request_headers()) as resp:
#             assert resp.status == 200, 'Could not fetch decryption key.'
#             return await resp.read()

#     async def make_cipher_for_segment(session: aiohttp.ClientSession, segment):
#         """Create AES cipher for decrypting segment"""
#         key = await get_key(session, segment.key.absolute_uri)
#         iv = bytes.fromhex(segment.key.iv.lstrip('0x'))
#         return AES.new(key, AES.MODE_CBC, IV=iv)

#     async def download_and_decrypt_segments(session: aiohttp.ClientSession, segments, stream_path):
#         """Download all segments and write decrypted data to file"""
#         with open(stream_path, mode='wb') as file:
#             # Use tqdm.asyncio for async progress bar
#             for segment in tqdm.tqdm(segments, desc="Downloading segments"):
#                 cipher = await make_cipher_for_segment(session, segment)

#                 async with session.get(segment.absolute_uri, headers=request_headers()) as resp:
#                     assert resp.status == 200, f'Could not download segment: {segment.absolute_uri}'

#                     # Read in chunks to avoid memory overload
#                     async for chunk in resp.content.iter_chunked(8192):
#                         decrypted = cipher.decrypt(chunk)
#                         file.write(decrypted)

#     # Parse M3U8 playlist (m3u8 library uses requests, but we can parse locally)
#     # If m3u8_url is remote, fetch it first
#     async with aiohttp.ClientSession() as session:
#         async with session.get(m3u8_url, headers=request_headers()) as resp:
#             m3u8_content = await resp.text()

#         # Parse M3U8 (synchronous operation)
#         import io
#         playlist = m3u8.loads(m3u8_content, uri=m3u8_url)
#         segments = playlist.segments

#         stream_path = tmp_folder / 'stream.ts'
#         await download_and_decrypt_segments(session, segments, stream_path)

#     print(f"Downloaded stream saved to: {stream_path}")

# ***********************************************************************************************************

# Decrypt password obtained from akniga's JS script.
# Found all string parts and tried to brute force the password.
PASSWORD = "EKxtcg46V"
KEY_LEN = 32
IV_LEN = 16
KDF_HASH_ALGO = "md5"
BLOCK_SIZE = 16


class EncryptedData:
    """Represents encrypted data structure from JSON."""

    def __init__(self, ct: str, iv: str, s: str):
        self.ct = ct
        self.iv = iv
        self.s = s


def decode_url(input_json: str) -> str:
    """
    Decrypts an encrypted URL from JSON string.

    Args:
        input_json: JSON string containing encrypted data with 'ct', 'iv', and 's' fields

    Returns:
        str: Decrypted URL

    Raises:
        ValueError: If decryption fails or data is invalid
    """
    try:
        data_dict = json.loads(input_json)
        data = EncryptedData(data_dict["ct"], data_dict["iv"], data_dict["s"])
    except (json.JSONDecodeError, KeyError) as e:
        raise ValueError(f"Failed to parse JSON: {e}")

    # Decode ciphertext from base64
    ct_base64 = data.ct.replace("\\/", "/")
    try:
        ciphertext = base64.standard_b64decode(ct_base64)
    except Exception as e:
        raise ValueError(f"Failed to decode base64 ciphertext: {e}")

    # Decode IV from hex
    try:
        iv = binascii.unhexlify(data.iv)
    except Exception as e:
        raise ValueError(f"Failed to decode hex IV: {e}")

    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"Invalid IV length: expected {BLOCK_SIZE}, got {len(iv)}")

    # Decode salt from hex
    try:
        salt = binascii.unhexlify(data.s)
    except Exception as e:
        raise ValueError(f"Failed to decode hex salt: {e}")

    # Derive key using EVP_BytesToKey
    try:
        key = evp_bytes_to_key(PASSWORD.encode(), salt, KEY_LEN, IV_LEN)
    except Exception as e:
        raise ValueError(f"Failed to derive key: {e}")

    # Create AES cipher and decrypt
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(ciphertext)
    except Exception as e:
        raise ValueError(f"Failed to decrypt: {e}")

    # Remove PKCS7 padding
    try:
        decrypted_data = unpad(decrypted_padded, BLOCK_SIZE)
    except ValueError as e:
        raise ValueError(f"Failed to unpad data (likely wrong key/ciphertext): {e}")

    # Clean up the decrypted string
    final_url = decrypted_data.decode("utf-8", errors="ignore")
    final_url = final_url.replace("\\", "")
    final_url = final_url.replace('"', "")

    if not final_url:
        raise ValueError("Decryption resulted in an empty string")

    return final_url


def evp_bytes_to_key(password: bytes, salt: bytes, key_len: int, iv_len: int) -> bytes:
    """
    Derives a key from password and salt using EVP_BytesToKey algorithm.

    This replicates OpenSSL's EVP_BytesToKey function with MD5 hash.

    Args:
        password: Password bytes
        salt: Salt bytes
        key_len: Desired key length
        iv_len: Desired IV length (not used in this function but kept for compatibility)

    Returns:
        bytes: Derived key of length key_len

    Raises:
        ValueError: If key derivation fails
    """
    derived_bytes = b""
    block = b""
    total_len = key_len + iv_len

    while len(derived_bytes) < total_len:
        hasher = hashlib.md5()

        if block:
            hasher.update(block)

        hasher.update(password)
        hasher.update(salt)

        block = hasher.digest()
        derived_bytes += block

    if len(derived_bytes) < key_len:
        raise ValueError(
            f"Derived bytes length ({len(derived_bytes)}) is less than "
            f"required key length ({key_len})"
        )

    return derived_bytes[:key_len]


def pkcs7_unpad(data: bytes) -> bytes:
    """
    Removes PKCS7 padding from data.

    Args:
        data: Padded data

    Returns:
        bytes: Unpadded data

    Raises:
        ValueError: If padding is invalid
    """
    if not data:
        raise ValueError("PKCS7: data is empty")

    padding_len = data[-1]

    if padding_len > len(data) or padding_len > BLOCK_SIZE or padding_len == 0:
        raise ValueError(
            f"PKCS7: invalid padding length {padding_len} (data length {len(data)})"
        )

    pad = data[-padding_len:]
    for byte in pad:
        if byte != padding_len:
            raise ValueError("PKCS7: invalid padding bytes")

    return data[:-padding_len]


# ***********************************************************************************************************


def decode_book_info(resp_json):
    result = {
        "author": resp_json["author"],
        "title": resp_json["titleonly"],
        "performer": resp_json["performer"],
        "items": json.loads(resp_json["items"]),
        "cover_100": resp_json["preview"],
        "cover": resp_json["preview"].split("100x100crop")[0] + "400x.webp",
    }

    return result


async def get_book(book_url):

    async with aiohttp.ClientSession() as session:

        user_agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
        session.headers.update({"user-agent": user_agent})

        async with session.get(book_url) as response:

            cookies = session.cookie_jar.filter_cookies("https://akniga.org")
            cookies_dict = {}
            for name, morsel in cookies.items():
                cookies_dict[name] = morsel.value

            html = await response.text()
            book_id = html.split("data-bid=")[1].split('"')[1]
            LIVESTREET_SECURITY_KEY = (
                html.split("LIVESTREET_SECURITY_KEY")[1]
                .split("=")[1]
                .split(",")[0]
                .strip()
                .split("'")[1]
            )

            ajax_url = f"https://akniga.org/ajax/b/{book_id}"
            data = {
                "bid": book_id,
                "hls": "true",
                "security_ls_key": LIVESTREET_SECURITY_KEY,
            }
            data_str = urlencode(data)
            session.headers.update(
                {
                    "Accept-Language": "ru-RU,ru;q=0.8,en-US;q=0.5,en;q=0.3",
                    "Connection": "keep-alive",
                    "Pragma": "no-cache",
                    "Cache-Control": "no-cache",
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "X-Requested-With": "XMLHttpRequest",
                    "Origin": "https://akniga.org",
                    "Referer": book_url,
                }
            )
            async with session.post(ajax_url, data=data_str) as response_ajax:
                resp_text = await response_ajax.text()
                resp_json = json.loads(resp_text)

                hls = decode_url(resp_json["hres"])
                book_info = decode_book_info(resp_json)
                book_info["hls"] = hls
                book_info["book_id"] = book_id
                book_info["security_ls_key"] = LIVESTREET_SECURITY_KEY
                book_info["user_agent"] = user_agent
                book_info["cookies"] = cookies_dict

                print(book_info)


def parse_args(parser, logger, check_url=True):
    try:
        args = parser.parse_args()
    except:
        exit(0)

    log_level = logging.ERROR
    if args.verbose == 1:
        log_level = logging.WARNING
    elif args.verbose == 2:
        log_level = logging.INFO
    elif args.verbose > 2:
        log_level = logging.DEBUG

    logger.setLevel(log_level)

    if check_url:
        if len(args.url) == 0:
            logger.error("Не задан ключ --url")
            exit(0)

    return args


if __name__ == "__main__":

    logging.basicConfig(
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        level=logging.ERROR,
    )
    logger.setLevel(logging.DEBUG)

    app_description = "Качалка akniga.org"
    parser = argparse.ArgumentParser(description=app_description)
    parser.add_argument(
        "--verbose",
        "-v",
        help="Уровень логирования по умолчанию (если ключ не задан) - error. warning -v, info -vv, debug -vvv",
        action="count",
        default=0,
    )
    parser.add_argument(
        "--url",
        help=("url книги"),
    )

    args = parse_args(parser, logger)
    logger.info(args)

    asyncio.run(get_book(args.url))
