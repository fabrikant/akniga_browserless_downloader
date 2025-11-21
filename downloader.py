import aiohttp
import asyncio
import logging
import argparse
import json
from urllib.parse import urlencode
import hashlib
import base64
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import aiofiles


logger = logging.getLogger(__name__)


import m3u8
from pathlib import Path
import tqdm.asyncio


def user_agent():
    return "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"


def request_headers():
    """Return request headers (same as your original)"""
    return {"user-agent": user_agent()}


# ***********************************************************************************************************
# Загрузка медиафайла


async def download_book_by_m3u8(m3u8_url, download_path):

    async def get_key(session: aiohttp.ClientSession, url: str) -> bytes:
        """Fetch decryption key from URL"""
        async with session.get(url, headers=request_headers()) as resp:
            assert resp.status == 200, "Could not fetch decryption key."
            return await resp.read()

    async def make_cipher_for_segment(session: aiohttp.ClientSession, segment):
        """Create AES cipher for decrypting segment"""
        key = await get_key(session, segment.key.absolute_uri)
        iv = bytes.fromhex(segment.key.iv.lstrip("0x"))
        return AES.new(key, AES.MODE_CBC, IV=iv)

    async def download_and_decrypt_segments(
        session: aiohttp.ClientSession, segments, stream_path
    ):
        """Download all segments and write decrypted data to file"""
        with open(stream_path, mode="wb") as file:
            for segment in tqdm.asyncio.tqdm(segments, desc="Downloading segments"):
                cipher = await make_cipher_for_segment(session, segment)

                async with session.get(
                    segment.absolute_uri, headers=request_headers()
                ) as resp:
                    assert (
                        resp.status == 200
                    ), f"Could not download segment: {segment.absolute_uri}"

                    buffer = b""
                    async for chunk in resp.content.iter_chunked(8192):
                        buffer += chunk
                        # Process complete 16-byte blocks
                        while len(buffer) >= 16:
                            block = buffer[:16]
                            buffer = buffer[16:]
                            decrypted = cipher.decrypt(block)
                            file.write(decrypted)

                    # Last block (should be padded by server)
                    if buffer:
                        decrypted = cipher.decrypt(buffer)
                        file.write(decrypted)

    # Parse M3U8 playlist (m3u8 library uses requests, but we can parse locally)
    # If m3u8_url is remote, fetch it first
    async with aiohttp.ClientSession() as session:
        async with session.get(m3u8_url, headers=request_headers()) as resp:
            m3u8_content = await resp.text()

        # Parse M3U8 (synchronous operation)
        import io

        playlist = m3u8.loads(m3u8_content, uri=m3u8_url)
        segments = playlist.segments

        stream_path = Path(download_path) / "stream.ts"
        await download_and_decrypt_segments(session, segments, stream_path)

    logger.info(f"Медиафайл успешно скачан и сохранен как: {stream_path}")


# ***********************************************************************************************************
# Расшифровка URL адреса HLS

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


# ***********************************************************************************************************


async def get_book_info(book_url):
    """
    Асинхронно получает информацию о книге с akniga.org.

    Args:
        book_url (str): URL страницы книги на akniga.org.

    Returns:
        dict: Словарь с информацией о книге, или None в случае ошибки.
    """
    try:
        async with aiohttp.ClientSession() as session:
            session.headers.update({"user-agent": user_agent()})

            # --- Шаг 1: GET-запрос к странице книги ---
            try:
                async with session.get(book_url, timeout=15) as response:
                    response.raise_for_status()  # Выбросит исключение для статусов 4xx/5xx
                    html = await response.text()
            except aiohttp.ClientError as e:
                logger.error(f"Ошибка HTTP при GET-запросе к {book_url}: {e}")
                return None
            except asyncio.TimeoutError:
                logger.error(f"Таймаут при GET-запросе к {book_url}")
                return None
            except Exception as e:
                logger.error(f"Неизвестная ошибка при GET-запросе к {book_url}: {e}")
                return None

            # --- Шаг 2: Парсинг HTML для извлечения book_id и LIVESTREET_SECURITY_KEY ---
            try:
                # Извлечение cookie, если это необходимо для последующих запросов
                cookies = session.cookie_jar.filter_cookies("https://akniga.org")
                cookies_dict = {name: morsel.value for name, morsel in cookies.items()}

                book_id = html.split("data-bid=")[1].split('"')[1]
                LIVESTREET_SECURITY_KEY = (
                    html.split("LIVESTREET_SECURITY_KEY")[1]
                    .split("=")[1]
                    .split(",")[0]
                    .strip()
                    .split("'")[1]
                )
            except IndexError as e:
                logger.error(
                    f"Ошибка парсинга HTML (не найден book_id или LIVESTREET_SECURITY_KEY) на {book_url}: {e}"
                )
                return None
            except Exception as e:
                logger.error(f"Неизвестная ошибка при парсинге HTML на {book_url}: {e}")
                return None

            # --- Шаг 3: POST-запрос к AJAX API ---
            try:
                ajax_url = f"https://akniga.org/ajax/b/{book_id}"
                data = {
                    "bid": book_id,
                    "hls": "true",
                    "security_ls_key": LIVESTREET_SECURITY_KEY,
                }
                data_str = urlencode(data)

                # Обновляем заголовки для POST-запроса
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

                async with session.post(
                    ajax_url, data=data_str, timeout=15
                ) as response_ajax:
                    response_ajax.raise_for_status()  # Выбросит исключение для статусов 4xx/5xx
                    resp_text = await response_ajax.text()
            except aiohttp.ClientError as e:
                logger.error(f"Ошибка HTTP при POST-запросе к {ajax_url}: {e}")
                return None
            except asyncio.TimeoutError:
                logger.error(f"Таймаут при POST-запросе к {ajax_url}")
                return None
            except Exception as e:
                logger.error(f"Неизвестная ошибка при POST-запросе к {ajax_url}: {e}")
                return None

            # --- Шаг 4: Парсинг JSON-ответа и декодирование информации ---
            try:
                resp_json = json.loads(resp_text)

                hls = decode_url(resp_json["hres"])
                # Убедитесь, что decode_book_info корректно обрабатывает возможные отсутствующие ключи
                book_info = decode_book_info(resp_json)

                book_info["hls"] = hls
                book_info["book_id"] = book_id
                book_info["security_ls_key"] = LIVESTREET_SECURITY_KEY
                book_info["user_agent"] = user_agent()
                book_info["cookies"] = cookies_dict

                return book_info
            except json.JSONDecodeError as e:
                logger.error(
                    f"Ошибка декодирования JSON-ответа от {ajax_url}: {e}. Ответ: {resp_text[:200]}..."
                )  # Показать часть ответа
                return None
            except KeyError as e:
                logger.error(
                    f"Ошибка: отсутствующий ключ в JSON-ответе от {ajax_url}: {e}. Ответ: {resp_json}"
                )
                return None
            except Exception as e:
                logger.error(
                    f"Неизвестная ошибка при обработке JSON-ответа или декодировании: {e}"
                )
                return None

    # Общий блок исключений для любых ошибок, которые могли не быть перехвачены выше
    except Exception as e:
        logger.error(
            f"Произошла непредвиденная ошибка в get_book_info для {book_url}: {e}"
        )
        return None


async def download_cover(url, download_path):

    filename = Path(download_path) / "cover.jpg"
    """
    Скачивает изображение по указанному URL и сохраняет его в файл.

    Args:
        url (str): URL изображения для скачивания.
        filename (str): Имя файла для сохранения изображения (например, 'cover.jpg').
    """
    async with aiohttp.ClientSession() as session:
        session.headers.update({"user-agent": user_agent()})

        try:
            async with session.get(url) as response:
                response.raise_for_status()  # Выбросит исключение для статусов 4xx/5xx

                # Проверяем, что это действительно изображение (опционально, но рекомендуется)
                if "image" not in response.headers.get("Content-Type", "").lower():
                    logger.error(
                        f"URL {url} не указывает на изображение. Content-Type: {response.headers.get('Content-Type')}"
                    )
                    return False

                with open(filename, "wb") as f:
                    # Читаем содержимое блоками, чтобы не загружать весь файл в память для больших изображений
                    while True:
                        chunk = await response.content.read(1024)  # Читаем по 1 КБ
                        if not chunk:
                            break
                        f.write(chunk)
                logger.info(f"Изображение успешно скачано и сохранено как {filename}")
                return True

        except aiohttp.ClientError as e:
            logger.error(f"Ошибка при скачивании изображения с {url}: {e}")
        except asyncio.TimeoutError:
            logger.error(f"Таймаут при скачивании изображения с {url}")
        except Exception as e:
            logger.error(f"Неизвестная ошибка: {e}")
        return False


async def save_book_info(book_info: dict, download_path: str):

    filename = Path(download_path) / "book_info.json"
    """
    Асинхронно сохраняет словарь в JSON файл.

    Args:
        data (dict): Словарь, который нужно сохранить.
        filename (str): Имя файла (например, 'metadata.json').
    """
    try:
        # Преобразуем словарь в JSON строку
        json_string = json.dumps(book_info, indent=4, ensure_ascii=False)

        # Открываем файл асинхронно и записываем данные
        async with aiofiles.open(filename, mode="w", encoding="utf-8") as f:
            await f.write(json_string)

        logger.info(f"Информация о книге успешно скачана и сохранена как {filename}")
    except IOError as e:
        logger.error(f"Ошибка ввода/вывода при сохранении файла {filename}: {e}")
    except TypeError as e:
        logger.error(
            f"Ошибка сериализации JSON (данные не могут быть преобразованы в JSON): {e}"
        )
    except Exception as e:
        logger.error(f"Неизвестная ошибка: {e}")


async def start(args):
    book_info = await get_book_info(args.url)

    await save_book_info(book_info, args.path)
    if args.download_cover:
        if not await download_cover(book_info["cover"], args.path):
            await download_cover(book_info["cover_100"], args.path)

    if args.download_media:
        await download_book_by_m3u8(book_info["hls"], args.path)


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
        "-v",
        help="Уровень логирования по умолчанию (если ключ не задан) - error. warning -v, info -vv, debug -vvv",
        action="count",
        default=0,
        dest="verbose",
    )

    parser.add_argument(
        "--media",
        "-m",
        help="Скачать медиафайл",
        action="store_true",
        dest="download_media",
    )
    parser.add_argument(
        "--cover",
        "-c",
        help="Скачать обложку",
        action="store_true",
        dest="download_cover",
    )
    parser.add_argument("--output", "-o", help=("Каталог для загрузки"), dest="path")

    parser.add_argument(
        "url",
        help=("url книги"),
    )

    args = parse_args(parser, logger)
    logger.info(args)

    asyncio.run(start(args))
