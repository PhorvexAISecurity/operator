"""A minimal Telegram Bot API client: long polling, messages and documents.

Long polling (getUpdates) needs no inbound port or public certificate on the
jump host. The HTTP call is injected, so the tests need no network. The bot
token is part of every request URL, so URLs are never logged or put in an
exception.
"""
import json
import mimetypes
import re
import urllib.error
import urllib.request
import uuid

API = 'https://api.telegram.org'
TOKEN = re.compile(r'^\d{5,}:[A-Za-z0-9_-]{30,}$')
MESSAGE_LIMIT = 4096


class TelegramError(Exception):
    pass


def urllib_transport(url, data, headers, timeout):  # pragma: no cover - network
    req = urllib.request.Request(url, data=data, headers=headers, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except urllib.error.HTTPError as err:
        return err.read()
    except (urllib.error.URLError, OSError) as err:
        raise TelegramError('Telegram API unreachable: %s' % getattr(err, 'reason', type(err).__name__))


def urllib_download(url, max_bytes, timeout):  # pragma: no cover - network
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            if int(response.headers.get('Content-Length') or 0) > max_bytes:
                raise TelegramError('Document exceeds the download limit')
            return response.read(max_bytes + 1)
    except urllib.error.HTTPError as err:
        raise TelegramError('Document download failed (HTTP %d)' % err.code) from None
    except (urllib.error.URLError, OSError, ValueError):
        raise TelegramError('Document download failed; try uploading the file again') from None


class Telegram:
    def __init__(self, token, transport=urllib_transport, api=API, download_transport=urllib_download):
        if not TOKEN.match(token or ''):
            raise TelegramError('TELEGRAM_BOT_TOKEN is missing or malformed')
        self._token, self.transport, self.api = token, transport, api.rstrip('/')
        self.download_transport = download_transport

    def call(self, method, params=None, files=None, timeout=70):
        url = '%s/bot%s/%s' % (self.api, self._token, method)
        if files:
            data, ctype = _multipart(params or {}, files)
        else:
            data, ctype = json.dumps(params or {}).encode(), 'application/json'
        raw = self.transport(url, data, {'Content-Type': ctype}, timeout)
        try:
            reply = json.loads(raw)
        except (TypeError, ValueError):
            raise TelegramError('%s: unreadable reply' % method)
        if not reply.get('ok'):
            raise TelegramError('%s: %s' % (method, reply.get('description', 'failed')))
        return reply.get('result')

    def get_updates(self, offset=None, timeout=50):
        params = {'timeout': timeout, 'allowed_updates': ['message']}
        if offset is not None:
            params['offset'] = offset
        return self.call('getUpdates', params, timeout=timeout + 20)

    def send_message(self, chat_id, text):
        receipt = None
        for start in range(0, max(len(text), 1), MESSAGE_LIMIT):
            receipt = self.call('sendMessage', {'chat_id': chat_id, 'text': text[start:start + MESSAGE_LIMIT],
                                      'disable_web_page_preview': True})
        return receipt

    def edit_message(self, chat_id, message_id, text):
        return self.call('editMessageText', {'chat_id': chat_id, 'message_id': message_id,
                                           'text': text[:MESSAGE_LIMIT], 'disable_web_page_preview': True})

    def download_document(self, file_id, max_bytes):
        info = self.call('getFile', {'file_id': file_id}) or {}
        if info.get('file_size', 0) > max_bytes:
            raise TelegramError('Document exceeds the download limit')
        path = info.get('file_path') or ''
        if not re.fullmatch(r'[A-Za-z0-9_./-]+', path) or any(part in ('', '.', '..') for part in path.split('/')):
            raise TelegramError('Telegram returned an invalid document path')
        data = self.download_transport('%s/file/bot%s/%s' % (self.api, self._token, path), max_bytes, 60)
        if not isinstance(data, bytes) or len(data) > max_bytes:
            raise TelegramError('Document exceeds the download limit')
        return data

    def send_document(self, chat_id, filename, data, caption=None):
        params = {'chat_id': str(chat_id)}
        if caption:
            params['caption'] = caption[:1000]
        return self.call('sendDocument', params, files={'document': (filename, data)})


def _multipart(params, files):
    boundary = 'phorvex-' + uuid.uuid4().hex
    out = bytearray()
    for k, v in params.items():
        out += ('--%s\r\nContent-Disposition: form-data; name="%s"\r\n\r\n%s\r\n' % (boundary, k, v)).encode()
    for k, (name, data) in files.items():
        safe = re.sub(r'[^A-Za-z0-9._-]', '_', name)
        mime_type = mimetypes.guess_type(safe)[0] or 'application/octet-stream'
        out += ('--%s\r\nContent-Disposition: form-data; name="%s"; filename="%s"\r\n'
                'Content-Type: %s\r\n\r\n' % (boundary, k, safe, mime_type)).encode()
        out += data + b'\r\n'
    out += ('--%s--\r\n' % boundary).encode()
    return bytes(out), 'multipart/form-data; boundary=' + boundary
