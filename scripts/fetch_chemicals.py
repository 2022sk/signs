"""chemicare 현장 페이지에서 화학물질 목록을 읽어 chemicals.json으로 저장한다.

현장 페이지 주소(CHEMICARE_URL)와 사이트 암호(SITE_PASSWORD)는 저장소 Secret으로 받는다.
목록은 사이트 암호로 AES-256-GCM 암호화해서만 저장한다 (암호 → PBKDF2-SHA256 키).
사용법: CHEMICARE_URL=... SITE_PASSWORD=... python scripts/fetch_chemicals.py [저장할 경로]
"""
import base64
import json
import os
import re
import sys
import time
import urllib.request
from datetime import datetime, timezone, timedelta
from html import unescape

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def fetch(url, tries=4):
    # 무료 서버는 잠들어 있으면 첫 응답까지 1분 가까이 걸릴 수 있다
    for n in range(tries):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'storage-signs-sync'})
            with urllib.request.urlopen(req, timeout=120) as r:
                return r.read().decode('utf-8')
        except Exception as e:
            if n == tries - 1:
                raise
            print('retry after error:', e)
            time.sleep(20)


def text(s):
    return unescape(re.sub(r'\s+', ' ', s)).strip()


def labeled(card, label):
    m = re.search(r'<span class="text-black/40">' + label + r'</span>\s*<span[^>]*>(.*?)</span>', card, re.S)
    return text(m.group(1)) if m else ''


def parse(html):
    starts = [m.start() for m in re.finditer(r'data-chemical-row="\d+"', html)]
    out = []
    for i, st in enumerate(starts):
        card = html[st: starts[i + 1] if i + 1 < len(starts) else len(html)]
        cid = re.match(r'data-chemical-row="(\d+)"', card).group(1)
        name = re.search(r'name="product_name" value="([^"]*)"', card)
        maker = re.search(r'name="manufacturer" value="([^"]*)"', card)
        vendor = re.search(r'<select name="vendor_id".*?<option value="\d+" selected>(.*?)</option>', card, re.S)
        out.append({
            'id': int(cid),
            'name': unescape(name.group(1)).strip() if name else '',
            'maker': unescape(maker.group(1)).strip() if maker else '',
            'vendor': text(vendor.group(1)) if vendor else '',
            'hazmat': labeled(card, '위험물 분류'),
            'limit': labeled(card, '지정수량'),
        })
    return [c for c in out if c['name']]


ITER = 310000


def encrypt(data, password):
    salt, iv = os.urandom(16), os.urandom(12)
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER).derive(password.encode())
    ct = AESGCM(key).encrypt(iv, json.dumps(data, ensure_ascii=False).encode(), None)
    b64 = lambda b: base64.b64encode(b).decode()
    return {'v': 1, 'iter': ITER, 'salt': b64(salt), 'iv': b64(iv), 'data': b64(ct)}


def decrypt(enc, password):
    d = lambda s: base64.b64decode(s)
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=d(enc['salt']), iterations=enc['iter']).derive(password.encode())
    return json.loads(AESGCM(key).decrypt(d(enc['iv']), d(enc['data']), None))


def main():
    url = os.environ.get('CHEMICARE_URL')
    password = os.environ.get('SITE_PASSWORD')
    if not url or not password:
        sys.exit('CHEMICARE_URL, SITE_PASSWORD 환경변수(저장소 Secret)가 필요합니다.')
    path = sys.argv[1] if len(sys.argv) > 1 else 'chemicals.enc.json'
    items = parse(fetch(url))
    if not items:
        sys.exit('화학물질을 하나도 읽지 못했습니다. 페이지 구조가 바뀌었는지 확인하세요.')
    items.sort(key=lambda c: c['name'].lower())
    # 내용과 암호가 그대로면 파일을 다시 쓰지 않아 불필요한 커밋을 막는다
    try:
        if decrypt(json.load(open(path, encoding='utf-8')), password).get('items') == items:
            print('변경 없음:', len(items), '개')
            return
    except Exception:
        pass
    data = {
        'updated': datetime.now(timezone(timedelta(hours=9))).strftime('%Y-%m-%d %H:%M'),
        'items': items,
    }
    json.dump(encrypt(data, password), open(path, 'w', encoding='utf-8'))
    print('암호화 저장:', len(items), '개')


if __name__ == '__main__':
    main()
