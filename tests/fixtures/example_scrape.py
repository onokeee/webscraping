"""reqrec が生成するスクリプトの例（手書き）

これは ``reqrec generate tests/fixtures/login_flow_chrome.har -o scrape.py`` が出力するものと
同じ構成で手書きした「例」です。実際の出力はヘッダの中身やコメントの文言など細部が異なります。
読み方は README の「生成コードの読み方」を参照してください。
（バイト列を渡す _soup はフェーズ 2 の生成コードに合わせたものです。）

generated-by: reqrec 0.1.0
source: har tests/fixtures/login_flow_chrome.har (WebInspector/537.36)
steps: 5
warnings:
  - step 2: `password` looks like a credential; the script reads it from the
    environment variable REQREC_PASSWORD (set it before running)
"""

import json
import os
import re
import sys
import time
from urllib.parse import unquote, urljoin  # noqa: F401  (生成コードは常に同じ import ブロックを持つ)

import requests
from bs4 import BeautifulSoup

# ---------------------------------------------------------------- 設定
TIMEOUT = 30.0  # 各リクエストのタイムアウト（秒）
DELAY = 0.0  # ステップ間の待ち時間（秒）。サーバーに負荷をかけないよう必要に応じて増やす

# ---------------------------------------------------------------- 定数 / 秘密情報
# 秘密情報: 記録した値はコードに埋め込まず、環境変数から読み込みます（step 2 の form `password`）
PASSWORD = os.environ.get("REQREC_PASSWORD", "")

# すべてのリクエストで共通だったヘッダ（記録したブラウザのもの）
BASE_HEADERS = {
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "accept-language": "ja,en-US;q=0.9,en;q=0.8",
    "sec-ch-ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
}

# 記録を開始した時点でブラウザが既に持っていた Cookie（記録中に Set-Cookie されなかったもの）。
# 期限切れになったら記録し直してください。
INITIAL_COOKIES = [
    # {"name": "lang", "value": "ja", "domain": "shop.example.test", "path": "/"},
]


# ---------------------------------------------------------------- ヘルパー
def _soup(resp):
    """レスポンスの HTML（バイト列）を BeautifulSoup にする。文字コードは <meta charset> 等から自動判定される。"""
    return BeautifulSoup(resp.content, "html.parser")


def _check(resp, expected, step):
    """エラー応答（4xx/5xx）なら例外にし、記録時と違うステータスなら警告を出す。"""
    if resp.status_code != expected:
        print("[警告] %s: ステータスコード %s (記録時: %s) %s" % (step, resp.status_code, expected, resp.url), file=sys.stderr)
    resp.raise_for_status()


def _regex(text, pattern):
    """正規表現の 1 つ目のグループを返す。見つからなければどのパターンかを示して失敗する。"""
    m = re.search(pattern, text)
    if not m:
        raise RuntimeError("正規表現にマッチしませんでした: %r" % pattern)
    return m.group(1)


def _json_path(data, path):
    """JSON を ["data", "items", 0, "id"] のようなパスでたどる。"""
    cur = data
    for key in path:
        try:
            cur = cur[key]
        except (KeyError, IndexError, TypeError):
            raise RuntimeError("JSON にパスが見つかりません: %r" % (path,))
    return cur


def _attr(soup, selector, attr):
    el = soup.select_one(selector)
    if el is None or not el.has_attr(attr):
        raise RuntimeError("要素または属性が見つかりません: %r [%s]" % (selector, attr))
    return el[attr]


def _text(soup, selector):
    el = soup.select_one(selector)
    if el is None:
        raise RuntimeError("要素が見つかりません: %r" % selector)
    return el.get_text(strip=True)


# ---------------------------------------------------------------- ステップ
def step_01_get_login(session):
    """GET https://shop.example.test/login -> 200 text/html"""
    resp = session.get(
        "https://shop.example.test/login",
        headers={
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "none",
            "upgrade-insecure-requests": "1",
        },
        timeout=TIMEOUT,
    )
    _check(resp, 200, 'step_01_get_login')
    soup = _soup(resp)
    # ログインフォームの hidden input `_token`（CSRF トークン）。step 2 の form `_token` で使う
    # 記録時の値: 'tokA1b2C3d4E5f6G7h8'
    token = soup.find("input", {"name": "_token"})["value"]
    return resp, {"token": token}


def step_02_post_login(session, token):
    """POST https://shop.example.test/login -> 302 -> GET /dashboard -> 200 text/html（リダイレクトをまとめた）"""
    resp = session.post(
        "https://shop.example.test/login",
        data={
            "_token": token,  # step 1 で抽出
            "username": "alice",
            "password": PASSWORD,  # 環境変数 REQREC_PASSWORD
        },
        headers={
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "origin": "https://shop.example.test",
            "referer": "https://shop.example.test/login",
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "same-origin",
        },
        timeout=TIMEOUT,
    )
    _check(resp, 200, 'step_02_post_login')
    soup = _soup(resp)
    # ダッシュボードのインライン script 内 `window.API_TOKEN = "..."`。step 3, 4 の Authorization ヘッダで使う
    api_token = _regex(resp.text, '  window\\.API_TOKEN = "([^"\'&<>\\s]+?)";')
    # <meta name="csrf-token" content="..."> 。step 3, 4 の X-CSRF-Token ヘッダで使う
    x_csrf_token = soup.find("meta", {"name": "csrf-token"})["content"]
    # エクスポートリンクの href に含まれる署名。step 5 のクエリ `sig` で使う
    sig = _regex(_attr(soup, "a#export-link", "href"), "sig=([^\"'&<>\\s]+?)$")
    return resp, {"api_token": api_token, "x_csrf_token": x_csrf_token, "sig": sig}


def step_03_get_v1_me(session, api_token, x_csrf_token):
    """GET https://api.example.test/v1/me -> 200 application/json"""
    resp = session.get(
        "https://api.example.test/v1/me",
        headers={
            "accept": "application/json, text/plain, */*",
            "authorization": "Bearer " + api_token,  # step 2 で抽出
            "origin": "https://shop.example.test",
            "referer": "https://shop.example.test/dashboard",
            "x-csrf-token": x_csrf_token,  # step 2 で抽出
            "x-requested-with": "XMLHttpRequest",
        },
        timeout=TIMEOUT,
    )
    _check(resp, 200, 'step_03_get_v1_me')
    return resp, {}


def step_04_get_orgs_items(session, page, api_token, x_csrf_token):
    """GET https://api.example.test/v1/orgs/77/items?page=N -> 200 application/json（ページ送り: page=1..3）"""
    resp = session.get(
        "https://api.example.test/v1/orgs/77/items",
        params={"page": page},  # ループ変数
        headers={
            "accept": "application/json, text/plain, */*",
            "authorization": "Bearer " + api_token,
            "origin": "https://shop.example.test",
            "referer": "https://shop.example.test/dashboard",
            "x-csrf-token": x_csrf_token,
        },
        timeout=TIMEOUT,
    )
    _check(resp, 200, 'step_04_get_orgs_items')
    return resp, {}


def step_05_get_export(session, sig):
    """GET https://shop.example.test/export?sig=... -> 200 text/csv（ダウンロード）"""
    resp = session.get(
        "https://shop.example.test/export",
        params={"sig": sig},  # step 2 で抽出
        headers={
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "referer": "https://shop.example.test/dashboard",
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "same-origin",
        },
        timeout=TIMEOUT,
    )
    _check(resp, 200, 'step_05_get_export')
    return resp, {}


# ---------------------------------------------------------------- 実行
def _print_result(resp):
    """最後のステップの結果を表示する（JSON / HTML / テキスト / バイナリで出し分け）。"""
    ctype = resp.headers.get("content-type", "")
    if "json" in ctype:
        print(json.dumps(resp.json(), ensure_ascii=False, indent=2))
    elif "html" in ctype:
        soup = _soup(resp)
        print("title:", soup.title.get_text(strip=True) if soup.title else "(なし)")
        # ここに BeautifulSoup で欲しいデータを取り出す処理を書く
    elif ctype.startswith("text/") or not resp.content:
        print(resp.text[:2000])
    else:
        with open("output.bin", "wb") as fh:
            fh.write(resp.content)
        print("バイナリの結果を output.bin に保存しました (%d bytes)" % len(resp.content))


def main():
    if not PASSWORD:
        print("警告: 環境変数 REQREC_PASSWORD が設定されていません", file=sys.stderr)

    session = requests.Session()
    # 統合 Windows 認証のサイトならここに session.auth = ... が入る
    session.headers.update(BASE_HEADERS)
    for c in INITIAL_COOKIES:
        session.cookies.set(c["name"], c["value"], domain=c["domain"], path=c["path"])

    ctx = {}  # 抽出した値をステップ間で受け渡す
    results = []  # ループしたステップの結果

    resp, out = step_01_get_login(session)
    ctx.update(out)
    time.sleep(DELAY)

    resp, out = step_02_post_login(session, token=ctx["token"])
    ctx.update(out)
    time.sleep(DELAY)

    resp, out = step_03_get_v1_me(session, api_token=ctx["api_token"], x_csrf_token=ctx["x_csrf_token"])
    ctx.update(out)
    time.sleep(DELAY)

    for page in range(1, 4):  # 記録時: page=1, 2, 3
        resp, out = step_04_get_orgs_items(session, page, api_token=ctx["api_token"], x_csrf_token=ctx["x_csrf_token"])
        ctx.update(out)
        results.append(resp.json())
        time.sleep(DELAY)

    resp, out = step_05_get_export(session, sig=ctx["sig"])
    ctx.update(out)

    _print_result(resp)
    return results


if __name__ == "__main__":
    main()
