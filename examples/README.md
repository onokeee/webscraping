# examples — 同梱のサンプルで試す

`tests/fixtures/` には、実際のブラウザが出力する形に合わせて手書きした HAR ファイルが入っています。
これを使うと、サイトに一切アクセスせずに reqrec の動きを確認できます。GUI でも CLI でも同じファイルが使えます。

| ファイル | 内容 |
|---|---|
| `tests/fixtures/login_flow_chrome.har` | Chrome の DevTools 風 HAR。ログインページ → CSRF トークン付き POST → リダイレクト → ダッシュボード → Bearer トークン付き JSON API → ページ送り（page=1..3）→ CSV ダウンロード。静的ファイル・トラッカー・CORS preflight などのノイズも含む |
| `tests/fixtures/api_firefox.har` | Firefox 風 HAR。JSON でログインしてアクセストークンを受け取り、API を呼ぶ SPA |
| `tests/fixtures/legacy_webforms_ntlm.har` | **Edge IE モード風**の社内サイト（`http://intra.example.local/`）。統合 Windows 認証（NTLM の 401 → 401 → 200 の 3 往復）、charset なしの Shift_JIS な ASP.NET WebForms ページ（`__VIEWSTATE` / `__EVENTVALIDATION`）、Shift_JIS で URL エンコードされた検索フォームの POST（`%93%FA%96%7B` = 「日本」）、検索結果から `Report.aspx?id=1234` へ、CSV エクスポート、`WebResource.axd`（捨てられる JS） |

## 1. GUI で試す（コードを書かない）

```console
$ reqrec gui
GUI を起動しました: http://127.0.0.1:8765  (Ctrl+C で終了)
```

1. **2 読み込み** — 「ファイルを選んで読み込む」に `tests/fixtures/login_flow_chrome.har` をドラッグ＆ドロップ
   （またはクリックして選択）し、[読み込む]。「現在読み込まれている記録」に `uploads/login_flow_chrome.har`、
   リクエスト数 14 件、ホスト `shop.example.test` / `api.example.test` などが表示されます。
2. **3 ステップ** — 自動で解析され、「解析結果」が **ステップ 5 / 採用リクエスト 8 / 除外 6** になります。
   表では、`/static/logo.png`（`static asset`）や `ads.tracker.example.test`（`tracker/analytics host`）、
   `OPTIONS`（`CORS preflight`）の行が灰色＝除外、`/login` → `/dashboard` のリダイレクトは同じステップ番号 `2` に
   まとまっています。
   - `https://api.example.test/v1/me` の行の **「採用」チェックを外す**と、即座に再計算されてステップが 4 になり、
     その行の判定が「手動で除外」（CLI の `inspect` では `excluded by user`）になります（もう一度チェックすると戻ります）。
   - `/v1/orgs/77/items?page=1` の行の **「結果」ラジオ**を選ぶと、「解析結果 → 結果にするステップ」がそのステップに
     変わります。生成されるスクリプトは全ステップを実行したあと、この JSON（ループなので 3 ページ分のリスト）を表示します。
   - `/login`（POST）の行をクリックすると詳細ドロワーが開き、リクエスト本文の `_token` / `password` と、レスポンスの
     HTML（`<meta name="csrf-token">` や `window.API_TOKEN`）を見比べられます。
3. **4 コード** — [生成]。プレビューに `def step_01_get_login(session):` から始まるスクリプトが出ます。
   「実行時に必要な環境変数」に `REQREC_PASSWORD` が出ているのを確認し、ファイル名に `scrape_example` と入れて [保存]
   （`reqrec_work/scripts/scrape_example.py` に保存されます）。[ダウンロード] でも取り出せます。
4. **5 実行** — `scrape_example` を選ぶと `REQREC_PASSWORD` の入力欄が出ます。ただし、このサンプルのホスト
   （`shop.example.test`）は架空なので、[実行] しても接続エラーで終わります（標準エラーに `ConnectionError` が出て
   「エラー終了」になることを確認するだけです）。自分で記録したファイルなら、ここで結果が標準出力に表示され、
   [結果を保存] で `reqrec_work/outputs/` に残せます。

`tests/fixtures/legacy_webforms_ntlm.har` を読み込むと、「解析結果 → HTTP 認証」に `ntlm`（`intra.example.local`）と
記録時のユーザー名が表示され、`Default.aspx` の 401 の 2 行は成功した 3 行目と同じステップにまとまります。
フィルタ設定の「古い TLS / 暗号しか使えないサーバー … 向けの接続設定を生成コードに入れる」をチェックして
[生成] すると、コードに `_LegacyTLSAdapter` が加わるのが分かります。

## 2. 何が残り、何が捨てられるかを見る（CLI）

リポジトリのルートで:

```console
$ reqrec inspect tests/fixtures/login_flow_chrome.har
入力: tests/fixtures/login_flow_chrome.har  (har, WebInspector/537.36)
フロー合計 14 件 / 採用 8 件 → ステップ 5 件 / 除外 6 件

ステップ (5 件):
#   FLOW               METHOD  STATUS   URL                                              抽出する変数 / ループ
--  -----------------  ------  -------  -----------------------------------------------  -----------------------------------------
01  f0001              GET     200      https://shop.example.test/login                  token←html_input[_token]
02  f0008+f0009        POST    302→200  https://shop.example.test/login                  api_token←regex[window\.API_TOKEN\ =\ "…]
                                                                                         x_csrf_token←html_meta[csrf-token]
                                                                                         sig←html_attr[#export-link@href]
03  f0010              GET     200      https://api.example.test/v1/me                   org_id←json[org.id]
04  f0011+f0012+f0013  GET ×3  200      https://api.example.test/v1/orgs/{org_id}/items  ループ page=1..3 (3回)
05  f0014              GET     200      https://shop.example.test/export                 -
  （FLOW はフロー ID。--exclude-flow / --include-flow / --final-flow で指定できます）

除外されたリクエスト (6 件):
  CORS preflight — 1 件
      f0007  https://api.example.test/v1/login
  ...
```

- `302→200` は「POST → リダイレクト → GET」が 1 ステップにまとめられたことを示します。FLOW（フロー ID）が
  `f0008+f0009` と 2 つあるのはそのためです。
- `GET ×3` と `ループ page=1..3` は、`page=1,2,3` の 3 回のリクエストが 1 つのループに折りたたまれたことを示します。
- `token←html_input[_token]` は「ステップ 1 のレスポンス HTML の `<input name="_token">` から値を取り出し、
  後のステップで使う」という意味です。
- `org_id←json[org.id]` は `/v1/me` の JSON から取り出した値で、ステップ 4 の URL の `{org_id}` に入ります。
- FLOW 列のフロー ID（`f0001` …）は次の「手動で調整する」で使います。

`--json` を付けると同じ内容を JSON で得られます（スクリプトから扱うときに便利です）。

```console
$ reqrec inspect tests/fixtures/login_flow_chrome.har --json | python -m json.tool | head
```

## 3. 手動で調整する（除外と「結果にするステップ」）

GUI のチェック / ラジオと同じことを CLI で行います。

```console
# ステップ 3（/v1/me）を外す → ステップは 4 件になり、除外一覧に "excluded by user" で出る
$ reqrec inspect tests/fixtures/login_flow_chrome.har --exclude-step 3

# 同じことをフロー ID で（inspect の FLOW 列を見て指定。カンマ区切り・繰り返し可）
$ reqrec inspect tests/fixtures/login_flow_chrome.har --exclude-flow f0010

# 除外されていた静的ファイル 1 件だけを強制的に採用する
$ reqrec inspect tests/fixtures/login_flow_chrome.har --include-flow f0002

# 最後の CSV ではなく、一覧 JSON（ステップ 4 のループ）を「結果」として表示するスクリプトにする
$ reqrec generate tests/fixtures/login_flow_chrome.har -o scrape_example.py --final-step 4
```

`--final-step` / `--final-flow` を付けても全ステップは実行されます。変わるのは `main()` の最後に表示される結果だけです。

## 4. スクリプトを生成する

```console
$ reqrec generate tests/fixtures/login_flow_chrome.har -o scrape_example.py
ステップ 5 件を生成します（フロー合計 14 件 / 除外 6 件 / 抽出する変数 4 個 / ループ 1 個）
秘密情報は環境変数から読み込みます。実行前に設定してください: REQREC_PASSWORD
警告 (1 件):
  - step 2: `password` looks like a credential; the script reads it from the environment variable REQREC_PASSWORD (set it before running)
スクリプトを書き出しました: scrape_example.py
```

生成された `scrape_example.py` を開いて、`step_01_get_login` … `step_05_get_export` の各関数と `main()` を
読んでみてください。ログイン時のパスワードはコードに埋め込まれず、環境変数 `REQREC_PASSWORD` から読む
ようになっています。先頭の設定ブロックには `VERIFY_TLS = True` があり、`main()` で `session.verify` に設定されます。

解析結果そのもの（Plan）を見たい場合は `--dump-plan plan.json` を付けます。

```console
$ reqrec generate tests/fixtures/login_flow_chrome.har -o scrape_example.py --dump-plan plan.json
```

## 5. 別タブの HAR を結合する（複数入力）

新しいタブで開いた画面を DevTools でタブごとに保存した場合（README の「別タブで開く画面を記録する」）、
ファイルを並べて渡すだけです。すべてのリクエストが開始時刻の順に並べ直され、1 つの記録として解析されます。

```console
$ reqrec inspect  tab1.har tab2.har                   # 「入力:」に両方のファイル名が出る
$ reqrec generate tab1.har tab2.har -o scrape.py
$ reqrec import   tab1.har tab2.har -o rec.json       # 結合した記録を 1 つの JSON として保存しておく
```

GUI では「2 読み込み」で 2 つのファイルを同時に選ぶか、1 つずつ「追加して結合」にチェックして読み込みます。

## 6. IE モード風のサンプル（NTLM + Shift_JIS + WebForms）

```console
$ reqrec inspect tests/fixtures/legacy_webforms_ntlm.har
```

確認するポイント:

- `Default.aspx` への 3 回の `GET`（401, 401, 200）が **1 つのステップ**（FLOW `f0001+f0002+f0003`、STATUS `401→401→200`）に
  まとまり、ヘッダー部に `認証: NTLM (記録時のユーザー: EXAMPLE\taro) → 生成コードは session.auth を設定します…` と
  表示される。ステップのヘッダに `Authorization` は残らない。
- ステップは 4 件（`GET Default.aspx` → `POST Default.aspx`（検索）→ `GET Report.aspx?id=1234` → `GET Export.aspx?id=1234&fmt=csv`）。
  `WebResource.axd`（JavaScript）は静的ファイルとして除外される。
- `POST Default.aspx` の `__VIEWSTATE` / `__VIEWSTATEGENERATOR` / `__EVENTVALIDATION` が、直前のページの
  `html_input` から抽出する変数になる。`Report.aspx?id=1234` の `id` は検索結果ページの `<a href>` から抽出される。
- 検索語（`ctl00$txtKeyword=%93%FA%96%7B`）は Shift_JIS で URL エンコードされているため警告が出て、生成コードでは
  `data=urlencode({...})` の中に `b'\x93\xfa\x96{'  # cp932 で「日本」` のようにバイト列のまま残る（`__VIEWSTATE` などは
  取得した値に差し替わる）。

```console
$ reqrec generate tests/fixtures/legacy_webforms_ntlm.har -o legacy_example.py --legacy-tls
```

生成コードの `main()` 冒頭に `requests_negotiate_sspi` / `requests_ntlm` を使う `session.auth` の設定、
`VERIFY_TLS` と `_LegacyTLSAdapter`（`--legacy-tls` を付けたため）が入ります。実行には
`pip install "reqrec[sspi]"`（Windows）または `pip install "reqrec[ntlm]"` と環境変数 `REQREC_NTLM_USER` /
`REQREC_NTLM_PASSWORD` が必要です（このサンプルのホストも架空なので、実際には接続できません）。

## 7. 実行について

サンプル HAR のホスト（`shop.example.test` / `api.example.test` / `intra.example.local`）は架空のものなので、生成したスクリプトを
そのまま実行しても接続できません。自分で記録した HAR から生成したスクリプトは次のように実行します。

```console
$ REQREC_PASSWORD='本物のパスワード' python scrape_example.py
```

（Windows の PowerShell なら `$env:REQREC_PASSWORD='...'; python scrape_example.py`。GUI なら「5 実行」の入力欄に入れて [実行]）

`generate` に `--run` を付けると、生成直後に同じ Python で実行して、その終了コードを返します。

## `example_scrape.py`

このディレクトリの [`example_scrape.py`](example_scrape.py) は、上の HAR から生成されるスクリプトと同じ構成で
**手書き**した「例」です（コメントや細部の文言は実際の出力と異なります）。生成コードを手で直すときの
参考として、ヘルパー関数・ステップ関数・`main()` の役割を README の「生成コードの読み方」と合わせて読んでください。
