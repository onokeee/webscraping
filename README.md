# reqrec — HTTP レベルの「マクロ記録」で Python スクレイピングコードを生成する

**reqrec** は、Web サイトを操作したときにブラウザが実際に送受信した **HTTP リクエスト / レスポンス** を記録し、
同じやりとりを再現する **単体で動く Python スクリプト**（`requests` + `BeautifulSoup`）を生成するツールです。

画面の要素（ボタンや入力欄）をつかんで操作を再現する Selenium / Playwright 型の「マクロ記録」ではなく、
**HTTP の会話そのもの**を記録してコードに書き起こします。生成されるコードにブラウザは不要で、
軽く・速く・安定して動きます。

コマンドライン（`reqrec generate`）に加えて、**コードを書かずにブラウザ上のボタン操作だけで使える GUI**
（`reqrec gui`）があります。Windows の **Edge IE モード**で使っている社内サイト（統合 Windows 認証、
古い TLS、Shift_JIS、ASP.NET WebForms）や、**別タブで開く画面**にも対応しています。

```
ログインページを開く → ID/パスワードを送る → 一覧を 3 ページめくる → CSV をダウンロード
                                  ↓ 記録（HAR / プロキシ / GUI の[記録開始]）
reqrec generate rec.har -o scrape.py      （または GUI の[生成]）
                                  ↓
step_01_get_login() / step_02_post_login() / step_03_get_items(page) ... を持つ scrape.py
```

> **できること**: ログイン（CSRF トークン付き）、JSON API（Bearer トークン）、ページ送り、
> リダイレクト、ファイルダウンロード、統合 Windows 認証（NTLM / Negotiate）・Basic / Digest 認証、
> 別タブで開く画面などを含む一連の操作の再現。
> トークンなど「前のレスポンスから取った値」を自動で見つけて、抽出コードに置き換えます。
>
> **できないこと**: JavaScript で計算される署名、CAPTCHA、Cloudflare などのボット対策の突破、
> WebSocket。詳しくは[検出できないケースと対処](#検出できないケースと対処)。

---

## クイックスタート（コードを書かずに使う）

```console
$ pip install "reqrec[record]"      # リポジトリからなら: pip install -e ".[record]"
$ reqrec gui
GUI を起動しました: http://127.0.0.1:8765  (Ctrl+C で終了)
作業フォルダ: C:\Users\you\reqrec_work
```

ブラウザが自動で開き、**かんたん画面**が表示されます（開かないときは表示された URL をブラウザに貼ってください）。
ポート番号やプロキシ、証明書といった設定は一切不要で、やることは 3 つだけです。
**Windows の設定（インターネット オプションのプロキシ、証明書ストア）は何も変更しません。**

```
 [● 記録をはじめる] ─▶ 開いた「記録用ブラウザ」でいつもどおりサイトを操作する ─▶ ブラウザを閉じる（または [■ 記録をおわる]）
        │                                                                      │
        │ 自動: 空きポートの選択・記録用プロキシの起動・                        │ 自動: 記録用ブラウザとプロキシを止める・解析・
        │       記録用ブラウザ (IE エンジン) の起動                              │       スクリプト生成・保存
        ▼                                                                      ▼
   「記録中 … 件の通信を記録しました」がライブで増える                      「✔ スクリプトができました」
                                                                       [ダウンロード] [保存先フォルダを開く] [試しに実行する]
```

1. **記録をはじめる** — 押すと、タイトルに「記録中」と付いた**記録用ブラウザ**が開きます。これは Edge の IE モードと
   同じエンジン（Internet Explorer / Trident）をこのツールが自分の窓に入れて動かしているもので、**この窓の通信だけ**が
   記録用プロキシを通ります。「開くサイトのアドレス」を入れておくとそのページが開きます（空欄なら空のページ。
   窓の上のアドレス欄に `http://kanri/` のように入れて Enter で開けます）。初回だけ記録用ブラウザの作成
   （Windows 標準のコンパイラで数秒）が走ります。
2. **いつもどおりサイトを操作する** — ログイン → 一覧を開く → 欲しいデータの画面まで、普段どおりに。
   画面の件数が増えていれば記録されています。`window.open` や `target="_blank"` の別窓、`showModalDialog` の
   ダイアログは記録用ブラウザの中でタブとして開き、その通信も記録されます。ファイルのダウンロードも、保存の
   ダイアログが出なくても HTTP の通信は記録されています。
3. **記録をおわる** — 記録用ブラウザを閉じる（×ボタン、または窓の赤い [■ 記録をおわる]）だけでスクリプトができあがり、
   作業フォルダの `scripts/` に保存されます（かんたん画面の [■ 記録をおわる] でも同じです）。
   [試しに実行する] でその場で動かして結果を確認でき（パスワードなどはこのとき入力します）、
   [ダウンロード] で別の PC に持っていけます。

> **記録されるのは `http://` のサイトです。** 記録用ブラウザは証明書を登録しないので、`https://` のページは
> 記録せずそのまま通します（画面は普通に見えますが、スクリプトには入りません）。社内の LAN にある古い業務サイトは
> ほぼ `http://` なのでそのまま使えます。`https://` のサイトを記録したいときは、詳細設定の「記録方式」で
> 「自分でブラウザを設定する (システムプロキシ / Edge)」を選び、証明書を登録する従来の方法を使ってください
> （[Edge IE モードで記録する](#edge-ie-モードで記録する)）。かんたん画面は Windows の設定や証明書を
> **自分からは一切変更しません**。記録用ブラウザが使えない Windows PC（.NET Framework のコンパイラがない）では、
> 準備状況の欄に理由が表示され、[記録をはじめる] は押せません。その場合は詳細設定で記録方式を選んでください。

フィルタ設定や通信の一覧を細かく見たいときは、右上の **[詳細設定を表示]** で従来の 5 画面
（1 記録 → 2 読み込み → 3 ステップ → 4 コード → 5 実行）に切り替えられます。詳しくは
[GUI の使い方](#gui-の使い方reqrec-gui) を、Edge IE モードの社内サイトなら
[Edge IE モードで記録する](#edge-ie-モードで記録する) を読んでください。

---

## 目次

- [クイックスタート（コードを書かずに使う）](#クイックスタートコードを書かずに使う)
- [何ができるか](#何ができるか)
- [仕組み](#仕組み)
- [インストール](#インストール)
- [記録方法（3 通り）](#記録方法3-通り)
  - [1. ブラウザの DevTools から HAR を保存する](#1-ブラウザの-devtools-から-har-を保存する)
  - [2. `reqrec record` でプロキシ記録する](#2-reqrec-record-でプロキシ記録する)
  - [3. 既存の mitmproxy ファイルを使う](#3-既存の-mitmproxy-ファイルを使う)
- [別タブで開く画面を記録する](#別タブで開く画面を記録する)
- [GUI の使い方（`reqrec gui`）](#gui-の使い方reqrec-gui)
- [Edge IE モードで記録する](#edge-ie-モードで記録する)
- [使い方: inspect → generate → 実行](#使い方-inspect--generate--実行)
- [ステップの手動選択と「結果にするステップ」](#ステップの手動選択と結果にするステップ)
- [生成コードの読み方](#生成コードの読み方)
- [依存関係検出の仕組み](#依存関係検出の仕組み)
- [検出できないケースと対処](#検出できないケースと対処)
- [オプション一覧](#オプション一覧)
- [Windows での配布と exe 化](#windows-での配布と-exe-化)
- [法的・倫理的な注意](#法的倫理的な注意)
- [トラブルシューティング FAQ](#トラブルシューティング-faq)
- [開発者向け](#開発者向け)

---

## 何ができるか

| | 画面要素ベース（Selenium 等のレコーダー） | **reqrec（HTTP ベース）** |
|---|---|---|
| 記録するもの | クリック・入力などの操作 | ブラウザが送受信した HTTP リクエスト/レスポンス |
| 生成コードの実行に | ブラウザ（と WebDriver）が必要 | `requests` だけ。ブラウザ不要 |
| 速度・リソース | 重い | 軽い（ページ描画をしない） |
| 画面レイアウトの変更 | 壊れやすい | 影響しない（API/フォームが変わらなければ動く） |
| JavaScript が計算する値 | ブラウザが実行してくれる | **再現できない**（手で補う必要あり） |

reqrec が自動でやること:

- 画像・CSS・JS・フォント・アクセス解析などの**ノイズを捨て**、本質的なリクエストだけを残す
- **リダイレクトの連鎖**（POST → 302 → GET）を 1 ステップにまとめる
- `page=1,2,3` のような**繰り返し**を検出して `for` ループにする
- 後のリクエストで使われている値（CSRF トークン、API トークン、ID、署名…）が
  **どのレスポンスのどこから来たか**を突き止め、抽出コードに置き換える
- Cookie は `requests.Session` に任せ、記録開始前からあった Cookie は `INITIAL_COOKIES` に出す
- パスワードなどの**秘密情報は環境変数**から読むコードにする（記録した値はコードに残さない）
- **HTTP 認証のやりとり**（統合 Windows 認証 NTLM / Negotiate、Basic、Digest）の 401 → 再送を 1 ステップに
  まとめ、生成コードでは `session.auth` に置き換える
- Shift_JIS / EUC-JP など **文字コードを自動判定**して文字化けしないコードにする
- 読みやすく、手で直しやすい Python を出力する（ステップ = 関数、日本語コメント付き）

人がやること（GUI ならチェックボックスとラジオボタン、CLI ならオプション）:

- 自動判定で残った不要なリクエストを外す / 捨てられた必要なリクエストを戻す
- 「最後に出力したい結果」がどのリクエストかを選ぶ
- 複数の記録（タブごとの HAR）を 1 つに結合する

## 仕組み

```
 ブラウザ ──プロキシ──▶ reqrec record / GUI「1 記録」(mitmproxy アドオン) ─┐
 DevTools ──「Save all as HAR with content」(タブごと・複数可) ─────────┼──▶ Recording ──▶ 解析 ──▶ Plan ──▶ コード生成 ──▶ scrape.py
 mitmdump -w flows.mitm ──────────────────────────────────────────────┘      (JSON)      │                        │
                                                                                         │ ・ノイズ除去            │ ・ステップ関数
                                                                                         │ ・認証ハンドシェイク統合 │ ・抽出コード
                                                                                         │ ・リダイレクト統合      │ ・session.auth / TLS 設定
                                                                                         │ ・ループ検出            │ ・main()
                                                                                         │ ・依存関係検出
                                                                                         │ ・手動の採用/除外
```

1. **record / import** — 記録を共通の `Recording`（JSON）に変換します。HAR も mitmproxy のファイルも同じ形になります。
   複数のファイルを渡すと**時刻順に結合**して 1 つの `Recording` にします。
2. **解析** — フィルタで不要なリクエストを捨て、残ったものを順に見て「この値はどこから来たか」を調べ、
   `Plan`（ステップの列）を作ります。`reqrec inspect` と GUI の「3 ステップ」はここまでを実行して結果を表示します。
3. **コード生成** — `Plan` から Python スクリプトを書き出します。`reqrec generate` と GUI の「4 コード」は
   1〜3 をまとめて実行します。

段階が分かれているので、生成結果が気に入らないときは `inspect`（GUI では表）でどこがどう解釈されたかを確認してから
オプションやチェックを調整できます。

## インストール

Python 3.10 以上が必要です。GUI（Flask）は本体に含まれ、追加インストールは不要です。

```console
# リポジトリから（開発用）
$ git clone <このリポジトリ>
$ cd reqrec
$ pip install -e .

# プロキシ記録（reqrec record / GUI の「記録」/ .mitm ファイルの読み込み）も使うなら mitmproxy を含めてインストール
$ pip install -e ".[record]"        # PyPI 配布時は  pip install "reqrec[record]"

# 生成コードで高速な lxml パーサーを使いたい場合（任意）
$ pip install -e ".[lxml]"
```

**統合 Windows 認証（NTLM / Negotiate）のサイト**を再現する生成コードは、実行する PC に次のどちらかが必要です
（reqrec 本体ではなく、**生成されたスクリプトを動かす側**に入れます）。

```console
$ pip install "reqrec[sspi]"   # Windows: 今ログインしているユーザーで認証する（requests-negotiate-sspi）
$ pip install "reqrec[ntlm]"   # 他の OS、または別のユーザー名/パスワードで認証する（requests_ntlm）
```

インストールすると `reqrec` コマンドが使えるようになります（`python -m reqrec.cli` でも同じです）。

```console
$ reqrec --version
reqrec 0.1.0
$ reqrec -h
```

> Windows で `reqrec` が見つからない場合は、Python のインストール時に「Add python.exe to PATH」を付けていないか、
> `Scripts` フォルダが PATH にありません。`python -m reqrec.cli gui` のように起動すれば PATH に関係なく動きます。

## 記録方法（3 通り）

どの方法でも、**記録する前に目的の操作だけを行う準備**をしておくと、あとの確認が楽になります
（別タブで無関係なサイトを開かない、不要な拡張機能を切る、など）。GUI の「1 記録」パネルは 2 番目の方法
（プロキシ記録）をボタンで行うものです。

### 1. ブラウザの DevTools から HAR を保存する

追加ソフトなしで一番手軽な方法です。

**Chrome / Edge**

1. 対象サイトを開き、`F12`（または右クリック → 検証）で DevTools を開いて **Network（ネットワーク）** タブへ。
2. **Preserve log（ログを保持）** にチェックを入れる。
   → ページ遷移やリダイレクトで記録が消えなくなります（ログインは必ず遷移するので必須）。
3. **Disable cache（キャッシュを無効化）** にチェックを入れる。
   → キャッシュから読まれた `304 Not Modified` やレスポンス本文なしの記録を防ぎます。
4. 記録ボタンが赤（記録中）になっていることを確認し、必要なら 🚫 で一度ログを空にする。
5. **再現したい操作を最初から最後まで**行う（ページを開く → ログイン → 一覧をめくる → ダウンロード…）。
6. リクエスト一覧のどこかを右クリック →
   **「Save all as HAR with content」**（日本語 UI では「コンテンツを含めて HAR としてすべて保存」）を選ぶ。
   - ⚠️ 必ず **"with content"（コンテンツを含む）** の方を選んでください。レスポンス本文がないと、
     トークンがどこから来たかを突き止められません。
   - 新しい Chrome では「Export HAR (sanitized)」と「Export HAR (with sensitive data)」のような選択が
     出ることがあります。**sensitive data（Cookie・認証ヘッダを含む）側**を選んでください。
     サニタイズ版では Cookie / Authorization が消え、依存関係を検出できません。
   - DevTools の設定（⚙）に「Allow to generate HAR with sensitive data」がある場合はオンにします。
   - 操作の途中で**新しいタブ**が開くサイトは、[別タブで開く画面を記録する](#別タブで開く画面を記録する) を先に読んでください。

**Firefox**

1. `F12` → **ネットワーク** タブ。右上の ⚙ から「ログを持続」をオン。
2. 操作を行ったあと、⚙ → **「すべてを HAR として保存」**。
3. Firefox は既定でレスポンス本文を含めますが、大きな本文は途中で切られます
   （`about:config` の `devtools.netmonitor.responseBodyLimit` で上限を変更できます）。

保存した `.har` はそのまま `reqrec inspect` / `reqrec generate`、GUI の「2 読み込み」に渡せます。

> **HAR には Cookie・パスワード・トークンがそのまま入っています。** 他人に渡さない、
> リポジトリにコミットしない（`.gitignore` の活用）、作業後は削除する、を徹底してください。

### 2. `reqrec record` でプロキシ記録する

[mitmproxy](https://mitmproxy.org/) ベースの記録用プロキシを立てる方法です。ブラウザだけでなく、
**スマホアプリ**やデスクトップアプリの通信も記録できます。`pip install "reqrec[record]"` が必要です。
**別タブ・ポップアップも含めてプロキシを通る通信がすべて記録される**ので、HAR より取りこぼしがありません。
Edge の IE モードはこの方法でしか記録できません（[Edge IE モードで記録する](#edge-ie-モードで記録する)）。

```console
$ reqrec record -o rec.json
# 必要なら: -p 8080（ポート）, --listen-host 0.0.0.0（他の端末から使う）, --hosts example.com（記録対象を絞る）
```

起動すると日本語で手順が表示されます。要点は次の 3 つです（GUI の「1 記録」パネルでは同じことをボタンで行います）。

**(a) プロキシを向ける**

- ブラウザ / OS のプロキシ設定で HTTP と HTTPS の両方を `127.0.0.1:8080`（`--listen-host` / `-p` で変更可）に向けます。
  - Windows: 設定 → ネットワークとインターネット → プロキシ → 手動プロキシ
    （「インターネット オプション」→ 接続 → LAN の設定、と同じ設定です。GUI なら「システムプロキシを自動で設定する」で自動化できます）
  - macOS: システム設定 → ネットワーク → 詳細 → プロキシ
  - Firefox は独自のプロキシ設定を持っています（設定 → ネットワーク設定）。
  - Chrome で一時的に使うなら `chrome --proxy-server=127.0.0.1:8080 --user-data-dir=/tmp/rec` のように起動すると
    普段のプロファイルを汚しません（Windows なら `--user-data-dir=%TEMP%\reqrec-profile`）。

**(b) CA 証明書を一度だけインストールする（HTTPS の中身を見るため）**

- プロキシ経由で **http://mitm.it** を開くと、OS / ブラウザごとの証明書ダウンロードと手順が表示されます。
- ファイルで取り込む場合は `~/.mitmproxy/mitmproxy-ca-cert.pem`（初回起動時に生成。Windows では
  `%USERPROFILE%\.mitmproxy\mitmproxy-ca-cert.cer` も作られます）を OS の「信頼されたルート証明機関」に追加します。
  Windows なら GUI の [CA 証明書をインストール] ボタン、またはコマンド
  `certutil -user -addstore Root %USERPROFILE%\.mitmproxy\mitmproxy-ca-cert.cer` で登録できます。
  Firefox は独自ストアなので、設定 → プライバシーとセキュリティ → 証明書を表示 → 認証局証明書 → インポート、から取り込みます。
- 記録が終わったら証明書を削除・無効化しておくと安全です（Windows: `certmgr.msc` → 信頼されたルート証明機関 → `mitmproxy`）。

**(c) 操作して Ctrl+C**

- 再現したい操作を行います。レスポンスが返るたびに `rec.json` に書き足されるので、
  途中で止めても壊れたファイルにはなりません。
- 終わったら `Ctrl+C` で停止します。あとは `reqrec inspect rec.json` へ。

**スマホアプリを記録する**

1. PC で `reqrec record -o app.json --listen-host 0.0.0.0 --hosts api.example.com`
2. スマホを PC と同じ Wi-Fi につなぎ、Wi-Fi 設定の **プロキシ** を「手動」にして PC の IP アドレスとポート（8080）を入力。
3. スマホのブラウザで http://mitm.it を開き、証明書をインストール。
   - iOS: プロファイルをインストール後、設定 → 一般 → 情報 → 証明書信頼設定 で **信頼をオン** にする（忘れがち）。
   - Android: 設定 → セキュリティ → 証明書のインストール → CA 証明書。
     ただし Android 7 以降、**多くのアプリはユーザーが追加した CA を信頼しません**（証明書ピンニング含む）。
     その場合アプリは通信エラーになり、記録できません。アプリ内ブラウザや Web ベースの画面は記録できることが多いです。
4. アプリを操作して、PC 側で `Ctrl+C`。

### 3. 既存の mitmproxy ファイルを使う

すでに mitmproxy / mitmdump で保存したフローファイルがあれば、そのまま渡せます（読み込みには mitmproxy が必要です）。

```console
$ mitmdump -w flows.mitm          # 別途記録しておいたもの（mitmproxy の画面なら w で保存）
$ reqrec inspect flows.mitm
$ reqrec generate flows.mitm -o scrape.py
```

HAR / .mitm / reqrec の JSON を 1 つの形式にまとめて保管したいときは `reqrec import` を使います。
複数のファイルを渡すと結合して 1 つの JSON にします。

```console
$ reqrec import traffic.har -o rec.json
14 件のフローを取り込みました（har, WebInspector/537.36） → rec.json
$ reqrec import tab1.har tab2.har -o rec.json      # 2 つのタブの HAR を結合して保存
```

## 別タブで開く画面を記録する

「検索結果の行をクリックすると詳細が**新しいタブ**で開く」「帳票が `window.open` でポップアップする」
といったサイトはよくあります。記録方法によって扱いが違います。

**プロキシ記録（`reqrec record` / GUI の「1 記録」）** — 何もしなくてよい。
新しいタブもポップアップも同じプロキシを通るので、1 つの記録に時刻順で入ります。
Edge IE モードでも同様です。

**HAR（DevTools）** — DevTools は**タブ単位**です。元のタブの Network パネルには、新しいタブで行われた通信は
出てきません。次のようにすると取りこぼしなく記録できます。

1. DevTools の設定（⚙ → 「基本設定 / Preferences」→「グローバル / Global」）で
   **「ポップアップに対して DevTools を自動的に開く (Auto-open DevTools for popups)」** をオンにする。
   → 新しいタブ / ポップアップが開くと、そのタブにも DevTools が自動で開きます。
2. 新しいタブの DevTools でも **Preserve log** をオンにしておく（開いた直後に確認）。
3. 操作が終わったら、**タブごとに** HAR を保存する（`tab1.har`、`tab2.har` …。順番はファイル名でなく時刻で決まるので
   名前は自由です）。
4. 複数のファイルをまとめて渡す。

```console
$ reqrec inspect  tab1.har tab2.har
$ reqrec generate tab1.har tab2.har -o scrape.py
```

GUI では「2 読み込み」でファイルを**複数選択**するか、1 つずつ「追加して結合」にチェックして読み込みます。

結合のルール:

- すべてのリクエストを **開始時刻（HAR の `startedDateTime`）の順**に並べ直し、ID（`f0001`, `f0002`, …）を付け直します。
  同じ PC の同じブラウザで保存したファイルなら時刻は揃っているので、タブをまたいだ操作もそのままの順序になります。
- `inspect` の先頭（入力: …）と GUI の「現在読み込まれている記録」には、結合した**すべてのファイル名**が出ます。
- 同じ通信が 2 つのファイルに入っていると（同じタブの HAR を 2 回保存した、など）ステップが二重になります。
  その場合は「3 ステップ」のチェック、または `--exclude-flow` で片方を外してください。
- 時刻のないフロー（古い形式のファイルなど）は、時刻のあるものの後ろに元の順序で並びます。

## GUI の使い方（`reqrec gui`）

### 起動と作業フォルダ

```console
$ reqrec gui                                   # http://127.0.0.1:8765 をブラウザで開く
$ reqrec gui --port 8766                       # ポートを変える（8765 が使われているとき）
$ reqrec gui --workdir D:\work\reqrec          # 作業フォルダを指定（既定: カレントの reqrec_work）
$ reqrec gui --no-browser                      # ブラウザを自動で開かない（URL を手で開く）
$ reqrec gui --host 0.0.0.0                    # 他の端末から使わせる（通常は不要。注意事項は下記）
```

| オプション | 意味 | 既定 |
|---|---|---|
| `--host HOST` | 待ち受けアドレス。`127.0.0.1` なら同じ PC のブラウザからだけ使える | `127.0.0.1` |
| `--port PORT` | 待ち受けポート | `8765` |
| `--workdir DIR` | 記録ファイル・読み込んだファイル・生成スクリプト・実行結果を保存する作業フォルダ | `./reqrec_work` |
| `--no-browser` | 起動時にブラウザを自動で開かない | 開く |

`Ctrl+C` で終了します。終了時には、記録中のプロキシを止め、GUI が変更した Windows のシステムプロキシ設定を元に戻します。

作業フォルダの中身:

| サブフォルダ | 内容 |
|---|---|
| `recordings/` | 「1 記録」で保存した記録（`rec_YYYYmmdd_HHMMSS.json`） |
| `uploads/` | 「2 読み込み」で読み込んだファイルのコピー（.har / .json / .mitm） |
| `scripts/` | 「4 コード」で [保存] したスクリプト（`<名前>.py`）。「5 実行」はここのファイルを実行します |
| `outputs/` | 「5 実行」の [結果を保存] で保存した標準出力 |

記録ファイルには Cookie やパスワードがそのまま入っています。作業フォルダは共有フォルダに置かず、作業が終わったら削除してください。

### かんたん画面（既定）

起動直後に表示される画面です。製造部門など、ポートやプロキシを知らない人が使う前提で、
**[記録をはじめる] → 記録用ブラウザでサイトを操作 → ブラウザを閉じる（または [記録をおわる]）** だけで完結します。
Windows の設定や証明書は変更しません。裏側では次のことを自動で行います。

| タイミング | 自動で行うこと |
|---|---|
| [記録をはじめる] | 空いているポートを選んで記録用プロキシを起動（`https://` は記録せず素通し）/ **記録用ブラウザ**（IE エンジン、初回だけ数秒でコンパイル）を、そのプロセスだけがプロキシを通る設定で起動（「開くサイトのアドレス」があればそのページ） |
| 記録中 | 記録した通信の件数をライブ表示。[ブラウザをもう一度開く]（閉じてしまったとき）、[やめる]（記録を破棄）も可能 |
| 記録用ブラウザを閉じる / [記録をおわる] | 記録用ブラウザとプロキシを止める → 解析 → スクリプト生成 → `scripts/scrape_<サイト名>_<日時>.py` に保存 |
| できあがり | ファイル名・保存先・手順の数・最後に取得する画面を表示。[ダウンロード] / [保存先フォルダを開く] / [試しに実行する]（パスワードなどを入力して実行、結果の保存）/ [もう一度記録する] |

- 記録用ブラウザの中で開く別窓（`window.open` / `target="_blank"` / `showModalDialog` など）はタブとして開き、
  その通信もそのまま記録されます。ファイルのダウンロードも、保存ダイアログが出ない場合でも HTTP は記録されています。
- 記録されるのは `http://` のサイトだけです（証明書を登録しないため）。`https://` のサイトは
  [記録用ブラウザ（IE エンジン）](#記録用ブラウザie-エンジン) の「使えないもの」を参照してください。
- 記録用ブラウザが使えない Windows PC（Windows 標準の .NET Framework コンパイラ `csc.exe` がない）では、
  準備状況の欄に「記録用ブラウザ (IE エンジン): 準備できていません: <理由>」と表示され、かんたん画面からは記録できません。
  かんたん画面が Windows のプロキシ設定や証明書を勝手に変えることはありません。どうしても記録が必要なときは、
  **[詳細設定を表示] → 1 記録** で記録方式「自分でブラウザを設定する (システムプロキシ / Edge)」を選びます
  （このときだけ、プロキシ設定の一時変更と証明書の登録を自分で行います）。
- 記録中に [やめる] を押すと、その記録は読み込まれずに破棄されます（それまで読み込んでいた記録はそのまま残ります）。
- 「詳細設定を表示」で読み込んだ記録（DevTools の HAR など）があるときは、かんたん画面に
  [読み込み済みの記録からスクリプトを作る] が出ます。
- 右上の **[詳細設定を表示]** で下記の 5 画面に切り替えられ、同じ記録をそのまま細かく調整できます
  （[かんたん画面に戻る] で戻ります）。
- Windows 以外の OS では、画面に表示されるプロキシのアドレスをブラウザに手で設定します。

### 記録用ブラウザ（IE エンジン）

かんたん画面と、詳細設定の「1 記録」で記録方式に「アプリ内の記録用ブラウザで開く」を選んだときに使われる、
reqrec 専用の小さなブラウザです（`reqrec/iehost/RecBrowser.cs`。初回起動時に Windows 標準の
`%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe` で作業フォルダの `bin\RecBrowser.exe` にコンパイルされ、
reqrec を更新したときだけ作り直されます）。

- **エンジン**: Edge の IE モードと同じ Internet Explorer のエンジン（WebBrowser コントロール / MSHTML）。
  統合 Windows 認証、ActiveX や `showModalDialog` を使う社内サイトがそのまま動きます（`https://` のページは
  表示はできますが記録されません）。
- **プロキシはこのプロセスだけ**: WinINet の「このプロセスのプロキシ」(`InternetSetOption(INTERNET_OPTION_PROXY)`)
  を使うので、インターネット オプションのプロキシ設定や Edge の設定、レジストリは**変更しません**。
  他のブラウザやアプリの通信は一切影響を受けません。バイパス（除外）リストは空で、`http://kanri/` のような
  ドットのない社内ホスト名も記録されます。
- **証明書不要**: 記録用プロキシは `https://`（どのポートでも）を記録せず素通し（`--ignore-hosts .*`。通常のプロキシ動作では
  暗号化された接続だけが素通しになり、`http://` は記録されます）で起動するため、
  mitmproxy の CA 証明書を登録する必要がありません。
- **別窓・ダイアログ**: `window.open`（`window.opener` / 窓の名前も有効）、`<a target="_blank">`、`<form target="_blank">`
  の POST、`showModelessDialog` / `showModalDialog`（`dialogArguments` / `returnValue` も有効）は、記録用ブラウザの
  タブとして開き、通信は記録されます。ページ側の `window.close()` でタブが閉じます。
- **ダウンロード**: 保存ダイアログが出ない場合でも、ファイルを取りに行った HTTP 通信は記録されています。
  生成したスクリプトは、Excel / CSV などのダウンロードをサーバーが付けたファイル名（日本語名も可）で保存します
  （GUI の [試しに実行する] では作業フォルダの `outputs\`、コマンドで実行したときは環境変数 `REQREC_OUTPUT_DIR`
  か実行したフォルダ）。
- **ログイン画面**: ID とパスワードを求める「Windows セキュリティ」の画面（Basic 認証や、自動ログオンが効かない
  Windows 認証）は表示されるので、そのまま入力してください。ページのスクリプトエラーのダイアログだけは表示しません。
- **画面の表示**: 記録用ブラウザの下の帯に「http:// のページの通信を記録しています」と出ます。`https://` の
  ページやダウンロードを開くと「記録されません」と表示されます。
- **閉じる = 記録終了**: 記録用ブラウザを閉じる（× / 赤い [■ 記録をおわる]）と、かんたん画面が自動で記録を止めて
  スクリプトを作ります。
- **表示モード**（詳細設定 → 1 記録 → 「表示モード (記録用ブラウザ)」）: 既定では IE7 互換表示（IE モードが社内サイトを
  「互換表示」で開くときと同じ）で、**レジストリには何も書きません**。「IE8 相当」「IE11 相当 (ページの指定に従う)」
  「IE11 強制」を選ぶと、`HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_BROWSER_EMULATION`
  に `RecBrowser.exe` という名前の値（8000 / 11000 / 11001）を書き込みます。これは現在のユーザーの、記録用ブラウザ
  （`RecBrowser.exe`）だけに効く設定で、Edge や IE モードの表示には影響しません。「既定」に戻すとその値は削除されます。
- **使えないもの**: Edge IE モードの「エンタープライズ モード サイト リスト」（企業で配布する IE モードの設定）、
  そして **`https://` の記録**（素通し）。なお、Windows から段階的に削除されつつある VBScript を使うページは、
  IE モードと同じく記録用ブラウザでも動かなくなることがあります。
  `https://` のサイトや、エンタープライズ モードが必要なサイトは、記録方式を「自分でブラウザを設定する
  (システムプロキシ / Edge)」にして、[Edge IE モードで記録する](#edge-ie-モードで記録する) の方法で記録してください。

### 1. 記録 — プロキシで記録する

| 項目 | 説明 |
|---|---|
| プロキシのポート番号 | 既定 `8080`。ブラウザに設定するポート |
| 記録するサイト（ホスト名） | カンマ区切り。サブドメインも含めて記録。空欄ならすべてのサイト |
| 待ち受けアドレス | 既定 `127.0.0.1`。スマホなど他の端末から記録するなら `0.0.0.0` |
| 追加モード | 停止したとき、すでに読み込んである記録に**追加して結合**する |
| 記録方式（Windows のみ） | **アプリ内の記録用ブラウザで開く (IE エンジン、設定変更なし、http のみ)**（既定。[記録用ブラウザ（IE エンジン）](#記録用ブラウザie-エンジン)）か、**自分でブラウザを設定する (システムプロキシ / Edge)**（従来の方法） |
| 最初に開くアドレス（記録用ブラウザ） | 記録用ブラウザが最初に開くページ。空欄なら空のページ |
| 表示モード（記録用ブラウザ） | 既定 (IE7 互換表示、レジストリに書き込まない) / IE8 相当 / IE11 相当 (ページの指定に従う) / IE11 強制 |
| https:// の通信は記録せず素通しする（Windows のみ） | チェックすると証明書なしで記録でき、`https://` のページはスクリプトに入らない。記録用ブラウザでは既定でオン |
| システムプロキシを自動で設定する（Windows のみ） | 記録方式が「自分でブラウザを設定する」のとき: 記録開始時に Windows の「インターネット オプション」のプロキシを `127.0.0.1:<ポート>` に設定し、停止時 / GUI 終了時に元に戻す。**Edge IE モード**を記録するならチェック |

記録方式が「アプリ内の記録用ブラウザで開く」なら、[記録開始] でプロキシと記録用ブラウザが起動し、以下の
「ブラウザ側の手順」は不要です。「記録の状態」には記録用ブラウザの状態（起動中 / 閉じられました）も出ます。

[記録開始] を押すとプロキシが起動し、右側の「記録の状態」に**記録したリクエスト件数がライブで**表示されます。
その下の「ブラウザ側の手順」カードに、プロキシ設定（`127.0.0.1:8080`）、CA 証明書
（`http://mitm.it` または `~/.mitmproxy/mitmproxy-ca-cert.pem`）、Edge IE モードは「インターネット オプション」
のプロキシを使う旨、といった手順が出ます。

サイトを操作し終えたら [記録停止して読み込む]。記録が `recordings/` に保存され、そのまま読み込まれて
「3 ステップ」へ進めます。

Windows では「Windows の設定（Edge IE モード向け）」カードが表示され、システムプロキシと mitmproxy の
CA 証明書の状態、[CA 証明書をインストール]（`certutil -user -addstore Root` で現在のユーザーの
「信頼されたルート証明機関」に登録）、[プロキシ設定を元に戻す]、[状態を更新] のボタンがあります。
証明書はプロキシを一度起動すると作られるので、初回は [記録開始] → [CA 証明書をインストール] の順です。

mitmproxy が入っていないと、このパネルの上に `pip install "reqrec[record]"` を促す注意が出ます。
HAR の読み込み以降の機能はそのまま使えます。

### 2. 読み込み — HAR / .mitm / 記録 JSON を読み込む

- **ファイルを選んで読み込む** — ドラッグ＆ドロップまたはクリックで `.har` / `.json` / `.mitm` を選びます。
  **複数選択できます**（別タブごとの HAR など）。選んだファイルは `uploads/` にコピーされ、
  複数なら時刻順に結合されます。
- **追加して結合** — チェックすると、読み込み済みの記録を置き換えずに追加します。
- **作業フォルダ内のファイルから開く** — `recordings/` と `uploads/` にあるファイルの一覧（リクエスト数・サイズ・更新日時）
  からチェックして [選択したファイルを開く]。複数選ぶと結合されます。
- **現在読み込まれている記録** — ファイル名・リクエスト数・ホストの一覧。[記録をクリア] で空に戻します。

### 3. ステップ — 採用 / 除外と「結果」を選ぶ

記録が読み込まれると自動で解析され、**全リクエストの表**が出ます（`reqrec inspect` と同じ内容を、
除外されたものも含めて 1 つの表にしたものです）。

| 列 | 意味 |
|---|---|
| 採用（チェック） | チェック = スクリプトのステップにする。外すと除外（判定「手動で除外」。CLI の `inspect` では `excluded by user`）。除外されていた行にチェックを付けると強制的に採用 |
| 結果（ラジオ） | **スクリプトの最後に出力するデータ**として使うリクエスト。未指定なら最後のステップ |
| ステップ | そのリクエストが入るステップ番号（リダイレクトの連鎖やループは複数行が同じ番号） |
| メソッド / ステータス / 種類 / URL / 参照元 | 記録されたリクエストの情報（種類は HTML / JSON / 画像など） |
| 判定 | 「採用」、または除外された理由（「静的ファイル」「トラッカー / 解析サービス」「304 (ブラウザキャッシュ)」など。CLI の `static asset` 等の日本語表示） |

- チェックやラジオ、フィルタ設定を変えると**即座に再計算**され、表と右側の「解析結果」（ステップ数・採用・除外・
  自動抽出する値・結果にするステップ・HTTP 認証・定数 / 秘密情報・ループ・警告）が更新されます。
- 行をクリックすると**詳細ドロワー**が開き、リクエスト / レスポンスのヘッダーと本文を確認できます
  （JSON は整形表示、大きな本文は途中まで、バイナリはサイズと種類のみ）。「このトークンはどこから来たか」を
  目で確かめたいときに使います。
- 「除外された行も表示」を外すと採用分だけ、検索欄で URL / ホスト / メソッドの絞り込みができます。

フィルタ設定は CLI のオプションと 1 対 1 です:

| GUI | CLI |
|---|---|
| 静的ファイル（画像 / CSS / JS / フォント）も残す | `--keep-static` |
| トラッカー / 解析サービスへの通信も残す | `--keep-trackers` |
| すべて残す（自動のノイズ除外を無効にする） | `--keep-all` |
| リダイレクトを 1 つのステップに統合する（既定オン） | `--no-collapse-redirects` で無効 |
| ループ（ページ送りなど）を検出してまとめる（既定オン） | `--no-loops` で無効 |
| パスワードなどの秘密情報を環境変数から読む（既定オン） | `--no-redact` で無効 |
| HTTP 認証（Windows 統合認証 NTLM / Basic / Digest）のやり取りを検出して統合する（既定オン） | `--no-detect-auth` で無効 |
| 古い TLS / 暗号しか使えないサーバー向けの接続設定を生成コードに入れる | `--legacy-tls` |
| このホストだけ採用 / このホストは除外 | `--include-host` / `--exclude-host` |
| 依存検出する値の最小文字数 / ステップ数の上限 | `--min-value-length` / `--max-steps` |
| 採用チェック（外す / 付ける） | `--exclude-flow ID` / `--include-flow ID`（`--exclude-step N`） |
| 結果ラジオ | `--final-flow ID`（`--final-step N`） |

### 4. コード — 生成して保存する

- 生成オプション: HTML パーサー（`html.parser` / `lxml`）、ステップ間の待ち時間（秒）、タイムアウト（秒）、
  日本語の説明コメントを入れる、厳格モード（記録時と違うステータスコードならエラー）。
- [生成] を押すとスクリプトがプレビューに表示され、警告と**実行時に必要な環境変数**（`REQREC_PASSWORD` など）の一覧が出ます。
- ファイル名を入れて [保存] すると `scripts/<名前>.py` に保存されます（ファイル名に空白や `/` `\` は使えません。英数字・`_`・`-`・`.` を推奨）。
  [ダウンロード] でブラウザからも保存できます。別の PC で動かすのに必要なのは Python と `pip install requests beautifulsoup4`
  だけです（統合 Windows 認証のサイトは加えて `pip install "reqrec[sspi]"` または `"reqrec[ntlm]"`）。

### 5. 実行 — その場で動かして結果を見る

- 実行するスクリプトを `scripts/` の一覧から選びます。
- 「4 コード」で検出された**秘密情報の環境変数ごとに入力欄**（パスワード型）が出ます。入力した値は
  **実行するプロセスにだけ**渡され、ファイルにもログにも保存されません。
- [実行] で同じ Python インタプリタ（`reqrec gui` を動かしているもの）で実行され、標準出力 / 標準エラーが
  コンソールに流れます。[停止] で中断できます。同時に実行できるのは 1 つです。
- [結果を保存] で最後の実行の標準出力を `outputs/<ファイル名>` に保存します。

### GUI のセキュリティ（なぜローカル専用か）

GUI が動いている間、同じブラウザでは記録対象のサイト（= 任意の第三者のページ）を開くことになります。
そのページの JavaScript から GUI を操作されないように、GUI は **(1) 既定で `127.0.0.1` だけで待ち受け**（同じ PC からしか
届かない）、**(2) 状態を変える操作（記録開始・ファイル保存・実行など）には起動ごとに変わるランダムなトークン**
（`X-Reqrec-Token` ヘッダー）を要求し、他のページからの要求は 403 で拒否、**(3) `Host` ヘッダーが `127.0.0.1` /
`localhost` / 待ち受けアドレス以外の要求と、別オリジンからの `Origin` を拒否**（DNS リバインディング対策）、
**(4) ファイル名は作業フォルダの中だけ**を指す、という作りになっています。`--host 0.0.0.0` で他の端末に開放すると
(1) の保護がなくなるので、信頼できる LAN 内だけで、必要なときだけにしてください。

## Edge IE モードで記録する

> **まず試すのはかんたん画面です。** かんたん画面の [記録をはじめる] は、IE モードと同じエンジンを使う
> [記録用ブラウザ](#記録用ブラウザie-エンジン) を開くので、Windows の設定も証明書も触らずに IE モード向けの
> 社内サイト（`http://`）を記録できます。この節は、`https://` のサイトやエンタープライズ モードが必要なサイトなど、
> **本物の Edge（IE モード）とシステムプロキシで記録する**ときの方法です（詳細設定の記録方式
> 「自分でブラウザを設定する (システムプロキシ / Edge)」）。

### なぜプロキシ記録で動くのか

Edge の IE モードのタブは、Edge（Chromium）ではなく **Internet Explorer 11 のエンジン**で描画・通信しています。
そのため Edge の DevTools（F12）はそのタブに対して使えず、HAR も Edge 側では保存できません。
一方、IE11 の通信は Windows の **WinINET** を通るので、**「インターネット オプション」のプロキシ設定（= Windows のシステム
プロキシ）**がそのまま適用されます。つまり、reqrec のプロキシを**システムプロキシに設定**すれば、IE モードのタブで行った
操作（別タブ・ポップアップ・フレーム内の通信を含めて）がすべて記録できます。IE モードかどうかに関係なく、
Edge の通常タブも同じ設定で記録されます。

### 手順（GUI）

1. `reqrec gui` を起動し、「1 記録」で **「システムプロキシを自動で設定する」にチェック**して [記録開始]。
   Windows の「インターネット オプション」→ 接続 → LAN の設定 → 「LAN にプロキシ サーバーを使用する」が
   `127.0.0.1:8080` に書き換えられます（元の設定は保存され、停止時に戻します）。
2. 社内サイトが HTTPS なら、初回だけ [CA 証明書をインストール] を押します（中身は
   `certutil -user -addstore Root %USERPROFILE%\.mitmproxy\mitmproxy-ca-cert.cer`。IE / Edge は Windows の証明書ストアを
   使うので、これだけで IE モードでも証明書エラーが出なくなります）。
3. Edge で IE モードのサイトを開き、取得したい画面まで普段どおり操作します。「記録の状態」の件数が増えていれば
   記録されています。
4. [記録停止して読み込む] → システムプロキシが元に戻り、「3 ステップ」へ。

手で設定する場合は、コントロール パネル → ネットワークとインターネット → **インターネット オプション** → 接続 →
**LAN の設定** → 「LAN にプロキシ サーバーを使用する」にチェック、アドレス `127.0.0.1`、ポート `8080`、
「ローカル アドレスにはプロキシ サーバーを使用しない」にチェック。記録後は**必ずチェックを外して**ください
（GUI の [プロキシ設定を元に戻す] でも戻せます）。

CLI なら `reqrec record -o rec.json` を起動した上で、同じ手設定を行います。

### IE11 の F12 開発者ツールで HAR を保存する（代替手段）

IE モードのタブでも、`C:\Windows\System32\F12\IEChooser.exe` を起動してそのタブを選ぶと IE11 の F12 開発者ツールが
開き、「ネットワーク」タブの **「HAR としてエクスポート」**（保存アイコン、`Ctrl+S`）で `.har` を保存できます。
reqrec はこの HAR も読み込めます。ただし、IE11 の HAR は**別タブの通信が入らない**（タブごとに F12 を開いて保存する
必要がある）、レスポンス本文や文字コードの情報が欠けることがある、といった弱点があるため、**プロキシ記録を推奨**します。

### 統合 Windows 認証（NTLM / Negotiate）・Basic / Digest 認証

社内サイトの多くは「ログイン画面なしで Windows のユーザーで自動的に認証」されます。HTTP ではこう見えます。

```
GET /Default.aspx                                   → 401  WWW-Authenticate: Negotiate, NTLM
GET /Default.aspx  Authorization: NTLM TlRMTVNTUAAB… → 401  WWW-Authenticate: NTLM TlRMTVNTUAAC…
GET /Default.aspx  Authorization: NTLM TlRMTVNTUAAD… → 200
```

reqrec はこの **401 → 再送のやりとりを検出して 1 ステップにまとめ**、生成コードではリクエストごとの `Authorization`
ヘッダを出す代わりに `session.auth` を設定します（記録した `Authorization` の値はワンタイムで再利用できないため、
そのまま再送しても必ず 401 になります）。`inspect` と GUI の「解析結果 → HTTP 認証」に、検出した方式
（`ntlm` / `negotiate` / `basic` / `digest`）、ホスト、記録時のユーザー名（`DOMAIN\user`。パスワードは含みません）が出ます。

**NTLM / Negotiate** — 生成コードの `main()` 冒頭はこうなります。

```python
    # 統合 Windows 認証（NTLM / Negotiate）: 記録時のユーザー: DOMAIN\user
    try:
        from requests_negotiate_sspi import HttpNegotiateAuth  # Windows: 今ログインしているユーザーで認証（pip install "reqrec[sspi]"）
        session.auth = HttpNegotiateAuth()
    except ImportError:
        from requests_ntlm import HttpNtlmAuth  # 他の OS / 別ユーザーで認証する場合（pip install "reqrec[ntlm]"）
        session.auth = HttpNtlmAuth(os.environ.get("REQREC_NTLM_USER", r"DOMAIN\user"), os.environ.get("REQREC_NTLM_PASSWORD", ""))
```

- Windows の PC で、記録したときと同じユーザーで実行するなら `pip install "reqrec[sspi]"` を入れるだけです。
  パスワードの入力は要りません（Windows のログオン情報で認証します）。
- Linux / macOS、または別のユーザーで実行するなら `pip install "reqrec[ntlm]"` を入れ、環境変数
  **`REQREC_NTLM_USER`**（`DOMAIN\user` 形式）と **`REQREC_NTLM_PASSWORD`** を設定します。
  GUI の「5 実行」ではこの 2 つの入力欄が出ます。
- どちらも入っていないと、スクリプトは `pip install "reqrec[sspi]"` / `"reqrec[ntlm]"` と環境変数名を案内する日本語の
  メッセージを出して終了します（スクリプト先頭の docstring の「注意」にも書かれています）。

**Basic 認証** — ユーザー名は定数 `AUTH_USERNAME` に、パスワードは秘密情報として環境変数 **`REQREC_AUTH_PASSWORD`**
から読む定数 `AUTH_PASSWORD` になり、`session.auth = (AUTH_USERNAME, AUTH_PASSWORD)` が出ます。
**Digest 認証**は同じ定数で `session.auth = requests.auth.HTTPDigestAuth(AUTH_USERNAME, AUTH_PASSWORD)` です。

認証検出は GUI の「HTTP 認証 … を検出して統合する」チェック、CLI の `--no-detect-auth` で無効にできます（無効にすると
401 の各応答もステップになり、`Authorization: NTLM …` などのトークンは秘密定数 `AUTHORIZATION`（環境変数
`REQREC_AUTHORIZATION`）として扱われます。`--no-redact` のときだけ平文です。通常はオンのままにしてください）。

### 古い TLS しか使えないサーバー（`--legacy-tls`）

IE モードで使い続けている社内サーバーには、TLS 1.0 / 1.1 や弱い暗号スイート（`DH key too small` など）しか
受け付けないものがあります。新しい Python の `requests` は既定でこれらを拒否するので、
`SSLError: ... unsupported protocol` / `handshake failure` になります。

- CLI: `reqrec generate rec.json -o scrape.py --legacy-tls`
- GUI: 「3 ステップ」のフィルタ設定「古い TLS / 暗号しか使えないサーバー … 向けの接続設定を生成コードに入れる」

を付けると、生成コードに `_LegacyTLSAdapter`（TLS 1.0 以上を許可、`DEFAULT:@SECLEVEL=1` の暗号、
`OP_LEGACY_SERVER_CONNECT`）が出力され、`session.mount("https://", _LegacyTLSAdapter())` されます。
証明書の検証そのものは下の `VERIFY_TLS` に従います。古い暗号を許す設定なので、**社内サーバーなど相手が分かっている場合だけ**使ってください。

生成コードの設定ブロックには常に

```python
VERIFY_TLS = True  # 自己署名証明書のサイトなら False か CA 証明書 (.pem) のパスに
```

があり、`main()` で `session.verify = VERIFY_TLS` されます。社内 CA や自己署名証明書のサイトで
`SSLError: CERTIFICATE_VERIFY_FAILED` になるときは、ここを社内 CA 証明書（PEM）のパスにするか、`False` にします。

### 文字コード（Shift_JIS / EUC-JP）

古い社内サイトは `Content-Type: text/html`（charset なし）で Shift_JIS のページを返すことが多く、`requests` の
`resp.text` は ISO-8859-1 として読んで文字化けします。reqrec の生成コードは

- HTML を BeautifulSoup に渡すとき**バイト列のまま**渡し（`<meta charset>` や BOM から判定させる）、
- 本文を文字列として使うときは `_text(resp)` ヘルパーで `Content-Type` → `<meta charset=…>` / `<meta http-equiv>` /
  `<?xml encoding=…>` → 推定（`apparent_encoding`）の順に文字コードを判定し、`shift_jis` / `sjis` / `x-sjis` /
  `windows-31j` は `cp932` に正規化（`euc-jp` はそのまま）してデコードします。

ので、Shift_JIS / EUC-JP のページでも正規表現による抽出や最終結果の表示が化けません。
フォームの値が Shift_JIS で URL エンコードされていた場合（`%93%FA%96%7B` = 「日本」）は、警告が出たうえで
`data=urlencode({...})` の形になり、日本語の値は `b'\x93\xfa\x96{'  # cp932 で「日本」（記録時の表記: %93%FA%96%7B）`
のようにバイト列のまま、`__VIEWSTATE` などの隠しフィールドは前のページから取得した値に差し替えて送ります
（`Content-Type: application/x-www-form-urlencoded` も記録どおり）。検索語を変えたいときは、そのバイト列を
`"検索語".encode("cp932")` に書き換えてください。

### ASP.NET WebForms（`__VIEWSTATE` など）

WebForms のページは、ボタンを押すたびに同じ URL に `__VIEWSTATE` / `__VIEWSTATEGENERATOR` / `__EVENTVALIDATION` /
`__EVENTTARGET` / `__EVENTARGUMENT` と `ctl00$...` という名前のフィールドを POST（ポストバック）します。
`__VIEWSTATE` 等は直前のページの **hidden input** にあるので、reqrec は自動的に `html_input` の抽出として検出し、
**毎回新しい値を引き継ぐ**コードを生成します（手で何かする必要はありません）。`__EVENTTARGET`（押したボタンの名前）
などはリテラルのまま出ます。検索結果の行から詳細（`Report.aspx?id=1234`）へ進む場合の `id` も、結果ページの
`<a href>` から抽出されます。

同梱のサンプル `tests/fixtures/legacy_webforms_ntlm.har`（NTLM + Shift_JIS + WebForms）で動きを確認できます
（[examples/README.md](examples/README.md)）。

## 使い方: inspect → generate → 実行

### 1. `inspect` — 何が残り、何が捨てられたかを確認する

```console
$ reqrec inspect rec.har
入力: rec.har  (har, WebInspector/537.36)
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
  no response recorded — 1 件
      f0006  https://ads.tracker.example.test/pixel.gif?pid=9981&r=0.6179
  static asset (resource type image) — 1 件
      f0003  https://shop.example.test/static/logo.png
  ...

定数 (1 件):
  PASSWORD  ← 環境変数 REQREC_PASSWORD（秘密情報: 実行前に設定してください）

警告 (1 件):
  - step 2: `password` looks like a credential; the script reads it from the environment variable REQREC_PASSWORD (set it before running)
```

各ステップと除外されたリクエストには記録上の **フロー ID（`FLOW` 列、`f0001` …）** が付きます。
リダイレクトの連鎖や認証のやりとりをまとめたステップは `f0008+f0009` のように複数の ID を持ち、ループは
`f0011+f0012+f0013`（4 件以上なら `f0011+…+f0015 (5)`）と表示されます。
この ID を `--exclude-flow` / `--include-flow` / `--final-flow` に指定して手動で調整します
（[ステップの手動選択](#ステップの手動選択と結果にするステップ)）。
HTTP 認証が検出されると、ヘッダー部に
`認証: NTLM (記録時のユーザー: EXAMPLE\taro) → 生成コードは session.auth を設定します（pip install "reqrec[sspi]" / "reqrec[ntlm]"）`
のような行が出ます（Basic / Digest では「（パスワードは環境変数 REQREC_AUTH_PASSWORD）」が付きます）。
`--final-flow` / `--final-step` を指定すると `結果にするステップ: 3 (GET https://…)` の行と、該当ステップの行の
「★ 結果として表示」印が出ます。

複数のファイルを渡すと結合して解析し、先頭の「入力:」にすべてのファイル名が並びます。

```console
$ reqrec inspect tab1.har tab2.har
入力: tab1.har, tab2.har  (結合 2 件: har, WebInspector/537.36 / har, Firefox/125.0.1)
フロー合計 20 件 / 採用 12 件 → ステップ 9 件 / 除外 8 件
...
```

見るべきポイント:

- **必要なリクエストが「除外」に入っていないか**。入っていたら `--include-host` / `--keep-static` / `--keep-all` などで調整します
  （たとえば API の URL が `.json` で終わる場合など）。1 件だけ戻すなら `--include-flow f0012`。
- **逆に、不要なリクエストがステップに残っていないか**。別タブの通信などが混ざっていたら `--exclude-host` で外すか、
  `--exclude-step 3` / `--exclude-flow f0008` で個別に外します。
- **「抽出する変数」がトークン類を捕らえているか**。`-` のステップばかりで、URL やヘッダに
  ランダムに見える値が含まれているなら、警告（`looks dynamic`）が出ているはずです。
  → [検出できないケースと対処](#検出できないケースと対処)。
- **最後に欲しいデータのステップが最後になっているか**。違うなら `--final-step N` で「結果にするステップ」を指定します。

`--json` を付ければ機械可読な JSON になります（秘密情報の値や Cookie の値は含まれません）。

### 2. `generate` — スクリプトを生成する

```console
$ reqrec generate rec.har -o scrape.py
ステップ 5 件を生成します（フロー合計 14 件 / 除外 6 件 / 抽出する変数 4 個 / ループ 1 個）
秘密情報は環境変数から読み込みます。実行前に設定してください: REQREC_PASSWORD
警告 (1 件):
  - step 2: `password` looks like a credential; ...
スクリプトを書き出しました: scrape.py
```

- 要約と警告は**標準エラー出力**に、スクリプトは `-o` のファイルに書かれます。`-o -` で標準出力に出せます。
- 入力は複数指定できます（`reqrec generate tab1.har tab2.har -o scrape.py`）。
- `inspect` と同じフィルタオプション・手動選択オプションがそのまま使えます。
- `--delay 1.0` を付けると、ステップ間に 1 秒の待ち時間を入れた（サーバーにやさしい）コードになります。
- `--legacy-tls` で古い TLS のサーバー向けの接続設定を入れます（[Edge IE モード](#古い-tls-しか使えないサーバー--legacy-tls)）。
- `--dump-plan plan.json` で解析結果（Plan）を JSON として保存できます（デバッグや差分確認に）。秘密情報として環境変数に置き換えた定数の値は、この JSON にも書き出されません。
- `--run` を付けると、生成直後に同じ Python インタプリタで実行し、その終了コードを返します。

### 3. 生成したスクリプトを実行する

```console
# Linux / macOS
$ REQREC_PASSWORD='本物のパスワード' python scrape.py

# Windows (PowerShell)
PS> $env:REQREC_PASSWORD='本物のパスワード'; python scrape.py

# Windows (cmd)
> set REQREC_PASSWORD=本物のパスワード && python scrape.py
```

- パスワード・API キーなど「秘密情報らしい名前」のパラメータは、`REQREC_<大文字の名前>` という環境変数から読まれます。
  どの環境変数が必要かは `generate` の出力と、スクリプト先頭の docstring / 定数ブロックに書かれています。
  統合 Windows 認証のサイトでは `REQREC_NTLM_USER` / `REQREC_NTLM_PASSWORD`（Windows で `reqrec[sspi]` を使うなら不要）、
  Basic / Digest 認証では `REQREC_AUTH_PASSWORD` です。
- **「結果にするステップ」**（未指定なら最後のステップ）の結果が表示されます（JSON なら整形表示、HTML なら title、
  テキストなら先頭 2000 文字）。Excel / CSV などのダウンロードは、どの手順のものでもサーバーが付けた名前で保存されます
  （[ダウンロードしたファイル](#ダウンロードしたファイルexcel--csv-出力など)）。**ここから先、何を取り出してどう保存するかは生成コードを編集して書きます。**
  `main()` の末尾、または各 `step_*` 関数の `return` の前が書き足す場所です。
- GUI の「5 実行」では環境変数を入力欄に入れて [実行] するだけです。

## ステップの手動選択と「結果にするステップ」

自動判定は万能ではありません。「別タブの無関係な通信が残った」「`.json` で終わる API が静的ファイル扱いで消えた」
「本当に欲しいのは最後の CSV ではなく 3 番目の一覧 JSON だ」といった調整を、**1 件単位**で行えます。

| やりたいこと | GUI（3 ステップ） | CLI（`inspect` / `generate`） |
|---|---|---|
| このリクエストをステップから外す | 行の「採用」チェックを外す | `--exclude-flow f0008`（繰り返し・カンマ区切り可）/ `--exclude-step 3`（ステップ番号で） |
| 除外されたリクエストを強制的に採用する | 灰色の行の「採用」にチェック | `--include-flow f0012` |
| 最後に出力する「結果」を選ぶ | 行の「結果」ラジオ（解析結果の [指定を解除] で戻す） | `--final-flow f0007` / `--final-step 3` |

- 手動で外したリクエストは判定理由 **「excluded by user」**（GUI の表では「手動で除外」）で除外一覧に出ます。ホスト指定より優先されます。
- 強制採用しても、**レスポンスが記録されていないリクエスト**（`no response recorded`）はステップにできません。
- `--exclude-step N` / `--final-step N` は、まず通常どおり解析してステップ番号を ID に変換し、その上でもう一度解析します。
  番号は「オプションなしで `inspect` したときのステップ番号」です。除外によって番号がずれても、ID（`f…`）で指定した
  ものは動きません。
- 「結果にするステップ」を指定しても、**ステップはすべて順番に実行**されます。変わるのは `main()` の最後に表示（保存）
  される結果だけです（JSON なら整形表示、HTML なら title …）。指定したリクエストが除外されていた場合は警告が出て、
  最後のステップが使われます。
- GUI では表を変更すると即座に再計算され、「解析結果 → 結果にするステップ」に反映されます。

## 生成コードの読み方

生成されるスクリプトの構成はいつも同じです（下は[同梱サンプル](examples/README.md)から生成したものを短くした**例**。
完全版は [`examples/example_scrape.py`](examples/example_scrape.py)）。

```python
"""reqrec が HTTP 通信の記録から自動生成したスクレイピングスクリプト

記録元: HAR ファイル (rec.har)   ステップ数: 5
実行前に環境変数 REQREC_PASSWORD を設定してください。
"""
import json, os, re, sys, time
from urllib.parse import unquote, urljoin
import requests
from bs4 import BeautifulSoup

TIMEOUT = 30.0     # 各リクエストのタイムアウト（秒）
DELAY = 0.0        # ステップ間の待ち時間（秒）
VERIFY_TLS = True  # 自己署名証明書のサイトなら False か CA 証明書 (.pem) のパスに

# 秘密情報は環境変数から（記録時の値は出力していません）
PASSWORD = os.environ.get('REQREC_PASSWORD', '')

BASE_HEADERS = {'user-agent': 'Mozilla/5.0 ...', 'accept-language': 'ja,en-US;q=0.9,en;q=0.8'}
INITIAL_COOKIES = []   # 記録開始時点でブラウザが既に持っていた Cookie

def _soup(resp): ...                       # HTML（バイト列）→ BeautifulSoup（文字コードは自動判定）
def _text(resp): ...                       # レスポンス本文 → 文字列（charset / <meta charset> / 推定で判定、Shift_JIS は cp932）
def _check(resp, expected, step): ...      # 4xx/5xx は例外、記録時と違うステータスは警告
def _regex(text, pattern): ...             # 正規表現のグループ 1。見つからなければ分かりやすいエラー
def _attr(soup, selector, attr): ...       # CSS セレクタで要素を探して属性を返す
def _json_path(data, path): ...            # JSON を ['data', 'items', 0, 'id'] のようなパスでたどる

def step_01_get_login(session):
    """GET https://shop.example.test/login  記録時のレスポンス: 200 text/html"""
    resp = session.get('https://shop.example.test/login', headers={...}, timeout=TIMEOUT)
    _check(resp, 200, 'step_01_get_login')
    soup = _soup(resp)
    # token: <input name='_token'> の value（記録時の値: 'tokA1b2…'） — used by step 2 (form `_token`)
    token = _attr(soup, 'input[name="_token"]', 'value')
    return resp, {'token': token}

def step_02_post_login(session, token):
    """POST https://shop.example.test/login  記録時のレスポンス: 200 text/html (redirect chain of 2 hops)"""
    resp = session.post('https://shop.example.test/login', headers={...},
                        data={'_token': token, 'username': 'alice', 'password': PASSWORD}, timeout=TIMEOUT)
    _check(resp, 200, 'step_02_post_login')
    soup = _soup(resp)
    api_token = _regex(_text(resp), '\\ \\ window\\.API_TOKEN\\ =\\ "([^"\'&<>\\s]+?)";')   # インライン script から
    x_csrf_token = _attr(soup, 'meta[name="csrf-token"]', 'content')                         # <meta> から
    return resp, {'api_token': api_token, 'x_csrf_token': x_csrf_token}

def step_04_get_orgs_items(session, page, api_token, x_csrf_token):
    """GET https://api.example.test/v1/orgs/77/items （page を変えて繰り返し）"""
    resp = session.get('https://api.example.test/v1/orgs/77/items', params={'page': page},
                       headers={'authorization': "Bearer " + api_token, 'x-csrf-token': x_csrf_token},
                       timeout=TIMEOUT)
    _check(resp, 200, 'step_04_get_orgs_items')
    return resp, {}

def main():
    session = requests.Session()
    session.verify = VERIFY_TLS
    # （統合 Windows 認証のサイトならここに session.auth = ... が入る。--legacy-tls なら session.mount(...)）
    session.headers.update(BASE_HEADERS)
    for c in INITIAL_COOKIES:
        session.cookies.set(c['name'], c['value'], domain=c['domain'], path=c['path'])
    ctx = {}                                   # 抽出した値をステップ間で受け渡す

    resp, out = step_01_get_login(session);                 ctx.update(out)
    resp, out = step_02_post_login(session, token=ctx['token']); ctx.update(out)

    results = []
    for page in range(1, 4):                   # 記録時: page=1, 2, 3
        resp, out = step_04_get_orgs_items(session, page, api_token=ctx['api_token'],
                                           x_csrf_token=ctx['x_csrf_token'])
        results.append(resp.json())
    final_resp = resp                          # 「結果にするステップ」のレスポンス（既定: 最後のステップ）

    print(json.dumps(results, ensure_ascii=False, indent=2))   # ← ここから先を書き足す
    return ctx

if __name__ == "__main__":
    main()
```

### 構成要素

| 要素 | 役割 |
|---|---|
| 先頭の docstring | 生成日時・記録元・ステップ数・必要な環境変数・警告・「注意」（統合 Windows 認証に必要なパッケージなど） |
| `TIMEOUT` / `DELAY` | タイムアウトと、ステップ間の待ち時間。`--timeout` / `--delay` で初期値を変えられる |
| `VERIFY_TLS` | 証明書検証。`True` / `False` / CA 証明書（.pem）のパス。`main()` で `session.verify` に設定される |
| 定数（`PASSWORD` など） | 複数のステップで同じ値が使われていたり、秘密情報らしい名前のものはモジュール先頭に集約。秘密情報は `os.environ.get("REQREC_…")`。Basic / Digest 認証なら `AUTH_USERNAME` / `AUTH_PASSWORD` |
| `BASE_HEADERS` | すべてのリクエストで同じだったヘッダ（User-Agent, Accept-Language など）。`Session` に設定される |
| `INITIAL_COOKIES` | 記録開始前からブラウザにあった Cookie。期限切れになったら記録し直す |
| `_LegacyTLSAdapter` | `--legacy-tls` のときだけ出力。TLS 1.0 / 1.1 と弱い暗号を許可するアダプタ。`session.mount("https://", …)` される |
| ヘルパー `_soup` `_text` `_check` `_regex` `_json_path` `_attr` … | 抽出コードを短く、失敗時のエラーを分かりやすくするための小さな関数。使われるものだけが出力される。`_soup` はバイト列を渡して文字コードを自動判定、`_text(resp)` は本文を正しい文字コードで文字列にする |
| `step_NN_<method>_<path>(session, …)` | 1 ステップ = 1 関数。`(resp, 抽出した値の dict)` を返す。引数は前のステップから受け取る値 |
| `main()` | `Session` を作り、`session.verify`（と必要なら `session.auth` / `session.mount`）を設定し、ステップを順に呼び、`ctx` に抽出値をためて次に渡す。ループは `for` で呼ぶ。「結果にするステップ」のレスポンスを `final_resp` に取って最後に表示する |

### `ctx` と値の受け渡し

各ステップ関数は、後のステップが必要とする値を dict で返します。`main()` はそれを `ctx.update(out)` で貯め、
次のステップにキーワード引数で渡します。ステップを増やしたり並べ替えたりするときは、
**必要な値が `ctx` にそろってから呼ぶ**ことだけ守れば動きます。

### 抽出（Extractor）の種類

`inspect` の「抽出する変数」列の `var←kind[...]` と、生成されるコードの対応です。

| kind | 値の出どころ | 生成されるコード（概形） |
|---|---|---|
| `html_input` | `<input name="X" value="…">`（CSRF hidden input、WebForms の `__VIEWSTATE` など） | `_attr(soup, 'input[name="X"]', 'value')` |
| `html_meta` | `<meta name="X" content="…">` | `_attr(soup, 'meta[name="X"]', 'content')` |
| `html_attr` | 要素の属性（`href` の中のトークンなど）。必要なら正規表現で部分抽出 | `_attr(soup, '#id', 'href')` / `_regex(_attr(...), pattern)` |
| `html_text` | 要素のテキスト | `_elem_text(soup, 'selector')`（必要なら `_regex(_elem_text(...), pattern)`） |
| `json` | JSON レスポンスの中の値（`data.items[0].id`） | `_json_path(data, ['data', 'items', 0, 'id'])`（`data = resp.json()`） |
| `header` | レスポンスヘッダ | `resp.headers.get('X-Request-Id')` |
| `cookie` | Cookie（`Set-Cookie` された値をヘッダ等で送り返す場合） | `session.cookies.get('XSRF-TOKEN')`（必要なら `unquote(...)`） |
| `regex` | インライン `<script>` やテキスト本文の中の値 | `_regex(_text(resp), r'...(…)...')` |
| `url` | リダイレクト後の最終 URL に含まれる値（認可コードなど） | `_regex(resp.url, r'...(…)...')` |

正規表現にはすべて**ちょうど 1 つ**のキャプチャグループがあり、記録されたレスポンスで実際にマッチすることを
生成時に検証しています。コメントに「記録時の値」が入っているので、動かなくなったときに見比べられます。

### ループ

`page=1,2,3` のように**同じリクエストが値 1 つだけ変えて 3 回以上**連続していると、1 つのステップに折りたたまれ、
`main()` の `for page in range(1, 4):` から呼ばれます。範囲を広げたいときは `range(1, 4)` を書き換えてください。
値が連番でない場合は `for page in ['a', 'b', 'c']:` のようにリストになります。
ループが邪魔なら `--no-loops` で無効化できます。

### 定数と秘密情報の扱い

- 名前に `password` / `passwd` / `pwd` / `secret` / `api_key` / `token` / `authorization` / `otp` などを含むパラメータは
  **秘密情報**とみなし、`NAME = os.environ.get("REQREC_NAME", "")` になります。記録した値はコードに書かれません。
- 複数のステップで同じ値が送られていて、どのレスポンスからも見つからなかった値（ユーザー名、組織 ID など）は
  `UPPER_SNAKE` の定数として先頭に出ます。別のアカウントで動かすときはここだけ直せば済みます。
- Basic / Digest 認証のユーザー名は `AUTH_USERNAME`、パスワードは `AUTH_PASSWORD`（環境変数 `REQREC_AUTH_PASSWORD`）になります。
  NTLM / Negotiate の `Authorization` ヘッダは**コードに一切出ません**（`session.auth` が毎回計算します）。
- パスワードらしい名前の項目は、値が短くても（`admin`、`123` など）、ユーザー ID と同じ値でも、必ず秘密情報として
  環境変数から読みます。
- 秘密情報（と Basic / Digest 認証のパスワード）は**必須**です。値が空のままだと、スクリプトはサーバーに何も送らずに
  「環境変数 REQREC_TXT_PASSWORD が設定されていません」と表示して止まります（空のパスワードでログインを試みて、
  後の手順で分かりにくいエラーになることはありません）。環境変数の代わりに、スクリプト先頭の定数
  （`TXT_PASSWORD = …`）に直接書いても動きます。GUI の [試しに実行する] では入力欄に入れた値が使われます。
- `--no-redact` を付けると秘密情報も記録した値のまま埋め込みます。**共有しないファイルにだけ**使ってください。

### ダウンロードしたファイル（Excel / CSV 出力など）

- 応答が `Content-Disposition: attachment`（ファイルとして保存。`inline` は対象外）か、Excel などのバイナリなら、
  スクリプトは**途中の手順でも、最後の手順でも、繰り返しの各回でも**、その応答を受け取った直後にファイルに保存して
  「… に保存しました」と表示します（後の手順が失敗しても保存済みのファイルは残ります）。HTML の表を Excel として
  出力するような、種類が HTML のダウンロードも保存されます。
- ファイル名はサーバーが付けた名前（日本語可。`filename*=UTF-8''…`、IE 向けの URL エンコード、Shift_JIS の生バイト、
  .NET が使う `=?UTF-8?B?…?=` 形式のいずれにも対応）で、無ければ URL の末尾、それも無ければ `output.xlsx` のように
  種類から決めます。1 回の実行で同じ名前が続いたときは `名前 (2).xlsx` のように番号を付けます（前回の実行で作られた
  同名ファイルは上書きします）。`CON` などの Windows で使えない名前や長すぎる名前は自動で直します。
- 保存先は環境変数 `REQREC_OUTPUT_DIR`（無ければスクリプトを実行したフォルダ）。GUI から実行したときは作業フォルダの
  `outputs\` です。かんたん画面の「保存されるファイル」欄に、記録から分かるファイル名が表示されます。
- 記録ファイル（HAR / rec.json）自体には秘密情報がすべて入っています。扱いには注意してください。

## 依存関係検出の仕組み

「このリクエストのこの値は、前のどのレスポンスから来たか」を突き止めるのが reqrec の中核です。
各リクエストのクエリ・フォーム・JSON の葉・マルチパートのテキスト・パスの一部・ヘッダの値を候補にし、
**時間的に後のレスポンスから先に**、次の場所を探します（URL エンコード / HTML エスケープ / JSON の `\/` の違いは吸収します）。

| 探す場所 | 例 |
|---|---|
| CSRF hidden input | Laravel / Rails / Django のログインフォームの `_token` / `authenticity_token` / `csrfmiddlewaretoken`、WebForms の `__VIEWSTATE` / `__EVENTVALIDATION` |
| `<meta name=... content=...>` | `<meta name="csrf-token">` → `X-CSRF-Token` ヘッダ |
| JSON レスポンス | ログイン API が返す `access_token` → `Authorization: Bearer …` |
| Cookie | `Set-Cookie: XSRF-TOKEN=…` → `X-XSRF-TOKEN` ヘッダ（URL デコードの違いも対応） |
| inline `<script>` / 任意のテキスト本文 | `window.API_TOKEN = "…"` → 周辺の文字列を使った正規表現 |
| 要素の属性 / テキスト | `<a id="export-link" href="/export?sig=…">` → `href` の中の `sig`、`<a href="Report.aspx?id=1234">` → `id` |
| `Location` / 最終 URL | OAuth の `code=…` が付いた戻り先 URL |
| タイムスタンプ | `_=1696…`（キャッシュ避け）→ `str(int(time.time()*1000))` に置換 |
| 繰り返し（ページネーション） | `page=1,2,3` / `offset=0,20,40` → ループ変数 |

HTTP 認証（NTLM / Negotiate / Basic / Digest）の `Authorization` ヘッダは、認証が検出されると候補から外れ、
`session.auth` に任せます（Bearer トークンは従来どおり追跡されます）。

補足:

- `Referer` ヘッダーに、同じ手順で取り出した値（URL キーなど）が含まれていれば、その部分も取り出した値に差し替えます
  （記録時の古いセッション値を送りません）。
- URL のパスのうち `Login.aspx` / `News.aspx` / `orders` のような英字だけの部分はページ名とみなし、追跡しません。
  数字やランダムな文字列を含む部分（`/orders/1234`、`/s/xBBHOHpXYZgFKyNZpuWy`）は追跡します。
- 英字だけでも、大文字・小文字が不規則に混ざった長い値（`xBBHOHpXYZgFKyNZpuWy`）はランダムなトークンとして扱います
  （`getElementById` や `XMLHttpRequest` のような単語の形は単語のまま）。

どこからも見つからなかった値は、記録した**リテラルのまま**出力されます。その値がランダムに見える場合
（長い英数字列など）は `looks dynamic` の警告が出ます。これは「次回の実行で失敗する可能性が高い場所」のサインです。

## 検出できないケースと対処

HTTP の記録から機械的に分かることには限界があります。次のものは**自動では再現できません**。

| ケース | 症状 | 対処 |
|---|---|---|
| **JavaScript で計算される署名・HMAC・暗号化**（リクエストごとに JS がパラメータに署名する、パスワードを JS でハッシュしてから送る、など） | 値が `looks dynamic` 警告付きのリテラルで出る。2 回目以降に 401/403 | ブラウザの DevTools（Sources タブ）で計算している JS を探し、同じ計算を Python で書く。鍵が JS に埋め込まれていれば再現できることが多い |
| **CAPTCHA**（reCAPTCHA, hCaptcha, 画像認証） | トークンパラメータ（`g-recaptcha-response` 等）がリテラルで出る | 自動化はできません。CAPTCHA のないフロー・API を探すか、人が解いた値を渡す設計にする |
| **ボット対策**（Cloudflare, Akamai, Imperva, PerimeterX など） | 403 / 429 / チャレンジページ（HTML）が返る。`cf_clearance` などの Cookie がリテラルで出る | 記録直後は `INITIAL_COOKIES` の Cookie で一時的に通ることがあるが、期限切れで止まる。根本的には回避対象ではありません。公式 API や許可された手段を使う |
| **TLS / HTTP2 フィンガープリント** | `requests` だけが 403 になり、ブラウザは通る | ヘッダを完全に合わせても通らない場合は、クライアントの指紋で判定されています。同様に、回避対象ではありません |
| **WebSocket / Server-Sent Events** | `inspect` で `websocket` / `server-sent events stream` として除外される | WebSocket は `websockets` ライブラリなどで別途実装する |
| **動的に変わる URL**（レスポンスから取れない ID が URL に入る、日付でパスが変わる） | URL がリテラルで固定される | URL の一部を変数にして `main()` で生成する。日付なら `time.strftime` |
| **記録に入っていない前提条件**（ログイン済みの Cookie、別タブで取得したトークン） | `INITIAL_COOKIES` に Cookie が出る。警告 `existed before the recording started` | ログインを含めて最初から記録し直す（推奨）。別タブなら[そのタブも記録して結合](#別タブで開く画面を記録する)する。または `INITIAL_COOKIES` を都度更新する |
| **レスポンス本文がない HAR** | 抽出がまったく検出されない | 「HAR with content」で保存し直す（[FAQ](#トラブルシューティング-faq)） |
| **Kerberos 限定（NTLM を受け付けない）サーバー** | 生成コードが Windows 以外で 401 | Windows で `reqrec[sspi]` を使う（ドメイン参加 PC のログオン情報で Kerberos も通る） |

いずれの場合も、生成コードは**読みやすい出発点**として使えます。該当ステップの関数の中身を直すだけで、
他のステップはそのまま動きます。`--keep-static` / `--keep-all` / `--include-host` で解析対象を広げると、
`.js` ファイル内の定数など追加の手がかりが残ることがあります。

## オプション一覧

### 入力ファイル（`import` / `inspect` / `generate` 共通）

`INPUT` には `.har` / `.mitm` / `.flows` / `.json`（HAR または reqrec の記録）を **1 つ以上**指定できます。
複数指定すると時刻順に結合して 1 つの記録として扱います（[別タブで開く画面を記録する](#別タブで開く画面を記録する)）。

### フィルタ / 解析オプション（`inspect` と `generate` 共通）

| オプション | 意味 | 既定 |
|---|---|---|
| `--include-host HOST` | このホスト（とサブドメイン）へのリクエストだけ残す。繰り返し指定・カンマ区切り可 | すべて |
| `--exclude-host HOST` | このホスト（とサブドメイン）を除外する。繰り返し指定・カンマ区切り可 | なし |
| `--keep-static` | 画像・CSS・JS・フォント等の静的ファイルも残す | 除外 |
| `--keep-trackers` | アクセス解析・広告などトラッカーへのリクエストも残す | 除外 |
| `--keep-all` | ノイズ除去をすべて無効（ホスト指定・手動除外だけ適用） | オフ |
| `--no-collapse-redirects` | リダイレクトの連鎖を 1 ステップにまとめない | まとめる |
| `--no-loops` | 繰り返しをループに折りたたまない | 折りたたむ |
| `--min-value-length N` | 依存関係の検出対象にする値の最小文字数（短すぎる値は誤検出のもと） | 4 |
| `--max-steps N` | ステップ数の上限（巨大な記録の安全弁。超えた分は警告付きで切り捨て） | なし |
| `--no-redact` | 秘密情報を環境変数に置き換えず、記録した値を埋め込む | 置き換える |
| `--no-detect-auth` | NTLM / Negotiate / Basic / Digest 認証のやり取り（401 → `Authorization`）を検出して `session.auth` にまとめる処理を行わない | 検出する |
| `--exclude-flow ID` | この ID のリクエストを除外する（理由 `excluded by user`）。繰り返し指定・カンマ区切り可。ID は `inspect` に表示 | なし |
| `--include-flow ID` | この ID のリクエストをノイズ判定に関係なく採用する（レスポンスのないものは不可） | なし |
| `--final-flow ID` | この ID のリクエストを含むステップを「結果にするステップ」にする | 最後のステップ |
| `--exclude-step N` | ステップ番号 N（オプションなしで `inspect` したときの番号）のリクエストを除外する | なし |
| `--final-step N` | ステップ番号 N を「結果にするステップ」にする | 最後のステップ |

既定で除外されるもの: 手動で除外したもの、ホストの指定に合わないもの、レスポンスがないもの、`OPTIONS`（CORS preflight）、
トラッカー、静的ファイル（拡張子 / MIME / リソース種別で判定）、`304 Not Modified`、WebSocket、SSE。
HTTP 認証の 401 応答（ハンドシェイクの途中）は、最終的に成功したリクエストと 1 つのステップにまとめられます。
HTML・JSON・XML・テキスト・リダイレクト・ダウンロード（CSV / PDF 等）は残ります。

### コード生成オプション（`generate`）

| オプション | 意味 | 既定 |
|---|---|---|
| `-o FILE` / `--out FILE` | 出力先。`-` で標準出力 | （必須） |
| `--html-parser html.parser\|lxml` | 生成コードが BeautifulSoup に渡すパーサー。`lxml` は高速だが別途インストールが必要 | `html.parser` |
| `--no-comments` | 説明コメントを出さない | 出す |
| `--delay SEC` | ステップ間の待ち時間（秒） | 0 |
| `--timeout SEC` | 各リクエストのタイムアウト（秒） | 30 |
| `--strict-status` | 記録時と同じステータスでなければエラーにする（既定は 4xx/5xx のみエラー、違いは警告） | オフ |
| `--legacy-tls` | TLS 1.0 / 1.1 と弱い暗号しか使えない古いサーバー向けの HTTPS アダプタ（`_LegacyTLSAdapter`）を生成コードに入れる | オフ |
| `--dump-plan FILE` | 解析結果（Plan）を JSON で書き出す（秘密情報の定数の値は含まれない） | なし |
| `--run` | 生成後すぐ同じ Python で実行し、その終了コードを返す（環境変数は引き継がれる） | オフ |

### `record`

| オプション | 意味 | 既定 |
|---|---|---|
| `-o FILE` | 記録の保存先（JSON） | （必須） |
| `-p PORT` / `--port PORT` | 待ち受けポート | 8080 |
| `--listen-host HOST` | 待ち受けアドレス。他の端末（スマホ）から使うなら `0.0.0.0` | 127.0.0.1 |
| `--hosts HOST` | 記録対象をこのホスト（とサブドメイン）に限定。繰り返し指定・カンマ区切り可 | すべて |
| `-v` / `--verbose` | mitmdump 自体の出力も表示 | オフ |
| `--mitm-arg ARG` | mitmdump にそのまま渡す追加引数（`--mitm-arg=--ssl-insecure` のように `=` で書く） | なし |

### `gui`

| オプション | 意味 | 既定 |
|---|---|---|
| `--host HOST` | 待ち受けアドレス（他の端末から使わせるなら `0.0.0.0`。[セキュリティ](#gui-のセキュリティなぜローカル専用か)を参照） | 127.0.0.1 |
| `--port PORT` | 待ち受けポート | 8765 |
| `--workdir DIR` | 作業フォルダ（`recordings/` `uploads/` `scripts/` `outputs/` が作られる） | `./reqrec_work` |
| `--no-browser` | ブラウザを自動で開かない | 開く |

### 終了コード

`0` 正常終了 / `1` 実行時エラー（ファイルがない、形式が未対応、mitmproxy 未インストール、GUI のポートが使用中など。`エラー: …` を表示）/
`2` 引数の誤り。`--run` のときはスクリプトの終了コードがそのまま返ります。`reqrec gui` は `Ctrl+C` で `0` を返します。

## Windows での配布と exe 化

**記録用ブラウザの事前ビルド（IT 担当向け・推奨）**

記録用ブラウザ（`RecBrowser.exe`）は、何もしなければ各 PC の作業フォルダ（ユーザーのフォルダの下）で初回に
コンパイルされます。工場の PC では、ユーザーのフォルダにある実行ファイルの起動がセキュリティ設定（AppLocker
など）で禁止されていることがあるため、配布フォルダを作るときに一度だけ次を実行してください。

```bat
python -m reqrec.iehost build
```

reqrec のフォルダ（`reqrec\iehost\`）に `RecBrowser.exe` と `RecBrowser.exe.sha256` ができ、各 PC はそれを
その場所から直接起動します（ユーザーのフォルダには何も作りません）。セキュリティ設定では、この配布フォルダの
実行だけを許可すれば足ります。reqrec を更新したら同じコマンドで作り直してください（古いままだと、各 PC の
作業フォルダでのコンパイルに戻ります）。`python -m reqrec.iehost status` で作成済みか確認できます。
記録用ブラウザは常に 32 ビット版で作られます（IE モードと同じく、古い社内サイトの 32 ビット ActiveX 部品を読み込めるように）。


**Python を入れて使う（推奨）**

1. [python.org](https://www.python.org/downloads/windows/) のインストーラで Python 3.10 以上を入れる
   （「Add python.exe to PATH」にチェック）。
2. reqrec のフォルダ（または wheel ファイル）をコピーし、コマンド プロンプトで
   ```bat
   cd reqrec
   pip install ".[record]"
   reqrec gui
   ```
   社内配布なら `pip wheel . -w dist` で作った `dist\reqrec-0.1.0-py3-none-any.whl` を配り、
   `pip install reqrec-0.1.0-py3-none-any.whl mitmproxy` としてもらう方法もあります。
3. 統合 Windows 認証のサイトを再現するスクリプトを動かす PC には `pip install "reqrec[sspi]"` も入れます。

**exe 化（PyInstaller）— 未検証**

Python を入れられない PC に配りたい場合は PyInstaller で単一の exe にする方法が考えられます。
次のコマンドは**設計上の例であり、動作は検証していません**。mitmproxy は依存パッケージが多く、
hidden import の追加や exe サイズ（数百 MB）、ウイルス対策ソフトによる誤検知への対応が必要になる見込みです。

```bat
pip install pyinstaller
pyinstaller --onefile --name reqrec --collect-all reqrec --collect-all mitmproxy -m reqrec.cli
```

（`-m` が使えない PyInstaller のバージョンでは、`from reqrec.cli import main; raise SystemExit(main())` と書いた
`reqrec_launcher.py` を作り、それを `pyinstaller --onefile --name reqrec --collect-all reqrec --collect-all mitmproxy reqrec_launcher.py`
のように渡します。こちらも未検証です。）出来上がった `reqrec.exe gui` で GUI が起動するか、記録（mitmproxy の起動）が
できるかを、配布前に必ず確認してください。

## 法的・倫理的な注意

reqrec は、**自分がアクセスする権利を持つサイト**での作業（自分のアカウントのデータ取得、自社サービスのテスト、
公開データの収集など）を楽にするための道具です。使う前に必ず確認してください。

- **利用規約**を読む。自動アクセスやスクレイピングを明示的に禁じているサイトは少なくありません。
- **robots.txt** と、サイトが提供する**公式 API** を優先する。API があるならそれを使うのが双方にとって最善です。
- **レート制限**を守る。`--delay` で待ち時間を入れ、必要以上の頻度・並列数でアクセスしない。
  相手のサーバーに負荷をかける行為は、法的責任を問われることがあります。
- **個人情報**・他人のデータを扱う場合は、個人情報保護法などの法令と、取得目的の範囲を守る。
- **認証の回避・アクセス制御の突破・ボット対策の回避**を目的に使わない。不正アクセス禁止法等に抵触し得ます。
  社内システムでも、情報システム部門のルール（自動化ツールの利用可否、アカウントの共用禁止など）を確認してください。
- 記録ファイル（HAR / JSON）と生成コードには **Cookie・トークン・パスワード** が含まれ得ます。
  共有・公開・コミットしない。作業が終わったら削除する。GUI の作業フォルダも同様です。

## トラブルシューティング FAQ

**Q. 生成したスクリプトを実行すると 403（または 401 / 429）になる。ブラウザでは見られる。**

1. まず `_check` の警告メッセージで**どのステップ**で失敗したかを確認します。最初のステップから 403 なら、
   ヘッダ / Cookie / フィンガープリントの問題。途中からなら、トークンの抽出漏れの可能性が高いです。
2. ヘッダ: `BASE_HEADERS` と各ステップの `headers` が記録時と同じか（`--keep-all` で `inspect` し直すと、
   除外されたリクエストにヒントがあることも）。
3. Cookie: ログイン前から必要な Cookie（同意バナー、A/B テスト、ボット対策の `cf_clearance` 等）が
   `INITIAL_COOKIES` に入っているか。期限切れなら記録し直す。
4. それでも通らない場合は TLS / HTTP2 のフィンガープリントで判定されています（[検出できないケース](#検出できないケースと対処)）。
   利用規約を確認し、公式 API を探してください。

**Q. 401 が繰り返される / 最初のステップで 401 になる（社内サイト）。**

統合 Windows 認証（NTLM / Negotiate）か Basic 認証のサイトです。

- `inspect`（GUI では「解析結果 → HTTP 認証」）に認証が**検出されているか**確認します。検出されていれば生成コードは
  `session.auth` を使っています。実行する PC に `pip install "reqrec[sspi]"`（Windows、同じユーザー）または
  `pip install "reqrec[ntlm]"` + 環境変数 `REQREC_NTLM_USER`（`DOMAIN\user`）/ `REQREC_NTLM_PASSWORD` が必要です。
  `ImportError: No module named 'requests_ntlm'` が出るなら未インストールです。
- Basic / Digest 認証なら環境変数 `REQREC_AUTH_PASSWORD` を設定してください（GUI の「5 実行」に入力欄が出ます）。
- 検出されていない（`Authorization: NTLM …` がステップのヘッダにリテラルで残っている）場合は、記録に 401 の応答が
  含まれていないことが原因です（ブラウザが認証情報をキャッシュしていて最初から `Authorization` 付きで送っている）。
  ブラウザを**すべて閉じてから**記録を始める、または GUI の「HTTP 認証 … を検出して統合する」がオンか確認してください。
- サーバーが Kerberos しか受け付けない場合、`requests_ntlm` では通りません。Windows で `reqrec[sspi]` を使ってください。

**Q. 1 回目は動いたのに、2 回目（または翌日）に失敗する。**

ほぼ確実に、**抽出できていないトークン**がリテラルのまま埋め込まれています。

- `reqrec inspect` の警告 `looks dynamic` が出ているパラメータを見る。
- 失敗するステップの関数で、ランダムに見える文字列（`'a8f3…'`）を探す。
- その値がどこから来たかを DevTools（GUI なら行をクリックして開く詳細ドロワー）で調べる
  （Network タブの検索欄に値を貼ると、含むレスポンスが見つかります）。
  レスポンスにあれば `_regex` / `_attr` で抽出コードを書く。JS が計算しているなら Python で同じ計算を書く。
- `INITIAL_COOKIES` のセッション Cookie が期限切れになっている場合もあります（ログインを含めて記録し直す）。

**Q. `inspect` の「抽出する変数」が全部 `-` で、警告も出ない。HAR にレスポンス本文が入っていない？**

- Chrome / Edge では「Save all as HAR **with content**」を選ぶ必要があります。`content` なし（または sanitized）の
  HAR には本文がなく、トークンの出どころを探せません。
- Firefox で大きなレスポンスが途中で切れている場合は `about:config` → `devtools.netmonitor.responseBodyLimit` を増やします。
- IE11 の F12 で保存した HAR も本文が欠けることがあります。プロキシ記録に切り替えてください。
- HAR の `entries[].response.content.text` が空なら本文なしです。

**Q. 必要な API リクエストが「除外」されてしまう。**

`.json` / `.js` / `.php` のような拡張子や `application/octet-stream` の判定に引っかかることがあります。
GUI ならその行の「採用」にチェックを付けるだけです。CLI では `--include-flow f0012`（1 件だけ戻す）、
`--keep-static`（静的ファイル判定を無効化）、`--include-host api.example.com` で調整してください。
`--keep-all` ですべてを残し、`--exclude-host` / `--exclude-flow` で不要なものを外す方法もあります。

**Q. 別タブや拡張機能の通信が混ざって、ステップが多すぎる。**

`--include-host example.com`（サブドメインも含む）で対象サイトに絞るか、`--exclude-host` で外します。
1 件ずつなら GUI のチェックを外す、または `--exclude-step N` / `--exclude-flow ID`。
記録時に専用のプロファイル（Chrome の `--user-data-dir`）やプライベートウィンドウを使うと混入を防げます。

**Q. 新しいタブで開いた画面が記録（HAR）に入っていない。**

DevTools はタブ単位です。[別タブで開く画面を記録する](#別タブで開く画面を記録する) の手順
（「ポップアップに対して DevTools を自動的に開く」→ タブごとに保存 → 複数ファイルを指定）に従うか、
プロキシ記録（全タブが入る）に切り替えてください。

**Q. ページ送りが 2 ページしかなく、ループにならない。**

ループ検出は 3 回以上の連続が条件です。`main()` で手で `for` に書き換えるか、3 ページ以上めくって記録してください。

**Q. 記録中、HTTPS サイトが開けない / ブラウザが証明書エラーを出す（記録時）。**

mitmproxy の CA 証明書がインストール（かつ信頼）されていません。Windows なら GUI の [CA 証明書をインストール]
（または `certutil -user -addstore Root %USERPROFILE%\.mitmproxy\mitmproxy-ca-cert.cer`）。他の OS はプロキシ経由で
http://mitm.it を開いて手順に従ってください。iOS は「証明書信頼設定」で信頼をオンにする必要があります。
Firefox は OS とは別に証明書をインポートします。証明書ファイルは**プロキシを一度起動すると**作られます。

**Q. 生成したスクリプトが `SSLError: CERTIFICATE_VERIFY_FAILED` になる（実行時）。**

サイトが社内 CA や自己署名の証明書を使っています（記録時はブラウザが社内 CA を信頼していたので気づきません）。
生成コード先頭の `VERIFY_TLS = True` を、社内 CA 証明書（PEM 形式）のパス、または `False`（検証しない。社内サーバー限定で）に変えてください。

**Q. IE モードのサイトで `SSLError`（`unsupported protocol` / `handshake failure` / `dh key too small` / `legacy renegotiation`）になる。**

サーバーが TLS 1.0 / 1.1 や古い暗号スイートしか話せません。`reqrec generate … --legacy-tls`、または GUI の
「古い TLS / 暗号しか使えないサーバー … 向けの接続設定を生成コードに入れる」をチェックして生成し直してください
（[古い TLS しか使えないサーバー](#古い-tls-しか使えないサーバー--legacy-tls)）。

**Q. 日本語が化ける（`�` や `ãƒ` のような文字になる）。**

生成コードは `Content-Type` の charset → `<meta charset>` → 推定の順で文字コードを判定し、Shift_JIS 系は `cp932` で
扱うので、通常は化けません。それでも化ける場合は、(1) 記録ファイルの段階で化けていないか GUI の詳細ドロワーで
レスポンス本文を確認し（IE11 の HAR は本文の文字コード情報が落ちることがあります → プロキシ記録へ）、
(2) 生成コードの該当ステップで `resp.encoding = "cp932"`（または `"euc_jp"`）を `_text(resp)` / `_soup(resp)` の前に
明示してください。Windows のコンソール自体の文字コードが原因のこともあります（`chcp 65001`、または結果をファイルに保存して確認）。

**Q. `reqrec gui` を実行しても GUI が開かない。**

- `GUI を起動できません: ポート 8765 は既に使われています` → 別の `reqrec gui` が動いているか、他のソフトが使っています。
  `reqrec gui --port 8766` のように別のポートを指定します。
- サーバーは起動した（`GUI を起動しました: http://127.0.0.1:8765`）がブラウザが開かない → その URL を手でブラウザに
  貼ってください。既定ブラウザの設定によっては自動で開けないことがあります（`--no-browser` で自動起動を切れます）。
- 「この Host ヘッダーからのアクセスは許可されていません」→ `http://127.0.0.1:8765` か `http://localhost:8765` で
  開いてください（PC 名や別の IP では開けません。他の端末から使うなら `--host 0.0.0.0` で起動）。
- 「認証トークンが一致しません」→ 古いタブが残っています。ページを再読み込みしてください。

**Q. かんたん画面に「記録用ブラウザ (IE エンジン): 準備できていません」と出る / 記録用ブラウザが開かない。**

- 「コンパイラ (csc.exe) が見つかりません」→ Windows 標準の .NET Framework 4.x（`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe`）
  がない PC です。管理者に「.NET Framework 4.8 の機能を有効にしてほしい」と伝えるか、別の PC で作られた
  `RecBrowser.exe` を `reqrec/iehost/` フォルダ（ソースの隣）に置くと、コンパイルせずに使えます。
  それまでは、かんたん画面が自動で切り替わる従来の Edge + システムプロキシの方法で記録できます。
- 「記録用ブラウザの作成 (コンパイル) に失敗しました」→ メッセージにコンパイラの出力が続きます。古い記録用ブラウザが
  開いたままだと上書きできないので、閉じてからもう一度 [記録をはじめる] を押してください。
- 記録用ブラウザは開いたが件数が増えない → `https://` のページは記録されません（`http://` のページだけ）。
  アドレス欄に `http://` で始まるアドレスを入れて開いてください。
- 記録用ブラウザのログは作業フォルダの `logs\recbrowser_<日時>.log` にあります（先頭の `proxy 127.0.0.1:<ポート> -> ok`
  でプロキシ設定が効いたことが分かります）。

**Q. 記録を止めたのに Windows のプロキシ設定が残ってしまった（ブラウザがどこにもつながらない）。**

GUI を開いて「1 記録」→「Windows の設定」カードの **[プロキシ設定を元に戻す]** を押してください。GUI がもう動いていない
場合は、コントロール パネル → ネットワークとインターネット → **インターネット オプション** → 接続 → LAN の設定 →
「LAN にプロキシ サーバーを使用する」のチェックを外します（Windows の設定 → ネットワークとインターネット → プロキシ →
「プロキシ サーバーを使う」をオフ、でも同じです）。GUI は通常、[記録停止して読み込む] と終了時に自動で元に戻します。

**Q. スマホアプリが「ネットワークエラー」になり、記録できない。**

アプリが証明書ピンニングをしているか、ユーザー CA を信頼しない設定です（Android 7 以降の既定）。
reqrec では対処できません。アプリ内の Web ページや、同じサービスの Web 版を記録してください。

**Q. `エラー: mitmproxy がインストールされていません` / GUI に「mitmproxy が見つかりません」と出る。**

`pip install "reqrec[record]"`（または `pip install mitmproxy`）を実行し、GUI は再起動してください。
`.mitm` ファイルの読み込みにも mitmproxy が必要です。HAR だけを使う場合は不要です。

## 開発者向け

```console
$ pip install -e ".[dev]"
$ python -m playwright install chromium   # GUI のブラウザテスト用（任意。無ければそのテストはスキップされる）
$ python3 -m pytest                       # すべてのテスト
$ python3 -m pytest tests/test_cli.py -q
$ python3 -m pytest tests/test_webapp.py tests/test_webapp_browser.py -q
```

- **モジュール構成と各モジュールの契約は [`DESIGN.md`](DESIGN.md)** にまとまっています（§1〜§12 が v0.1 の CLI パイプライン、
  **§13 が GUI / IE モード / 複数記録の結合**）。`reqrec/model.py`（データ型）と `reqrec/util.py`（共通ヘルパー）がすべての基盤です。
- パイプライン: `importers/`（HAR・mitmproxy → `Recording`、`load_recordings` で複数ファイルを結合）→ `filters.py`
  （ノイズ除去・手動の採用/除外・認証ハンドシェイク統合・リダイレクト統合・Cookie 分類）→ `loops.py`（ループ検出）→
  `deps.py`（依存関係検出）→ `plan.py`（`Plan` 構築、「結果にするステップ」）→ `codegen.py`（コード生成、`session.auth` /
  `VERIFY_TLS` / レガシー TLS / 文字コード）→ `cli.py`。
- GUI: `webapp/`（`create_app` / `run_gui`、`routes.py` の JSON API、`state.py` のプロセス内状態、`templates/index.html` と
  `static/app.js` / `app.css`。外部 CDN を使わないのでオフラインで動く）、`recorder/manager.py`（mitmdump 子プロセスの管理）、
  `winsupport.py`（Windows のシステムプロキシ・`certutil`。`winreg` / `subprocess` を注入してテストする）。
- テスト: `tests/fixtures/*.har` は手書きの現実的な HAR（`legacy_webforms_ntlm.har` は NTLM + Shift_JIS + WebForms の
  IE モード風記録）、`tests/e2e/` はローカル HTTP サーバーに対して「記録 → 生成 → 生成コードをサブプロセスで実行」まで通す
  エンドツーエンドテスト、`tests/test_webapp.py` は Flask のテストクライアントで全エンドポイントとトークン / Host / Origin /
  パストラバーサルの拒否を検証、`tests/test_webapp_browser.py` は **Playwright（Chromium）で実際に GUI を操作**する
  テストです（HAR をアップロード → 表を待つ → チェックを外して再計算 → 結果を選ぶ → 生成 → 保存。Chromium が無い
  環境では自動でスキップ。バイナリの場所は環境変数 `REQREC_CHROMIUM` で指定可）。`tests/e2e/test_gui_recording.py` は
  **本物の `mitmdump`** を GUI の記録機能から起動し、ローカルサイトをプロキシ経由で操作して「記録停止して読み込む →
  ステップ表 → 生成 → 実行」まで通します（mitmproxy が無い環境ではスキップ）。`tests/test_integration.py` は同梱 HAR
  （IE モード風の `legacy_webforms_ntlm.har`、複数ファイルの結合、手動の取捨選択）を解析・生成し、生成コードを偽サイトに
  対して実行します。
- 生成コードに記録由来の文字列を埋め込むときは**必ず `repr()` / `json.dumps()`** を通します
  （記録内容は攻撃者が制御し得る入力なので、文字列連結でソースに混ぜてはいけません）。GUI も同じ理由で、記録内容は
  `textContent` でのみ描画します。

## ライセンス

MIT
