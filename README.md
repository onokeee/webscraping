# reqrec — HTTP レベルの「マクロ記録」で Python スクレイピングコードを生成する

**reqrec** は、Web サイトを操作したときにブラウザが実際に送受信した **HTTP リクエスト / レスポンス** を記録し、
同じやりとりを再現する **単体で動く Python スクリプト**（`requests` + `BeautifulSoup`）を生成するツールです。

画面の要素（ボタンや入力欄）をつかんで操作を再現する Selenium / Playwright 型の「マクロ記録」ではなく、
**HTTP の会話そのもの**を記録してコードに書き起こします。生成されるコードにブラウザは不要で、
軽く・速く・安定して動きます。

コマンドライン（`reqrec generate`）に加えて、**コードを書かずにブラウザ上のボタン操作だけで使える GUI**
（`reqrec gui`）があります。Windows の **Edge IE モード**で使っている社内サイト（統合 Windows 認証、
Shift_JIS、ASP.NET WebForms）や、**別タブ・別窓で開く画面**にも対応しています。

> **対象は、Edge の IE モードで使う `http://` の社内サイトです。** `https://` のサイトや、Chrome / 通常の Edge
> （IE モードでないタブ）で使うサイトは対象外です。記録は GUI が開く**記録用ブラウザ**（IE モードと同じ
> IE エンジン、Windows のみ）だけで行い、Windows のプロキシ設定や証明書は一切変更しません。
> 記録用ブラウザが使えないときは、IE11 の F12 開発者ツールで保存した HAR を読み込んで使うこともできます。

```
ログインページを開く → ID/パスワードを送る → 一覧を 3 ページめくる → CSV をダウンロード
                                  ↓ 記録（GUI の記録用ブラウザ。保存済みの HAR も可）
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
> ほぼ `http://` なのでそのまま使えます。かんたん画面は Windows の設定や証明書を**一切変更しません**。
> 記録用ブラウザが使えない PC（Windows 以外の OS や、.NET Framework のコンパイラがない Windows）では、
> 準備状況の欄に理由が表示され、[記録をはじめる] は押せません。その PC では記録できません
> （HAR の読み込みからスクリプトを作ることはできます。対処は[トラブルシューティング FAQ](#トラブルシューティング-faq)
> の「準備できていません」を参照）。

フィルタ設定や通信の一覧を細かく見たいときは、右上の **[詳細設定を表示]** で 5 画面
（1 記録 → 2 読み込み → 3 ステップ → 4 コード → 5 実行）に切り替えられます。詳しくは
[GUI の使い方](#gui-の使い方reqrec-gui) を、統合 Windows 認証・文字コード・WebForms など社内サイト特有のことは
[Edge IE モードの社内サイト](#edge-ie-モードの社内サイト認証文字コードwebforms) を読んでください。

---

## 目次

- [クイックスタート（コードを書かずに使う）](#クイックスタートコードを書かずに使う)
- [何ができるか](#何ができるか)
- [仕組み](#仕組み)
- [インストール](#インストール)
- [記録方法（記録用ブラウザと HAR）](#記録方法記録用ブラウザと-har)
- [別タブで開く画面を記録する](#別タブで開く画面を記録する)
- [GUI の使い方（`reqrec gui`）](#gui-の使い方reqrec-gui)
- [Edge IE モードの社内サイト（認証・文字コード・WebForms）](#edge-ie-モードの社内サイト認証文字コードwebforms)
- [使い方: inspect → generate → 実行](#使い方-inspect--generate--実行)
- [ステップの手動選択と「結果にするステップ」](#ステップの手動選択と結果にするステップ)
- [同梱のサンプルで試す](#同梱のサンプルで試す)
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
 記録用ブラウザ (IE エンジン)
   │ このプロセスだけのプロキシ設定で
   ▼
 GUI の記録 (mitmproxy アドオン) ─────┐
                                      ├──▶ Recording ──▶ 解析 ───────▶ Plan ──────▶ コード生成 ──▶ scrape.py
 HAR (IE11 の F12 など) / 記録 JSON ──┘    (JSON)        │                          │
                                                         │ ・ノイズ除去             │ ・ステップ関数
                                                         │ ・認証ハンドシェイク統合 │ ・抽出コード
                                                         │ ・リダイレクト統合       │ ・session.auth / 文字コード
                                                         │ ・ループ検出             │ ・ダウンロードの保存
                                                         │ ・依存関係検出           │ ・main()
                                                         │ ・手動の採用/除外
```

1. **記録 / 読み込み** — 記録を共通の `Recording`（JSON）に変換します。GUI の記録も HAR も同じ形になります。
   記録用ブラウザは、自分の通信だけを GUI が起動した記録用プロキシ（mitmproxy に reqrec 自身をアドオンとして
   読み込ませたもの）に通し、プロキシは `http://` のレスポンスが返るたびに記録ファイル（JSON）を保存し直します
   （途中で止まっても壊れたファイルになりません）。
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

# GUI の記録（記録用ブラウザ）を使うなら mitmproxy を含めてインストール
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

インストールすると `reqrec` コマンドが使えるようになります（`python -m reqrec` でも同じです）。

```console
$ reqrec --version
reqrec 0.1.0
$ reqrec -h
```

> Windows で `reqrec` が見つからない場合は、Python のインストール時に「Add python.exe to PATH」を付けていないか、
> `Scripts` フォルダが PATH にありません。`python -m reqrec gui` のように起動すれば PATH に関係なく動きます。

reqrec の本体は `reqrec.py` 1 ファイルなので、pip でインストールせずに、必要なライブラリ（`requests` /
`beautifulsoup4` / `flask`、記録には `mitmproxy`）を入れた Python のフォルダ（`python.exe` のあるフォルダ）に
`reqrec.py` を置いて `python -m reqrec gui` で使うこともできます（[Windows での配布と exe 化](#windows-での配布と-exe-化)）。

## 記録方法（記録用ブラウザと HAR）

reqrec の記録は、GUI が開く**記録用ブラウザ**（Edge の IE モードと同じ IE エンジン。Windows のみ）だけで行います
（詳しくは [記録用ブラウザ（IE エンジン）](#記録用ブラウザie-エンジン)）。始め方は 2 つあり、どちらも同じ記録用ブラウザを使います。

| 始め方 | こんなときに | 終わり方 |
|---|---|---|
| かんたん画面の **[● 記録をはじめる]**（[クイックスタート](#クイックスタートコードを書かずに使う)） | まず試すならこちら。設定は不要 | 記録用ブラウザを閉じる（または [■ 記録をおわる]）と、そのままスクリプトができる |
| [詳細設定を表示] → **「1 記録」の [● 記録開始]**（[1. 記録](#1-記録--記録用ブラウザで記録する)） | 記録するサイトの絞り込み・追加モード・表示モードを使いたいとき | [■ 記録停止して読み込む] → 「3 ステップ」で確認・調整してから生成 |

どちらの場合も、記録を始めると GUI が次のことを自動で行います。

- 空いているポート（8080 から順に探し、GUI 自身のポートは避けます）で、記録用プロキシ（mitmproxy）を
  **この PC の中だけ**（`127.0.0.1`）で起動します。`https://` の通信は記録せずそのまま通すので、証明書は要りません。
- 記録用ブラウザを、**そのプロセスだけ**がこのプロキシを通る設定で起動します。インターネット オプションのプロキシ、
  Edge の設定、証明書ストアは変更しません。
- 記録用ブラウザで開いた `http://` のページの通信（別窓・ダイアログ・ダウンロードを含む）が記録され、
  作業フォルダの `recordings/rec_YYYYmmdd_HHMMSS.json` に保存されます。

記録の前に、**目的の操作だけを行う準備**をしておくと、あとの確認が楽になります（関係のないサイトを開かない、
ログインを含めて最初から操作する、など）。

### 保存済みの HAR を使う（IE11 の F12 開発者ツール）

記録用ブラウザが使えない PC などでは、IE11 の F12 開発者ツールで保存した HAR を読み込んでスクリプトを作ることも
できます。Edge の IE モードのタブは Edge（Chromium）ではなく IE11 のエンジンで動いているので、Edge の DevTools（F12）は
そのタブには使えません。代わりに `C:\Windows\System32\F12\IEChooser.exe` を起動してそのタブを選ぶと IE11 の F12
開発者ツールが開くので、「ネットワーク」タブを開いた状態で再現したい操作を最初から最後まで行い（記録が止まっていれば
▶ で開始）、**「HAR としてエクスポート」**（保存アイコン、`Ctrl+S`）で `.har` を保存します。

保存した `.har` はそのまま `reqrec inspect` / `reqrec generate`、GUI の「2 読み込み」に渡せます。
ただし、IE11 の HAR は**別タブの通信が入らない**（タブごとに F12 を開いて保存する必要がある）、レスポンス本文や
文字コードの情報が欠けることがある、といった弱点があるため、**記録用ブラウザでの記録を推奨**します。

> **HAR や記録ファイルには Cookie・パスワード・トークンがそのまま入っています。** 他人に渡さない、
> リポジトリにコミットしない（`.gitignore` の活用）、作業後は削除する、を徹底してください。

HAR / reqrec の JSON を 1 つの形式にまとめて保管したいときは `reqrec import` を使います。
複数のファイルを渡すと結合して 1 つの JSON にします。

```console
$ reqrec import traffic.har -o rec.json
14 件のフローを取り込みました（har, WebInspector/537.36） → rec.json
$ reqrec import tab1.har tab2.har -o rec.json      # 2 つのタブの HAR を結合して保存
```

## 別タブで開く画面を記録する

「検索結果の行をクリックすると詳細が**新しいタブ**で開く」「帳票が `window.open` でポップアップする」
といったサイトはよくあります。記録のしかたによって扱いが違います。

**記録用ブラウザ（かんたん画面 / 「1 記録」）** — 何もしなくてよい。
`window.open`、`target="_blank"` のリンクやフォーム、`showModalDialog` / `showModelessDialog` のダイアログは
記録用ブラウザの中でタブとして開き、元のタブと同じプロキシを通るので、1 つの記録に時刻順で入ります。

**HAR（IE11 の F12 開発者ツール）** — F12 開発者ツールは**タブ単位**です。元のタブの「ネットワーク」には、
新しいタブ / ウィンドウで行われた通信は出てきません。新しいタブの通信も必要なら、`IEChooser.exe` でそのタブも選んで
F12 開発者ツールを開き、**タブごとに** HAR を保存して（`tab1.har`、`tab2.har` …。順番はファイル名でなく時刻で
決まるので名前は自由です）、複数のファイルをまとめて渡します。F12 開発者ツールを開く前の通信は入らないので、
別タブを使うサイトは記録用ブラウザで記録するのが確実です。

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
$ reqrec gui --host 0.0.0.0                    # 他の PC から使わせる（パスワードが必要。記録はできない。下記参照）
```

| オプション | 意味 | 既定 |
|---|---|---|
| `--host HOST` | 待ち受けアドレス。`127.0.0.1` なら同じ PC のブラウザからだけ使える | `127.0.0.1` |
| `--port PORT` | 待ち受けポート | `8765` |
| `--workdir DIR` | 記録ファイル・読み込んだファイル・生成スクリプト・実行結果を保存する作業フォルダ | `./reqrec_work` |
| `--no-browser` | 起動時にブラウザを自動で開かない | 開く |

`Ctrl+C` で終了します。終了時には、記録用ブラウザと記録用プロキシ、実行中のスクリプトを止めます。

作業フォルダの中身:

| サブフォルダ | 内容 |
|---|---|
| `recordings/` | かんたん画面 / 「1 記録」で保存した記録（`rec_YYYYmmdd_HHMMSS.json`） |
| `uploads/` | 「2 読み込み」で読み込んだファイルのコピー（.har / .json） |
| `scripts/` | 「4 コード」で [保存] したスクリプト（`<名前>.py`）とかんたん画面が作ったスクリプト。「5 実行」はここのファイルを実行します |
| `outputs/` | 「5 実行」の [結果を保存] で保存した標準出力と、GUI から実行したスクリプトが保存したダウンロード（Excel / CSV など） |
| `bin/` / `logs/` | 記録用ブラウザ（`RecBrowser.exe`。事前ビルドがないときだけ）と、そのログ（`recbrowser_<日時>.log`） |

記録ファイルには Cookie やパスワードがそのまま入っています。作業フォルダは共有フォルダに置かず、作業が終わったら削除してください。

### かんたん画面（既定）

起動直後に表示される画面です。製造部門など、ポートやプロキシを知らない人が使う前提で、
**[記録をはじめる] → 記録用ブラウザでサイトを操作 → ブラウザを閉じる（または [記録をおわる]）** だけで完結します。
Windows の設定や証明書は変更しません。裏側では次のことを自動で行います。

| タイミング | 自動で行うこと |
|---|---|
| [記録をはじめる] | 空いているポートを選んで記録用プロキシを起動（この PC の中だけで待ち受け。`https://` は記録せず素通し）/ **記録用ブラウザ**（IE エンジン、初回だけ数秒でコンパイル）を、そのプロセスだけがプロキシを通る設定で起動（「開くサイトのアドレス」があればそのページ） |
| 記録中 | 記録した通信の件数をライブ表示。[ブラウザをもう一度開く]（記録用ブラウザが見当たらないとき）、[やめる]（記録を破棄）も可能 |
| 記録用ブラウザを閉じる / [記録をおわる] | 記録用ブラウザとプロキシを止める → 解析 → スクリプト生成 → `scripts/scrape_<サイト名>_<日時>.py` に保存 |
| できあがり | ファイル名・保存先・手順の数・最後に取得する画面を表示。[ダウンロード] / [保存先フォルダを開く] / [試しに実行する]（パスワードなどを入力して実行、結果の保存）/ [もう一度記録する] |

- 記録用ブラウザの中で開く別窓（`window.open` / `target="_blank"` / `showModalDialog` など）はタブとして開き、
  その通信もそのまま記録されます。ファイルのダウンロードも、保存ダイアログが出ない場合でも HTTP は記録されています。
- 記録されるのは `http://` のサイトだけです（証明書を登録しないため）。`https://` のページは表示はできますが、
  スクリプトには入りません（このツールの対象外です）。
- 記録用ブラウザが使えない PC（Windows 以外の OS や、Windows 標準の .NET Framework コンパイラ `csc.exe` がない
  Windows）では、準備状況の欄に「記録用ブラウザ (IE エンジン): 準備できていません: <理由>」と表示され、
  [記録をはじめる] は押せません。ほかの記録方法に切り替える仕組みはなく、`csc.exe` が使えるようになるか、
  `reqrec browser build` で作った記録用ブラウザを置くまで、その PC では記録できません
  （[FAQ](#トラブルシューティング-faq)。HAR の読み込みからスクリプトを作ることはできます）。
- 記録中に [やめる] を押すと、その記録は読み込まれずに破棄されます（それまで読み込んでいた記録はそのまま残ります）。
- 「詳細設定を表示」で読み込んだ記録（HAR など）があるときは、かんたん画面に
  [読み込み済みの記録からスクリプトを作る] が出ます。
- 右上の **[詳細設定を表示]** で下記の 5 画面に切り替えられ、同じ記録をそのまま細かく調整できます
  （[かんたん画面に戻る] で戻ります）。

### 記録用ブラウザ（IE エンジン）

かんたん画面の [記録をはじめる] と、詳細設定の「1 記録」の [記録開始] で開く reqrec 専用の小さなブラウザで、
reqrec の記録はすべてこのブラウザで行います（C# のソースは `reqrec.py` に埋め込み済み。初回起動時に Windows 標準の
`%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe` で作業フォルダの `bin\RecBrowser.exe` にコンパイルされ、
reqrec を更新したときだけ作り直されます。`reqrec browser build` で配布フォルダに作成済みなら、それをそのまま使います）。

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
- **閉じる = 記録終了**: かんたん画面から始めた記録は、記録用ブラウザを閉じる（× / 赤い [■ 記録をおわる]）と
  自動で止まり、スクリプトができます。詳細設定の「1 記録」から始めた記録は自動では止まらないので、
  [記録停止して読み込む] を押します。
- **表示モード**（詳細設定 → 1 記録 → 「表示モード (記録用ブラウザ)」）: 既定では IE7 互換表示（IE モードが社内サイトを
  「互換表示」で開くときと同じ）で、**レジストリには何も書きません**。「IE8 相当」「IE11 相当 (ページの指定に従う)」
  「IE11 強制」を選ぶと、`HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_BROWSER_EMULATION`
  に `RecBrowser.exe` という名前の値（8000 / 11000 / 11001）を書き込みます。これは現在のユーザーの、記録用ブラウザ
  （`RecBrowser.exe`）だけに効く設定で、Edge や IE モードの表示には影響しません。「既定」に戻すとその値は削除されます。
  選んだ表示モードは次の記録でも（かんたん画面から始めたときも）そのまま使われます。
- **使えないもの**: Edge IE モードの「エンタープライズ モード サイト リスト」（企業で配布する IE モードの設定）、
  そして **`https://` の記録**（素通し）。なお、Windows から段階的に削除されつつある VBScript を使うページは、
  IE モードと同じく記録用ブラウザでも動かなくなることがあります。`https://` のサイトや、エンタープライズ モードが
  ないと動かないサイトは、このツールでは記録できません。

### 1. 記録 — 記録用ブラウザで記録する

| 項目 | 説明 |
|---|---|
| 記録するサイト（ホスト名） | カンマ区切り。サブドメインも含めて記録。空欄ならすべてのサイト |
| 追加モード | 停止したとき、すでに読み込んである記録に**追加して結合**する |
| 最初に開くアドレス | 記録用ブラウザが最初に開くページ（`http://kanri/` など）。空欄なら空のページ |
| 表示モード（記録用ブラウザ） | 変更しない (今の設定のまま) / 既定 (IE7 互換表示、レジストリに書き込まない) / IE8 相当 / IE11 相当 (ページの指定に従う) / IE11 強制（[記録用ブラウザ（IE エンジン）](#記録用ブラウザie-エンジン)の「表示モード」） |

[記録開始] を押すと、空いているポートで記録用プロキシ（この PC の中だけで待ち受け、`https://` は素通し）が起動し、
続けて**記録用ブラウザ**が開きます。ポートやプロキシ、証明書の設定は要りません。右側の「記録の状態」には、
**記録したリクエスト件数がライブで**表示されるほか、プロキシのアドレス（`127.0.0.1:<ポート>`。記録用ブラウザが
自動で使います）、出力ファイル、記録用ブラウザの状態（起動中 / 閉じられました）、[プロキシのログを表示] があります。

記録用ブラウザでサイトを操作し終えたら [記録停止して読み込む]（ここから始めた記録は、記録用ブラウザを閉じても
自動では止まりません）。記録が `recordings/` に保存され、そのまま読み込まれて「3 ステップ」へ進めます。

mitmproxy が入っていないと、このパネルの上に `pip install "reqrec[record]"` を促す注意が出ます。記録用ブラウザが
使えない PC（Windows 以外の OS、`csc.exe` も作成済みの記録用ブラウザもない Windows）では「この PC では記録できません」
という注意とその理由が出て、[記録開始] は押せません。どちらの場合も、HAR の読み込み以降の機能はそのまま使えます。

### 2. 読み込み — HAR / 記録 JSON を読み込む

- **ファイルを選んで読み込む** — ドラッグ＆ドロップまたはクリックで `.har` / `.json` を選びます（「1 記録」で保存した
  記録のほか、IE11 の F12 開発者ツールで保存した HAR も読み込めます）。
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

GUI が動いている間も、記録用ブラウザや同じ PC のブラウザでは記録対象のサイトや他のサイト（= 任意の第三者のページ）を
開くことになります。そのページの JavaScript から GUI を操作されないように、GUI は **(1) 既定で `127.0.0.1` だけで待ち受け**（同じ PC からしか
届かない）、**(2) 状態を変える操作（記録開始・ファイル保存・実行など）には起動ごとに変わるランダムなトークン**
（`X-Reqrec-Token` ヘッダー）を要求し、他のページからの要求は 403 で拒否、**(3) `Host` ヘッダーが `127.0.0.1` /
`localhost` / 待ち受けアドレス以外の要求と、別オリジンからの `Origin` を拒否**（DNS リバインディング対策）、
**(4) ファイル名は作業フォルダの中だけ**を指す、という作りになっています。

パスワードを設定していないときは、GUI を動かしている PC 以外からの要求をすべて拒否します（`--host 0.0.0.0` で
起動しようとしても、パスワードがなければ起動しません）。他の PC から使うときは、次の「サーバーで自分専用に使う」の
とおりパスワードを設定します。

### サーバーで自分専用に使う（パスワードと `flask` コマンド）

社内 LAN のサーバー（JupyterLab のターミナルなど）で GUI を動かし、自分の PC のブラウザから開いて使えます。
環境変数 `REQREC_GUI_PASSWORD` にパスワードを設定して起動すると、最初にログイン画面が出て、パスワードを
入れた人だけが使えます。`reqrec.py` のあるフォルダで次のように起動します（`flask` コマンドは Flask と一緒に入ります）。

```console
$ export REQREC_GUI_PASSWORD='好きなパスワード'
$ export REQREC_WORKDIR=~/reqrec_work                     # 作業フォルダ（省略時はカレントの reqrec_work）
$ flask --app reqrec run --host 0.0.0.0 --port 8765
```

`reqrec gui --host 0.0.0.0 --port 8765 --no-browser` でも同じように動きます。自分の PC のブラウザで
`http://<サーバーの IP アドレス>:8765/` を開き、パスワードを入れると GUI が表示されます。

- ログインは 12 時間有効です。サーバーを起動し直すとログアウトされます。画面右上の [ログアウト] でも終われます。
- パスワードを 5 回続けて間違えると、その PC からは 60 秒間ログインできなくなります。
- パスワードは生成したスクリプト用の `REQREC_PASSWORD` とは別の名前です。[試しに実行する] で動かすスクリプトには
  渡しません。
- 画面は `http://` なので、パスワードや記録の中身は暗号化されずに社内 LAN を流れます。Windows のログオンと同じ
  パスワードは使わないでください。
- 記録用ブラウザは GUI を動かしているサーバー側で開こうとするため、他の PC からは記録できません。IE11 の F12
  開発者ツールで保存した HAR（[記録方法](#記録方法記録用ブラウザと-har)）を「2 読み込み」で読み込んで使います。
- スクリプトはサーバーで実行されるので、社内サイトから見た接続元はサーバーになります。統合 Windows 認証の
  サイトは、サーバーのアカウントで認証されるため、そのままでは動かないことがあります。
- 起動時に Flask が「This is a development server.」と表示しますが、自分専用で使う分には問題ありません。
- サーバーの Python は 3.12 以上が必要です（`requirements.txt` の mitmproxy 12.2.3 の条件）。

## Edge IE モードの社内サイト（認証・文字コード・WebForms）

Edge の IE モードのタブは、Edge（Chromium）ではなく **Internet Explorer 11 のエンジン**で描画・通信しています。
reqrec の[記録用ブラウザ](#記録用ブラウザie-エンジン)は同じエンジンを使うので、IE モードで使っている `http://` の
社内サイトをそのまま開いて記録できます（Edge の DevTools は IE モードのタブには使えないので、HAR を使うなら
[IE11 の F12 開発者ツール](#保存済みの-har-を使うie11-の-f12-開発者ツール)で保存します）。
この節では、そうした社内サイトによくある仕組みを reqrec がどう扱うかを説明します。

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
（[同梱のサンプルで試す](#同梱のサンプルで試す)）。

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
- `--dump-plan plan.json` で解析結果（Plan）を JSON として保存できます（デバッグや差分確認に）。秘密情報として環境変数に置き換えた定数の値は、この JSON にも書き出されません。
- `--run` を付けると、生成直後に同じ Python インタプリタで実行し、その終了コードを返します。

### 3. 生成したスクリプトを実行する

```console
# Linux / macOS
$ REQREC_PASSWORD='本物のパスワード' python scrape.py

# Windows (PowerShell)
PS> $env:REQREC_PASSWORD='本物のパスワード'; python scrape.py

# Windows (cmd)
> set "REQREC_PASSWORD=本物のパスワード" && python scrape.py
（cmd では `set X=値 && …` と書くと値の末尾に空白が入り、ログインに失敗します。上のように引用符で囲んでください）
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

## 同梱のサンプルで試す

`tests/fixtures/` には、実際のブラウザが出力する形に合わせて手書きした HAR が入っています。サイトに一切アクセスせずに、
GUI（「2 読み込み」でファイルを選ぶ）でも CLI でも同じファイルで reqrec の動きを確認できます。
reqrec の本来の対象に近いのは 3 つめの `legacy_webforms_ntlm.har` です。最初の 2 つは、解析（トークンの追跡・ループ・
ノイズ除去）とコード生成の動きを見るための一般的な Web サイト風のサンプルです。

| ファイル | 内容 |
|---|---|
| `tests/fixtures/login_flow_chrome.har` | Chrome 風。ログインページ → CSRF トークン付き POST → リダイレクト → Bearer トークン付き JSON API → ページ送り（page=1..3）→ CSV ダウンロード。静的ファイル・トラッカー・CORS preflight などのノイズ入り |
| `tests/fixtures/api_firefox.har` | Firefox 風。JSON でログインしてアクセストークンを受け取り、API を呼ぶ SPA |
| `tests/fixtures/legacy_webforms_ntlm.har` | **Edge IE モード風**の社内サイト（`http://intra.example.local/`）。統合 Windows 認証（NTLM の 401 → 401 → 200）、charset なしの Shift_JIS な ASP.NET WebForms ページ（`__VIEWSTATE` / `__EVENTVALIDATION`）、Shift_JIS で URL エンコードされた検索 POST、`Report.aspx?id=1234`、CSV エクスポート、捨てられる `WebResource.axd` |

**`login_flow_chrome.har`** — `reqrec inspect` の結果は[「使い方」の例](#使い方-inspect--generate--実行)と同じです
（フロー 14 件 → ステップ 5 件 / 除外 6 件）。GUI の「3 ステップ」の表では、`/static/logo.png`・`ads.tracker.example.test`・
`OPTIONS` の行が灰色（除外）になり、`/login` → `/dashboard` のリダイレクトは同じステップ番号 2 にまとまります。
`https://api.example.test/v1/me` の行の「採用」を外すとステップが 4 件になり、`/v1/orgs/77/items?page=1` の行の「結果」を
選ぶと、生成コードが最後に表示するものがその一覧 JSON（ループなので 3 ページ分）に変わります。CLI では次のとおりです。

```console
$ reqrec inspect  tests/fixtures/login_flow_chrome.har --exclude-step 3       # /v1/me を外す（"excluded by user"）
$ reqrec inspect  tests/fixtures/login_flow_chrome.har --include-flow f0002   # 除外された静的ファイル 1 件を採用する
$ reqrec generate tests/fixtures/login_flow_chrome.har -o scrape_example.py --final-step 4   # 一覧 JSON を結果にする
```

**`legacy_webforms_ntlm.har`** — `reqrec inspect` と `reqrec generate … -o legacy_example.py` で確かめられること:

- `Default.aspx` への 3 回の `GET`（401, 401, 200）が 1 ステップ（FLOW `f0001+f0002+f0003`、STATUS `401→401→200`）に
  まとまり、`認証: NTLM (記録時のユーザー: EXAMPLE\taro) → 生成コードは session.auth を設定します…` と表示される。
  ステップのヘッダに `Authorization` は残らない。
- ステップは 4 件（`GET Default.aspx` → 検索の `POST Default.aspx` → `GET Report.aspx?id=1234` → CSV エクスポート）。
  `__VIEWSTATE` / `__VIEWSTATEGENERATOR` / `__EVENTVALIDATION` は直前のページの `html_input` から、`Report.aspx` の `id` は
  検索結果の `<a href>` から抽出される。`WebResource.axd`（JavaScript）は静的ファイルとして除外される。
- Shift_JIS で URL エンコードされた検索語（`ctl00$txtKeyword=%93%FA%96%7B`）は警告が出て、生成コードでは
  `b'\x93\xfa\x96{'  # cp932 で「日本」` のようにバイト列のまま残る。
- 生成コードの `main()` 冒頭に `requests_negotiate_sspi` / `requests_ntlm` を使う `session.auth` の設定が入る。

サンプルのホスト（`shop.example.test` / `api.example.test` / `intra.example.local`）は架空なので、生成したスクリプトを
実行しても接続エラー（`ConnectionError`）で終わります（GUI の「5 実行」では「エラー終了」になります）。生成コードを
手で直すときの参考には、`login_flow_chrome.har` から生成されるものと同じ構成で**手書き**した
[`tests/fixtures/example_scrape.py`](tests/fixtures/example_scrape.py) があります（コメントや細部の文言は実際の出力と
異なります。読み方は次の「生成コードの読み方」）。

## 生成コードの読み方

生成されるスクリプトの構成はいつも同じです（下は[同梱サンプル](#同梱のサンプルで試す)から生成したものを短くした**例**。
同じ構成で手書きした完全版は [`tests/fixtures/example_scrape.py`](tests/fixtures/example_scrape.py)）。

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
    # （統合 Windows 認証のサイトならここに session.auth = ... が入る）
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
| 定数（`PASSWORD` など） | 複数のステップで同じ値が使われていたり、秘密情報らしい名前のものはモジュール先頭に集約。秘密情報は `os.environ.get("REQREC_…")`。Basic / Digest 認証なら `AUTH_USERNAME` / `AUTH_PASSWORD` |
| `BASE_HEADERS` | すべてのリクエストで同じだったヘッダ（User-Agent, Accept-Language など）。`Session` に設定される |
| `INITIAL_COOKIES` | 記録開始前からブラウザにあった Cookie。期限切れになったら記録し直す |
| ヘルパー `_soup` `_text` `_check` `_regex` `_json_path` `_attr` … | 抽出コードを短く、失敗時のエラーを分かりやすくするための小さな関数。使われるものだけが出力される。`_soup` はバイト列を渡して文字コードを自動判定、`_text(resp)` は本文を正しい文字コードで文字列にする |
| `step_NN_<method>_<path>(session, …)` | 1 ステップ = 1 関数。`(resp, 抽出した値の dict)` を返す。引数は前のステップから受け取る値 |
| `main()` | 必要な秘密情報がそろっているか確かめ、`Session` を作り（必要なら `session.auth` を設定し）、ステップを順に呼び、`ctx` に抽出値をためて次に渡す。ループは `for` で呼ぶ。「結果にするステップ」のレスポンスを `final_resp` に取って最後に表示する |

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
| **JavaScript で計算される署名・HMAC・暗号化**（リクエストごとに JS がパラメータに署名する、パスワードを JS でハッシュしてから送る、など） | 値が `looks dynamic` 警告付きのリテラルで出る。2 回目以降に 401/403 | 計算している JS を探し（GUI の「3 ステップ」で「除外された行も表示」にして `.js` の行を開く、または IE11 の F12 開発者ツールの「デバッガー」）、同じ計算を Python で書く。鍵が JS に埋め込まれていれば再現できることが多い |
| **CAPTCHA**（reCAPTCHA, hCaptcha, 画像認証） | トークンパラメータ（`g-recaptcha-response` 等）がリテラルで出る | 自動化はできません。CAPTCHA のないフロー・API を探すか、人が解いた値を渡す設計にする |
| **ボット対策**（Cloudflare, Akamai, Imperva, PerimeterX など） | 403 / 429 / チャレンジページ（HTML）が返る。`cf_clearance` などの Cookie がリテラルで出る | 記録直後は `INITIAL_COOKIES` の Cookie で一時的に通ることがあるが、期限切れで止まる。根本的には回避対象ではありません。公式 API や許可された手段を使う |
| **TLS / HTTP2 フィンガープリント** | `requests` だけが 403 になり、ブラウザは通る | ヘッダを完全に合わせても通らない場合は、クライアントの指紋で判定されています。同様に、回避対象ではありません |
| **WebSocket / Server-Sent Events** | `inspect` で `websocket` / `server-sent events stream` として除外される | WebSocket は `websockets` ライブラリなどで別途実装する |
| **動的に変わる URL**（レスポンスから取れない ID が URL に入る、日付でパスが変わる） | URL がリテラルで固定される | URL の一部を変数にして `main()` で生成する。日付なら `time.strftime` |
| **記録に入っていない前提条件**（ログイン済みの Cookie、別タブで取得したトークン） | `INITIAL_COOKIES` に Cookie が出る。警告 `existed before the recording started` | ログインを含めて最初から記録し直す（推奨）。別タブなら[そのタブも記録して結合](#別タブで開く画面を記録する)する。または `INITIAL_COOKIES` を都度更新する |
| **レスポンス本文がない HAR**（IE11 の F12 で保存したものなど） | 抽出がまったく検出されない | 記録用ブラウザで記録し直す（[FAQ](#トラブルシューティング-faq)） |
| **Kerberos 限定（NTLM を受け付けない）サーバー** | 生成コードが Windows 以外で 401 | Windows で `reqrec[sspi]` を使う（ドメイン参加 PC のログオン情報で Kerberos も通る） |

いずれの場合も、生成コードは**読みやすい出発点**として使えます。該当ステップの関数の中身を直すだけで、
他のステップはそのまま動きます。`--keep-static` / `--keep-all` / `--include-host` で解析対象を広げると、
`.js` ファイル内の定数など追加の手がかりが残ることがあります。

## オプション一覧

コマンドは `import` / `inspect` / `generate` / `gui` / `browser build|status` の 5 つです（`reqrec -h`、
`reqrec <コマンド> -h` で日本語のヘルプが出ます）。記録は `reqrec gui` の記録用ブラウザで行い、記録だけをする
コマンドはありません。

### 入力ファイル（`import` / `inspect` / `generate` 共通）

`INPUT` には `.har` / `.json`（HAR または reqrec の記録）を **1 つ以上**指定できます。それ以外の拡張子はエラーになります。
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
| `--dump-plan FILE` | 解析結果（Plan）を JSON で書き出す（秘密情報の定数の値は含まれない） | なし |
| `--run` | 生成後すぐ同じ Python で実行し、その終了コードを返す（環境変数は引き継がれる） | オフ |

### `gui`

| オプション | 意味 | 既定 |
|---|---|---|
| `--host HOST` | 待ち受けアドレス（他の PC から使わせるなら `0.0.0.0`。環境変数 `REQREC_GUI_PASSWORD` のパスワードが必要で、他の PC からは記録できません。[サーバーで自分専用に使う](#サーバーで自分専用に使うパスワードと-flask-コマンド)を参照） | 127.0.0.1 |
| `--port PORT` | 待ち受けポート | 8765 |
| `--workdir DIR` | 作業フォルダ（`recordings/` `uploads/` `scripts/` `outputs/` が作られる） | `./reqrec_work` |
| `--no-browser` | ブラウザを自動で開かない | 開く |

### `browser`

記録用ブラウザ（`RecBrowser.exe`、Windows）を `reqrec.py` と同じフォルダ（配布フォルダ）に事前に作成します
（[Windows での配布と exe 化](#windows-での配布と-exe-化)を参照）。

| コマンド | 意味 |
|---|---|
| `reqrec browser build` | 記録用ブラウザ（32 ビット版）と `RecBrowser.exe.sha256` を `reqrec.py` と同じフォルダに作成する（csc.exe が必要） |
| `reqrec browser status` | このバージョン用の記録用ブラウザが作成済みか表示する |

### 終了コード

`0` 正常終了 / `1` 実行時エラー（ファイルがない、形式が未対応、GUI のポートが使用中、記録用ブラウザを作成できないなど。`エラー: …` を表示）/
`2` 引数の誤り。`--run` のときはスクリプトの終了コードがそのまま返ります。`reqrec gui` は `Ctrl+C` で `0` を返します。

## Windows での配布と exe 化

配るものは **`reqrec.py` 1 ファイル**だけです（GUI の画面と記録用ブラウザのソースもこの中に入っています）。
必要なライブラリ（`requests` / `beautifulsoup4` / `flask`、記録には `mitmproxy`）を入れた Python で動かします。
置き方は次の 2 通りです。

**ポータブル Python のフォルダに置く（pip install 不要）**

フォルダごとコピーして使う Python（ポータブル Python。python.org のインストーラで入れた Python 3.12 以上の
フォルダをコピーしたものなど）を、各 PC や共有フォルダに配る場合です。

1. ポータブル Python に必要なライブラリを入れます（インターネットにつながる PC で一度だけ。`python.exe` のある
   フォルダで実行します）。入れるライブラリと動作確認したバージョンは reqrec のフォルダの `requirements.txt` に
   まとめてあります。`-r` のあとは、その `requirements.txt` の場所に合わせて書き換えてください。
   ```bat
   .\python.exe -m pip install -r C:\work\reqrec\requirements.txt
   ```
   統合 Windows 認証のサイトを再現するスクリプトもこの Python で動かすなら、`requirements.txt` の
   `requests-negotiate-sspi` の行頭の `# ` を消してから実行します。インターネットにつながらない PC に入れる手順も
   `requirements.txt` の先頭に書いてあります。`requirements.txt` は入れるときに使うだけで、各 PC に配る必要はありません。
2. `reqrec.py` を **`python.exe` と同じフォルダ**に置きます。このフォルダは Python がモジュールを探す場所に
   入っているので、どのフォルダからでも次のように起動できます（`reqrec` コマンドは作られないので、ほかのコマンドも
   `python.exe -m reqrec inspect rec.har` のように書きます）。
   ```bat
   C:\tools\python\python.exe -m reqrec gui
   ```
   デスクトップにショートカットを作り、リンク先をこのコマンドにしておくと、ダブルクリックで GUI が起動します。
3. 記録用ブラウザを事前に作成する（下の「記録用ブラウザの事前ビルド」）なら、`python.exe -m reqrec browser build`
   を実行します。`RecBrowser.exe` は `reqrec.py` と同じこのフォルダにできます。
4. 利用者がこのフォルダに書き込めない場合（共有フォルダや `C:\Program Files` の下に置くときなど）は、`reqrec.py` を
   置いたあとに `python.exe` のあるフォルダで一度だけ次を実行します。`reqrec.py` を Python が読み込める形に変換した
   ファイルが `__pycache__` フォルダにでき、起動と記録の開始がそれぞれ約 0.5 秒速くなります（書き込めるフォルダなら、
   初回の起動で自動的にできるので不要です）。
   ```bat
   .\python.exe -m compileall reqrec.py
   ```

reqrec を更新するときは `reqrec.py` を置き換え、記録用ブラウザを作成していたら `browser build` も、
手順 4 を行っていたら `compileall` もやり直します。

**pip でインストールする**

1. [python.org](https://www.python.org/downloads/windows/) のインストーラで Python 3.10 以上を入れる
   （「Add python.exe to PATH」にチェック）。
2. reqrec のフォルダ（`reqrec.py`・`pyproject.toml`・`README.md` があるフォルダ）または wheel ファイルをコピーし、
   コマンド プロンプトで
   ```bat
   cd reqrec
   pip install ".[record]"
   reqrec gui
   ```
   社内配布なら `pip wheel . -w dist` で作った `dist\reqrec-0.1.0-py3-none-any.whl` を配り、
   `pip install reqrec-0.1.0-py3-none-any.whl mitmproxy` としてもらう方法もあります。
3. 統合 Windows 認証のサイトを再現するスクリプトを動かす PC には `pip install "reqrec[sspi]"` も入れます。

`reqrec.py` は Python の `site-packages` フォルダに入ります（`pip install -e .` のときは元のフォルダのまま）。
wheel（`pip install .` も中で wheel を作ります）には記録用ブラウザ（exe）を入れられないので、事前に作成するなら、
インストールした PC で `reqrec browser build` を実行します。

**記録用ブラウザの事前ビルド（IT 担当向け・推奨）**

記録用ブラウザ（`RecBrowser.exe`）は、何もしなければ各 PC の作業フォルダ（ユーザーのフォルダの下）で初回に
コンパイルされます。工場の PC では、ユーザーのフォルダにある実行ファイルの起動がセキュリティ設定（AppLocker
など）で禁止されていることがあるため、配布フォルダを作るときに一度だけ次を実行してください
（`reqrec` コマンドがないとき — ポータブル Python や、PATH にないとき — は `python -m reqrec browser build`）。

```bat
reqrec browser build
```

`reqrec.py` と同じフォルダ（ポータブル Python なら `python.exe` のフォルダ、pip でインストールしたなら `site-packages`。
作成した場所は実行結果に表示されます）に `RecBrowser.exe` と `RecBrowser.exe.sha256` ができ、各 PC はそれを
その場所から直接起動します（ユーザーのフォルダには何も作りません）。セキュリティ設定では、この配布フォルダの
実行だけを許可すれば足ります。reqrec を更新したら同じコマンドで作り直してください（古いままだと、各 PC の
作業フォルダでのコンパイルに戻ります）。`reqrec browser status`（`python -m reqrec browser status`）で
作成済みか確認できます。
記録用ブラウザは常に 32 ビット版で作られます（IE モードと同じく、古い社内サイトの 32 ビット ActiveX 部品を読み込めるように）。

**exe 化（PyInstaller）— 未検証**

Python を入れられない PC に配りたい場合は PyInstaller で単一の exe にする方法が考えられます。
次のコマンドは**設計上の例であり、動作は検証していません**。mitmproxy は依存パッケージが多く、
hidden import の追加や exe サイズ（数百 MB）、ウイルス対策ソフトによる誤検知への対応が必要になる見込みです。

```bat
pip install pyinstaller
pyinstaller --onefile --name reqrec --collect-all mitmproxy reqrec.py
```

（`reqrec.py` はそのままスクリプトとして実行でき、GUI の画面と記録用ブラウザのソースも埋め込まれているので、
追加のデータファイルはありません。）出来上がった `reqrec.exe gui` で GUI が起動するか、記録（mitmproxy の起動）が
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
  記録用ブラウザを**閉じてから**記録をやり直す、または GUI の「HTTP 認証 … を検出して統合する」がオンか確認してください。
- サーバーが Kerberos しか受け付けない場合、`requests_ntlm` では通りません。Windows で `reqrec[sspi]` を使ってください。

**Q. 1 回目は動いたのに、2 回目（または翌日）に失敗する。**

ほぼ確実に、**抽出できていないトークン**がリテラルのまま埋め込まれています。

- `reqrec inspect` の警告 `looks dynamic` が出ているパラメータを見る。
- 失敗するステップの関数で、ランダムに見える文字列（`'a8f3…'`）を探す。
- その値がどこから来たかを、GUI の「3 ステップ」で行をクリックして開く詳細ドロワーで調べる
  （その値を送っているリクエストより前のレスポンスの本文に、同じ値が入っていないかを見ます）。
  レスポンスにあれば `_regex` / `_attr` で抽出コードを書く。JS が計算しているなら Python で同じ計算を書く。
- `INITIAL_COOKIES` のセッション Cookie が期限切れになっている場合もあります（ログインを含めて記録し直す）。

**Q. `inspect` の「抽出する変数」が全部 `-` で、警告も出ない。HAR にレスポンス本文が入っていない？**

- IE11 の F12 開発者ツールで保存した HAR は、レスポンス本文が欠けることがあります。本文がないと、トークンの出どころを
  探せません。記録用ブラウザで記録し直してください（記録用ブラウザの記録には本文が入ります）。
- HAR の `entries[].response.content.text` が空なら本文なしです。

**Q. 必要な API リクエストが「除外」されてしまう。**

`.json` / `.js` / `.php` のような拡張子や `application/octet-stream` の判定に引っかかることがあります。
GUI ならその行の「採用」にチェックを付けるだけです。CLI では `--include-flow f0012`（1 件だけ戻す）、
`--keep-static`（静的ファイル判定を無効化）、`--include-host api.example.com` で調整してください。
`--keep-all` ですべてを残し、`--exclude-host` / `--exclude-flow` で不要なものを外す方法もあります。

**Q. 関係のないサイトの通信が混ざって、ステップが多すぎる。**

記録されるのは記録用ブラウザで開いたページの通信だけですが、ページが別のサーバー（ポータルの部品、解析サービスなど）
を読み込んでいると、それも記録に入ります。`--include-host example.com`（サブドメインも含む）で対象サイトに絞るか、
`--exclude-host` で外します。1 件ずつなら GUI のチェックを外す、または `--exclude-step N` / `--exclude-flow ID`。
記録の時点で絞るなら、詳細設定の「1 記録」の「記録するサイト（ホスト名）」に対象のホスト名を入れて記録します。

**Q. 新しいタブで開いた画面が記録に入っていない。**

記録用ブラウザで記録した場合は、`window.open` や `target="_blank"` で開いた画面もタブとして記録されます。
件数が増えないときは、その画面が `https://` でないか（`https://` は記録されません）を確認してください。
IE11 の F12 開発者ツールの HAR はタブ単位なので、新しいタブの通信は入りません
（[別タブで開く画面を記録する](#別タブで開く画面を記録する)。タブごとに保存して複数ファイルを指定するか、
記録用ブラウザで記録し直してください）。

**Q. ページ送りが 2 ページしかなく、ループにならない。**

ループ検出は 3 回以上の連続が条件です。`main()` で手で `for` に書き換えるか、3 ページ以上めくって記録してください。

**Q. `https://` のページが記録されない。**

仕様です。記録用ブラウザは証明書を登録しないので、`https://` のページは記録せずにそのまま通します（画面は普通に
表示されます）。reqrec が対象とするのは `http://` の社内サイトです。

**Q. 生成したスクリプトが `SSLError`（`CERTIFICATE_VERIFY_FAILED` など）になる（実行時）。**

`https://` のサイトに接続しようとしています（記録用ブラウザは `https://` を記録しないので、`https://` の URL を含む
HAR から作ったスクリプトで起こります）。`https://` のサイトはこのツールの対象外です。GUI の [試しに実行する] でも
同じ内容の案内が出ます。

**Q. 日本語が化ける（`�` や `ãƒ` のような文字になる）。**

生成コードは `Content-Type` の charset → `<meta charset>` → 推定の順で文字コードを判定し、Shift_JIS 系は `cp932` で
扱うので、通常は化けません。それでも化ける場合は、(1) 記録ファイルの段階で化けていないか GUI の詳細ドロワーで
レスポンス本文を確認し（IE11 の HAR は本文の文字コード情報が落ちることがあります → 記録用ブラウザで記録し直す）、
(2) 生成コードの該当ステップで `resp.encoding = "cp932"`（または `"euc_jp"`）を `_text(resp)` / `_soup(resp)` の前に
明示してください。Windows のコンソール自体の文字コードが原因のこともあります（`chcp 65001`、または結果をファイルに保存して確認）。

**Q. `reqrec gui` を実行しても GUI が開かない。**

- `GUI を起動できません: ポート 8765 は既に使われています` → 別の `reqrec gui` が動いているか、他のソフトが使っています。
  `reqrec gui --port 8766` のように別のポートを指定します。
- サーバーは起動した（`GUI を起動しました: http://127.0.0.1:8765`）がブラウザが開かない → その URL を手でブラウザに
  貼ってください。既定ブラウザの設定によっては自動で開けないことがあります（`--no-browser` で自動起動を切れます）。
- 「この Host ヘッダーからのアクセスは許可されていません」→ `http://127.0.0.1:8765` か `http://localhost:8765` で
  開いてください（PC 名や別の IP では開けません）。他の PC から使うときは、パスワードを設定して `--host 0.0.0.0` で
  起動し、`http://<IP アドレス>:8765` で開きます（[サーバーで自分専用に使う](#サーバーで自分専用に使うパスワードと-flask-コマンド)）。
- 「パスワードが設定されていないため、この PC 以外からは使えません」→ 他の PC から開いています。環境変数
  `REQREC_GUI_PASSWORD` にパスワードを設定して起動し直してください。
- 「GUI を起動できません: --host 0.0.0.0 で他の PC から使えるようにするときは、パスワードが必要です」→ 同じく
  `REQREC_GUI_PASSWORD` を設定してから起動します。
- ログイン画面で「パスワードを続けて間違えたため…ログインできません」→ 60 秒待ってから入れ直してください。
- 「認証トークンが一致しません」→ 古いタブが残っています。ページを再読み込みしてください。

**Q. かんたん画面に「記録用ブラウザ (IE エンジン): 準備できていません」と出る / 記録用ブラウザが開かない。**

- 「記録用ブラウザ (IE エンジン) は Windows でのみ使えます。」→ Windows 以外の OS では記録できません
  （HAR の読み込み以降の機能は使えます）。
- 「コンパイラ (csc.exe) が見つかりません」→ Windows 標準の .NET Framework 4.x（`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe`）
  がない PC です。管理者に「.NET Framework 4.8 の機能を有効にしてほしい」と伝えるか、別の PC で
  `reqrec browser build` を実行してできた `RecBrowser.exe` と `RecBrowser.exe.sha256` を、この PC の
  `reqrec.py` と同じフォルダに置くと、コンパイルせずに使えます。
  それまでは、この PC では記録できません（HAR の読み込み以降は使えます）。
- 「記録用ブラウザの作成 (コンパイル) に失敗しました」→ メッセージにコンパイラの出力が続きます。古い記録用ブラウザが
  開いたままだと上書きできないので、閉じてからもう一度 [記録をはじめる] を押してください。
- 「記録用ブラウザを起動できませんでした」→ パソコンのセキュリティ設定（AppLocker など）で、作業フォルダの
  `RecBrowser.exe` の実行が止められている可能性があります。IT 担当が `reqrec browser build` で配布フォルダに
  記録用ブラウザを作成し、そのフォルダの実行を許可してください（[Windows での配布と exe 化](#windows-での配布と-exe-化)の
  「記録用ブラウザの事前ビルド」）。
- 記録用ブラウザは開いたが件数が増えない → `https://` のページは記録されません（`http://` のページだけ）。
  アドレス欄に `http://` で始まるアドレスを入れて開いてください。
- 記録用ブラウザのログは作業フォルダの `logs\recbrowser_<日時>.log` にあります（先頭の `proxy 127.0.0.1:<ポート> -> ok`
  でプロキシ設定が効いたことが分かります）。

**Q. GUI に「mitmproxy が見つかりません」/ かんたん画面に「記録機能: 準備できていません (mitmproxy が未インストール)」と出る。**

記録用プロキシに使う mitmproxy が入っていません。`pip install "reqrec[record]"`（または `pip install mitmproxy`。
ポータブル Python なら `requirements.txt` で入れます。[Windows での配布と exe 化](#windows-での配布と-exe-化)）を実行し、
GUI を再起動してください。HAR だけを使う場合は不要です。

## 開発者向け

```console
$ pip install -e ".[dev]"
```

リポジトリにあるのは `reqrec.py`（アプリ本体）、`pyproject.toml`、`requirements.txt`（ポータブル Python に入れる
ライブラリの一覧）、`README.md`、`DESIGN.md`、`.gitignore` と `tests/` だけです。

### `reqrec.py` の構成（アプリ本体は 1 ファイル）

アプリ本体は **`reqrec.py` 1 ファイルだけ**です（GUI の画面 `GUI_HTML` と、記録用ブラウザの C# ソース
`RECBROWSER_CS` も文字列としてこの中に入っています）。ほかにできるのは、実行時の `__pycache__` と、
`reqrec browser build` で作る `RecBrowser.exe` / `RecBrowser.exe.sha256`（`reqrec.py` の隣）だけで、どちらも git には入れません。

- `reqrec ...` / `python -m reqrec ...` / `python reqrec.py ...` … コマンド（`import` / `inspect` / `generate` / `gui` / `browser build|status`）
- `mitmdump -s reqrec.py` … 記録用プロキシは**このファイル自体**をアドオンとして読み込みます（GUI が起動）
- `import reqrec` … ライブラリとして使う（`load_recording` / `build_plan` / `generate` / `create_app` など）

中は元のモジュールごとの区切り（見出し `# ===== former reqrec/xxx.py: … =====`。エディタでこの見出しを検索すると
目的の部分に移動できます）が、次の順に並んでいます。

| 区切り（見出し） | 中身 |
|---|---|
| 先頭（最初の見出しより前） | docstring、import、`__version__`、公開する名前の一覧 `__all__`（区切りごと）、`mitmdump -s` で読み込まれたとき用の `_register_script_module()` |
| `core`（`former reqrec/core.py`） | データ型（`Recording` / `Flow` / `Plan` / `PlanOptions` など）と共通ヘルパー。すべての基盤 |
| `importers`（`former reqrec/importers.py`） | HAR・記録 JSON → `Recording`。`load_recordings` で複数ファイルを時刻順に結合。記録用アドオンが使う mitmproxy のフロー → `Flow` の変換（`flow_from_mitm`） |
| `analysis`（`former reqrec/analysis.py`） | 解析: ノイズ除去・手動の採用/除外・認証ハンドシェイク統合・リダイレクト統合・Cookie 分類 → 依存関係検出 → ループ検出 → `Plan` の構築（`build_plan`、「結果にするステップ」） |
| `codegen`（`former reqrec/codegen.py`） | `Plan` → Python スクリプト（`session.auth` / 文字コード / ダウンロードの保存） |
| `recorder`（`former reqrec/recorder.py`） | 記録用プロキシ: mitmproxy アドオン（`addons`）、`mitmdump` のコマンドライン（`build_command`。待ち受けは `127.0.0.1` だけ）、GUI 用の子プロセス管理（`RecorderManager`） |
| `iehost`（`former reqrec/iehost.py`） | 記録用ブラウザのビルド・起動・表示モード（名前空間 `iehost`: `iehost.launch(...)` など） |
| `RECBROWSER_CS`（`former reqrec/RecBrowser.cs`） | 記録用ブラウザ本体の C# ソース（文字列。コンパイルするときだけ作業フォルダの `bin\RecBrowser.cs` に書き出す） |
| `gui`（`former reqrec/gui.py`） | GUI（Flask）: `create_app` / `run_gui`、JSON API、プロセス内の状態、記録用ブラウザの最初のアドレスの確認（`validate_url`）とフォルダを開く処理（`open_folder`） |
| `GUI_HTML`（`former reqrec/gui.html`） | GUI の画面。CSS と JavaScript を埋め込んだ Jinja テンプレートの文字列（外部 CDN を使わないのでオフラインで動く） |
| `cli`（`former reqrec/cli.py`） | `reqrec` コマンド（argparse。`import` / `inspect` / `generate` / `gui` / `browser`） |
| 最後（`entry point: main()`） | `main()` と、`python -m reqrec` / `python reqrec.py` で動かすときの `if __name__ == "__main__":` |

- 1 つのファイルなので、どの名前も 1 回しか定義されていません。元のモジュール同士で名前がぶつかったものは
  区切りの名前を付けて区別しています（例: CLI 用の `cli_normalise_flow_id`、GUI 用の `_gui_to_int`）。一覧は
  [`DESIGN.md`](DESIGN.md) 先頭の「Module layout」にあります。
- **各部分の契約と設計の経緯は [`DESIGN.md`](DESIGN.md)** にまとまっています（§1〜§12 が v0.1 の CLI パイプライン、
  **§13 が GUI / IE モード / 複数記録の結合**）。DESIGN.md の経緯の部分は統合前のモジュール名（`filters.py`、
  `webapp/routes.py` など）で書かれていて、先頭の「Module layout」の表で今の区切りとの対応が分かります。
- 生成コードに記録由来の文字列を埋め込むときは**必ず `repr()` / `json.dumps()`** を通します
  （記録内容は攻撃者が制御し得る入力なので、文字列連結でソースに混ぜてはいけません）。GUI も同じ理由で、記録内容は
  `textContent` でのみ描画します。

### 埋め込みの HTML / C# を直す（`GUI_HTML` / `RECBROWSER_CS`）

GUI の画面と記録用ブラウザの C# ソースは、別のファイルではなく `reqrec.py` の中の文字列です。`reqrec.py` で
`GUI_HTML = r'''` または `RECBROWSER_CS = r'''` を検索し、次の `'''` までをそのまま書き換えます。

- どちらも raw 文字列（`r'''…'''`）なので、元のファイルと同じ書き方のままで構いません（`\n` や `\\` は書いたとおりに
  HTML / C# に渡ります）。書いてはいけないのは `'''`（シングルクォート 3 つ。そこで文字列が終わってしまいます）と、
  最後の `'''` の直前の `\` だけです。
- **`GUI_HTML`** は Jinja テンプレートです。CSS と JavaScript は `{% raw %}` 〜 `{% endraw %}` の中にあるので、
  `{{ }}` を気にせずに書けます（サーバーから値を渡すのは raw の外にある `{{ token }}` などだけです）。変更は
  `reqrec gui` を起動し直してからページを再読み込みすると反映されます。
- **`RECBROWSER_CS`** は C# 5 で書きます（Windows 標準の .NET Framework 4.x の `csc.exe` でコンパイルするため）。
  `reqrec gui` を起動し直すと、次に記録用ブラウザを開いたときにソースの変更を検出して、作業フォルダの
  `bin\RecBrowser.exe` を自動で作り直します（コンパイルに失敗したときはコンパイラの出力が画面に表示されます）。
  `reqrec browser build` で作成した exe はソースと合わなくなって使われなくなるので、作り直してください。
- 直したら次のテストで確かめます。

  ```console
  $ python -m pytest tests/test_gui.py tests/test_gui_browser.py   # GUI_HTML（後者は Chromium が必要。REQREC_CHROMIUM で指定可）
  $ python -m pytest tests/test_iehost.py                          # 記録用ブラウザのビルド・起動のロジック
  > set REQREC_IEHOST_TESTS=1
  > python -m pytest tests/test_real_engine.py                     # Windows: RECBROWSER_CS を実際にコンパイルして動かす
  ```

### テスト

```console
$ python -m playwright install chromium   # GUI のブラウザテスト用（任意。無ければそのテストはスキップされる）
$ python -m pytest                        # tests/ にまとめたテストをすべて実行
$ python -m pytest -k "<キーワード>"       # テスト名で絞り込んで実行
```

テストは `tests/` にまとめてあります。`reqrec.py` の区切り（元のモジュール）ごとの単体テストのほか、手書きの HAR（`tests/fixtures/`）を解析・生成して
偽サイトに対して実行する結合テスト、ローカル HTTP サーバーに対して「記録 → 生成 → 生成コードをサブプロセスで実行」まで
通すエンドツーエンドテスト、Flask のテストクライアントで全エンドポイントとトークン / Host / Origin / パストラバーサルの
拒否を確かめるテストがあります。環境によっては次のテストが自動でスキップされます。

- **本物の `mitmdump`** を使うテスト — mitmproxy が無いとき（GUI の記録機能で本物の `mitmdump` を起動し、記録用ブラウザの
  代わりにテスト側からローカルサイトへ通信して記録するテストは、Windows を含むどの OS でも動きます。`mitmdump` を直接
  Ctrl+C で止めるテストだけは Windows でスキップされます）。
- **Playwright で実際に GUI を操作する**テスト — Chromium が無いとき。ブラウザの場所は環境変数 `REQREC_CHROMIUM` で
  指定できます（Windows なら Edge の `msedge.exe` でも動きます）。
- **本物の記録用ブラウザ（IE エンジン）**を使うテスト — Windows で環境変数 `REQREC_IEHOST_TESTS=1` を設定したときだけ
  動きます（小さなブラウザの窓が短時間開きます）。

`tests/` のファイル（サブフォルダは HAR などのデータを置く `tests/fixtures/` だけ。複数をまとめたファイルは
`# ===== former tests/xxx.py` の見出しで元のファイルごとに区切ってあります）:

| ファイル | 中身 |
|---|---|
| `test_core.py` | 取り込み（HAR / 記録 JSON）と、記録用アドオンが使う `flow_from_mitm`、複数記録の結合 |
| `test_analysis.py` | 解析（ノイズ除去・依存関係・ループ・`Plan`・手動の採用/除外・認証ハンドシェイク） |
| `test_codegen.py` | コード生成（生成コードをモックの通信で実際に実行する） |
| `test_cli.py` / `test_recorder.py` / `test_iehost.py` | CLI / 記録用プロキシ（mitmproxy アドオン・`mitmdump` の起動）/ 記録用ブラウザのビルド・起動（偽物を注入したロジック） |
| `test_gui.py` | GUI の全エンドポイント・かんたんモード・記録用ブラウザまわりのエンドポイント |
| `test_gui_browser.py` | Playwright で GUI を実際に操作する |
| `test_integration.py` | 結合・エンドツーエンド（ローカル HTTP サーバーで記録 → 生成 → 実行） |
| `test_real_engine.py` | 本物の記録用ブラウザ・IE ドライバーを使うテスト（大半は `REQREC_IEHOST_TESTS=1` のときだけ） |
| `support.py` / `ie_support.py` / `IEDriver.cs` | テスト用の部品（モックの通信・ローカルサーバー・テストサイト・外部ドライバー） |

```console
$ python -m pytest --ignore=tests/test_gui_browser.py   # GUI をブラウザで操作するテストを除いて速く回す
> set REQREC_IEHOST_TESTS=1
> python -m pytest tests/test_real_engine.py            # Windows: 本物の記録用ブラウザのテストも動かす
```

## ライセンス

MIT
