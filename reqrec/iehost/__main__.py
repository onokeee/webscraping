"""``python -m reqrec.iehost build``: prebuild the recording browser into the reqrec folder.

For a distribution folder (portable Python + reqrec) prepared by IT: the exe is written next to
``RecBrowser.cs`` together with the hash of the source it came from, and every PC that uses the
folder then runs it in place — nothing is compiled or written under the user's profile, and an
application-control policy (AppLocker / SRP) only has to allow that one folder.  DESIGN.md §13.12.
"""

from __future__ import annotations

import sys

from . import IEHostError, build_shipped, shipped_exe


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args[:1] == ["build"]:
        try:
            exe = build_shipped()
        except IEHostError as exc:
            print(f"エラー: {exc}", file=sys.stderr)
            return 1
        # always 32-bit, so the 32-bit ActiveX controls of legacy intranet pages load (as in IE mode)
        print(f"記録用ブラウザを作成しました (32 ビット版): {exe}")
        return 0
    if args[:1] == ["status"]:
        exe = shipped_exe()
        print(f"配布フォルダの記録用ブラウザ: {exe}" if exe else "配布フォルダの記録用ブラウザ: なし（各 PC の作業フォルダで初回にコンパイルします）")
        return 0
    print("使い方: python -m reqrec.iehost build   （記録用ブラウザを reqrec のフォルダに作成）\n"
          "        python -m reqrec.iehost status  （作成済みか確認）", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
