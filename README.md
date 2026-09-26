# rakutenai.c

evex-dev/rakutenai をC言語に移植したやつ。

## 元repo
evex-devのやつ: https://github.com/evex-dev/rakutenai (thx)

- 本家の機能をまるごと移植
- C99からC23まで動く
- 変なライブラリ不要（WinHTTPとBCryptだけ）
- メモリ確保も無駄削ぎ落としてて速い
- -Wall -Wextra -Werror -pedantic で警告ゼロ
