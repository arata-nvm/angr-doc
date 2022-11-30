# 識別子

識別子は、テストケースを使用してCGCバイナリに含まれる一般的なライブラリ関数を識別します。
スタック変数/引数に関するいくつかの基本的な情報を見つけることによって、プリフィルタリングを行います。
スタック変数に関する情報は、他のプロジェクトでも一般的に有用です。

```python
>>> import angr

# すべてのマッチを取得する
>>> p = angr.Project("../binaries/tests/i386/identifiable")
# 解析はIdentifierの呼び出しを通して実行されることに注意してください
>>> idfer = p.analyses.Identifier()
>>> for funcInfo in idfer.func_info:
... 	print(hex(funcInfo.addr), funcInfo.name)

0x8048e60 memcmp
0x8048ef0 memcpy
0x8048f60 memmove
0x8049030 memset
0x8049320 fdprintf
0x8049a70 sprintf
0x8049f40 strcasecmp
0x804a0f0 strcmp
0x804a190 strcpy
0x804a260 strlen
0x804a3d0 strncmp
0x804a620 strtol
0x804aa00 strtol
0x80485b0 free
0x804aab0 free
0x804aad0 free
0x8048660 malloc
0x80485b0 free
```
