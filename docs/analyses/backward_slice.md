# バックワードスライシング

*プログラムスライス* とは、通常は元のプログラムから0個以上のステートメントを削除して得られるステートメントのサブセットです。
スライシングは、デバッグやプログラムの理解に役立つことが多いです。
たとえば、プログラムスライスでは、通常、変数のソースを簡単に見つけることができます。

バックワードスライスは、プログラム内の *ターゲット* から構築され、このスライスのすべてのデータフローは *ターゲット* で終了します。

angrには`BackwardSlice`という、プログラムのバックワードスライスを構築するためのビルトインの解析モジュールがあります。
このセクションでは、angrの`BackwardSlice`解析の方法と、実装の選択と制限に関する詳細な説明を行います。

## 最初のステップ

`BackwardSlice` を作るには、以下の情報を入力として必要とします。

- **必須** CFG。プログラムの制御フローグラフ（CFG）。このCFGは正確なCFG（CFGEmulated）でなければなりません。
- **必須** ターゲット。バックワードスライスが終了する最終目的地です。
- **任意** CDG。CFGから派生した制御依存グラフ（CDG）です。
  angrには、そのためのビルトインの解析モジュール`CDG`があります。
- **任意** DDG。CFGの上に構築されたデータ依存グラフ（DDG）です。
  angrには、そのためのビルトインの解析モジュール`DDG`があります。

`BackwardSlice`は以下のコードで構築できます:

```python
>>> import angr
# プロジェクトをロードする
>>> b = angr.Project("examples/fauxware/fauxware", load_options={"auto_load_libs": False})

# まずCFGを作成する。その後にデータ依存グラフを生成するために、以下のことが必要になります:
# - keep_state=Trueを指定して、すべての入力状態を保持する。
# - angr.options.refsオプションを追加することで、メモリ、レジスタ、一時変数へのアクセスを保存する。
# 必要に応じて、CFG復元に必要なパラメータ（たとえば、context_sensitivity_level）を自由に設定できます。
>>> cfg = b.analyses.CFGEmulated(keep_state=True, 
...                              state_add_options=angr.sim_options.refs, 
...                              context_sensitivity_level=2)

# 制御依存グラフを作成する
>>> cdg = b.analyses.CDG(cfg)

# データ依存グラフを作成する。時間がかかるかもしれないので、気長に待ちましょう！
>>> ddg = b.analyses.DDG(cfg)

# どこに行きたいか見てみましょう... exit()の呼び出しに行ってみましょう、これはSimProcedureです。
>>> target_func = cfg.kb.functions.function(name="exit")
# CFGNodeのインスタンスが必要です
>>> target_node = cfg.get_any_node(target_func.addr)

# BackwardSliceを生成してみましょう！
# `targets`はオブジェクトのリストで、それぞれのオブジェクトはCodeLocationオブジェクト、またはCFGNodeのインスタンスとステートメントIDのタプルです。
# ステートメントIDを-1に設定すると、そのCFGNodeの先頭を意味します。
# SimProcedureはステートメントを持たないため、常に-1を指定する必要があります。
>>> bs = b.analyses.BackwardSlice(cfg, cdg=cdg, ddg=ddg, targets=[ (target_node, -1) ])

# これは素晴らしいプログラムスライスです！
>>> print(bs)

```

データ依存グラフを得るのが困難な場合や、CFGNodeの上にプログラムスライスを構築したい場合もあります。
DDGがオプションのパラメータなのは、基本的にそのためです。
次のようにすることで、CFGだけをもとにした`BackwardSlice`を構築することができます:
```
>>> bs = b.analyses.BackwardSlice(cfg, control_flow_slice=True)
BackwardSlice (to [(<CFGNode exit (0x10000a0) [0]>, -1)])
```

## `BackwardSlice`オブジェクトの使用方法

`BackwardSlice`オブエクトを使用する前に、このクラスの設計は現在かなり不確かであり、近い将来変更される可能性があることに注意してください。このドキュメントを最新の状態に保つために、私達は最善を尽くします。

### メンバー

構築後の`BackwardSlice`は、プログラムスライスを記述する以下のメンバーを持っています:

| メンバー             | モード     | 意味                                                                                                                               |
| -------            | -------- | -------                                                                                                                               |
| runs_in_slice      | CFGのみ | プログラムスライス内のブロックとSimProceduresのアドレス、およびそれらの間の遷移を示す`networkx.DiGraph`インスタンス。 |
| cfg_nodes_in_slice | CFGのみ | プログラムスライス内のCFGNodeとその間の遷移を示す`networkx.DiGraph`インスタンス。 |
| chosen_statements  | DDGあり | プログラムスライスの一部であるステートメントIDのリストに基本ブロックアドレスをマッピングした辞書。 |
| chosen_exits       | DDGあり | 基本ブロックアドレスを「出口」のリストにマッピングした辞書。リスト内の各出口はプログラムスライス内の有効な遷移です。 |

`chosen_exit`の各「出口」は、ステートメントIDとターゲットアドレスのリストを含むタプルです。
たとえば、「出口」は次のようになります:
```
(35, [ 0x400020 ])
```

「出口」が基本ブロックのデフォルトの出口である場合、次のようになります:
```
(“default”, [ 0x400085 ])
```

### アノテーションされた制御フローグラフのエクスポート

TODO

### ユーザーフレンドリーな表現

`BackwardSlice.dbg_repr()`を見てみましょう！

TODO

## 実装の選択

TODO

## 機能の限界

TODO

### 完全性

TODO

### 安定性

TODO

