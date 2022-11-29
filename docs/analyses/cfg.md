# 制御フローグラフ（CFG）の復元

angrには、バイナリプログラムの制御フローグラフを復元するための解析モジュールが含まれています。
また、関数境界の復元、間接ジャンプやその他の有用なメタデータの推論も含まれます。

## 一般的な考え方

バイナリを解析する基本的な方法の一つは制御フローグラフを使うことです。
CFGは、（概念的に）基本ブロックをノード、jump/call/ret/その他をエッジとするグラフである。

angrでは、静的CFG（CFGFast）と動的CFG（CFGEmulated）の2種類のCFGを生成することができます。

CFGFast は静的解析を用いてCFGを生成します。
これは大幅に高速化されますが、一部の制御フローの遷移は実行時にしか解決できないため、理論的には限界があります。
これは、他の一般的なリバースエンジニアリングツールが行うCFG解析と同じ種類のもので、結果はそれらの出力と同等です。

CFGEmulatedは、CFGを取得するためにシンボリック実行を使用します。これは理論的にはより正確ですが、劇的に遅くなります。
また、エミュレーションの精度に問題があるため、一般的に完全ではありません（システムコール、ハードウェア機能の欠落、など）。

*どのCFGを使用するべきかわからない場合、あるいはCFGEmulatedで問題がある場合はまずCFGFastを試してみてください。*

CFGは次のようにして作成できます:

```python
>>> import angr
# プロジェクトをロードする
>>> p = angr.Project('/bin/true', load_options={'auto_load_libs': False})

# 静的CFGを作成する
>>> cfg = p.analyses.CFGFast()

# 動的CFGを作成する
>>> cfg = p.analyses.CFGEmulated(keep_state=True)
```

## CFGを使う

CFGのコアは[NetworkX](https://networkx.github.io/)の有向グラフです。
つまり、通常のNetworkXのAPIはすべて利用できます。

```python
>>> print("This is the graph:", cfg.graph)
>>> print("It has %d nodes and %d edges" % (len(cfg.graph.nodes()), len(cfg.graph.edges())))
```

CFGグラフのノードは、クラス`CFGNode`クラスのインスタンスです。
コンテキストに依存するため、与えられた基本ブロックはグラフ内に複数のノードを持つことができます（複数のコンテキストに対応するため）。

```python
# 与えられた場所にある*任意の*ノードを取得する
>>> entry_node = cfg.get_any_node(p.entry)

# すべてのノードを取得する
>>> print("There were %d contexts for the entry block" % len(cfg.get_all_nodes(p.entry)))

# 先行ノードと後継ノードを調べることもできます
>>> print("Predecessors of the entry point:", entry_node.predecessors)
>>> print("Successors of the entry point:", entry_node.successors)
>>> print("Successors (and type of jump) of the entry point:", [ jumpkind + " to " + str(node.addr) for node,jumpkind in cfg.get_successors_and_jumpkind(entry_node) ])
```

### CFGを表示する

制御フローグラフのレンダリングは難しい問題です。
angrはCFG解析の出力をレンダリングするビルトインの機構を持っておらず、matplotlibのような伝統的なグラフレンダリングライブラリを使用すると、使えない画像になります。

angrのCFGを見るための1つの解決策は、[axtのangr-utilsリポジトリ](https://github.com/axt/angr-utils)にあります。

## 共有ライブラリ

CFG解析は異なるバイナリオブジェクトのコードを区別しません。
つまり、デフォルトではロードされた共有ライブラリを通る制御フローを解析しようとします。
これは、解析時間を数日間に延ばしてしまうため、ほとんど意図した動作ではありません。
共有ライブラリを含めずにバイナリをロードするには、`Project`コンストラクタに次のキーワード引数を追加してください:
`load_options={'auto_load_libs': False}`

## 関数マネージャー

CFGの結果は *Function Manager* というオブジェクトを生成し、`cfg.kb.functions`からアクセスできます。
このオブジェクトの最も一般的な使用方法は、辞書のようにアクセスすることです。このオブジェクトはアドレスを`Function`オブジェクトにマップし、関数に関するプロパティを知ることができます。

```python
>>> entry_func = cfg.kb.functions[p.entry]
```

Functionはいくつかの重要なプロパティを持っています！
- `entry_func.block_addrs`は、関数に属する基本ブロックの開始アドレスの集合です。
- `entry_func.blocks`は、 関数に属する基本ブロックの集合で、capstoneを使って探索したり逆アセンブルしたりできます。
- `entry_func.string_references()`は、関数内の任意の時点で参照されたすべての定数文字列のリストを返します。
	それらは`(addr, string)`タプルとして表現されます。ここでaddrは文字列が存在するバイナリのデータセクションのアドレスで、stringは文字列の値を含むPythonの文字列です。
- `entry_func.returning`は、関数がreturnできるかどうかを示すブーリアン値です。
	`False`は、すべてのパスがreturnしないことを示します。
- `entry_func.callable`は、この関数を参照するangr Callableオブジェクトです。
	Pythonの関数のようにPythonの引数で呼び出すことができ、その引数で関数を実行したかのように実際の結果（シンボリックかもしれない）を返すことができます！
- `entry_func.transition_graph`は、関数自体の制御フローを記述したNetworkX有向グラフです。これは、IDAが関数単位で表示する制御フローグラフに似ています。
- `entry_func.name`は、関数の名前です。
- `entry_func.has_unresolved_calls`と`entry.has_unresolved_jumps`はCFG内の不鮮明な部分を検出することに関係しています。
	間接的な呼び出しやジャンプのターゲットとなりうるものを解析で検出できない場合があります。
	もしこれが関数で発生した場合、その関数には適切な`has_resolved_*`値が`True`に設定されます。
- `entry_func.get_call_sites()`は、他の関数への呼び出しで終わるすべての基本ブロックのアドレスをリストで返します。
- `entry_func.get_call_target(callsite_addr)`は、コールサイトのアドレスを`callsite_addr`に与えると、そのコールサイトが呼び出される場所を返します。
- `entry_func.get_call_return(callsite_addr)`は、コールサイトのアドレスを`callsite_addr`に与えると、そのコールサイトがどこに戻るべきかを返します。

ほかにもいろいろあります！

## CFGFastの詳細

CFGFastは静的な制御フローと関数を復元します。
エントリポイント（またはユーザーが定義した任意の箇所）を起点に、おおよそ以下の手順で実行されます。

1) 基本ブロックがVEX IRにリフトされ、そのすべての出口（jump、call、return、次のブロックへの継続）が集められます。
2) それぞれの出口について、出口が定数アドレスである場合、CFGに正しい型のエッジを追加し、解析対象ブロックの集合に目的ブロックを追加します。
3) 出口で関数を呼び出す場合、行き先のブロックは新しい関数の開始点ともみなされます。呼び出す関数がリターンすることがわかっている場合、呼び出した後のブロックも解析します。
4) 出口でリターンする場合、現在の関数はリターンすることが記録され、呼び出しグラフとCFGの適切なエッジが更新されます。
4) すべての間接ジャンプ（目的地が一定でないブロックの出口）に対して、間接ジャンプの解決が行われます。

### 関数の開始アドレスを見つける

CFGFastは関数の開始アドレスと終了アドレスを決定する複数の方法をサポートしています。

まず、バイナリのmainエントリポイントが解析されます。
シンボルを持つバイナリ（たとえば、ストリップされていないELFやPEバイナリ）では、すべての関数シンボルが開始点になりうるものとして扱われます。
ストリップされたバイナリや、`blob`ローダーバックエンドを使用してロードされたバイナリなど、シンボルを持たないバイナリでは、CFGはバイナリのアーキテクチャで定義された関数プロローグをスキャンします。
最後に、デフォルトでは、バイナリのコードセクション全体が、プロローグやシンボルに関係なく、実行可能なコンテンツとしてスキャンされます。

これらに加えて、CFGEmulatedと同様に、関数の開始点は、それらが与えられたアーキテクチャ上の「call」命令のターゲットである場合にも考慮されます。

これらのオプションはすべて無効にできます。

### FakeRetと関数リターン

関数呼び出しが検出された場合、まず、呼び出し側関数が最終的にリターンすると想定し、その後のブロックを呼び出し側関数の一部として扱います。
この推測された制御フローエッジは「FakeRet」として知られています。
呼び出し側関数を解析した結果、そうでないことが判明した場合、CFGを更新し、このFakeRetを削除し、それに応じて呼び出しグラフと関数ブロックを更新します。
このように、CFGは *2回* 復元されます。この際、各関数のブロックの集合と、関数がリターンするかどうかを復元し、直接伝搬します。

### 間接ジャンプの解決

*TODO*

### オプション

これらはCFGFastを使用する際にもっとも便利なオプションです:

| オプション | 説明 |
|--------|-------------|
| force_complete_scan | （デフォルト: True）関数検出のためにバイナリ全体をコードとして扱います。blob（たとえば、コードとデータが混在している）が含まれている場合、 *これをオフにしたくなるでしょう* 。 |
| function_starts | 解析のエントリポイントとして使用するアドレスのリスト。 |
| normalize | （デフォルト: False）関数を正規化する（たとえば、それぞれの基本ブロックは最大1つの関数に属し、バックエッジは基本ブロックの開始点を指す）。 |
| resolve_indirect_jumps | デフォルト: True）CFG作成中に発見したすべての間接ジャンプのターゲットを見つけるために追加の分析を実行する。 | 
| もっと！ | 最新のオプションはp.analyses.CFGFastのdocstringを参照してください。 |

## CFGEmulatedの詳細

### オプション

CFGEmulatedのもっとも一般的なオプションです:

| オプション | 詳細 |
|--------|-------------|
| context_sensitivity_level | これは解析の文脈依存度を設定します。詳細については、以下の文脈依存度についてのセクションを参照してください。デフォルトでは1です。 |
| starts | 解析のエントリポイントとして使用するアドレスのリストです。 |
| avoid_runs | 解析の際に無視するアドレスのリストです。 |
| call_depth | 解析の深さを呼び出し数で制限します。これは、特定の関数がどの関数に直接ジャンプできるかを確認するのに便利です（`call_depth`を1に設定する）。 |
| initial_state | CFGに、解析で利用する初期状態を提供することができます。 |
| keep_state | メモリを節約するために、それぞれの基本ブロックでの状態はデフォルトで破棄されます。`keep_state`がTrueの場合、CFGNodeに状態が保存されます。 |
| enable_symbolic_back_traversal | 間接ジャンプを解決するための強力な手法を有効にするかどうか。 |
| enable_advanced_backward_slicing | 直接ジャンプを解決するための別の強力な手法を有効にするかどうか。 |
| more! | 最新のオプションはp.analyses.CFGEmulatedのdocstringを参照してください。 |

### 文脈依存度

angrは、すべての基本ブロックを実行し、それがどこに進むかを見ることでCFGを構築します。
これはいくつかの問題をもたらします: 基本ブロックは異なる *文脈* で異なる動作をします。
たとえば、ブロックが関数からのリターンで終わる場合、その基本ブロックを含む関数がどこから呼び出されたかによってそのリターンのターゲットは異なるでしょう。

文脈依存度とは、概念的には、コールスタックに保持する呼び出し元の個数です。
この概念を説明するために、次のコードを見てみましょう:

```c
void error(char *error)
{
	puts(error);
}

void alpha()
{
	puts("alpha");
	error("alpha!");
}

void beta()
{
	puts("beta");
	error("beta!");
}

void main()
{
	alpha();
	beta();
}
```

上記のサンプルには4つの連続した呼び出しの連鎖があります。`main>alpha>puts`、`main>alpha>error>puts`、`main>beta>puts`、`main>beta>error>puts`です。
この場合、angrはおそらく両方の呼び出しの連鎖を実行することができますが、大きなバイナリでは実行不可能になります。
そこで、angrは文脈依存度による制限を設定して、特定の状態でブロックを実行します。
つまり，各関数は，それが呼ばれた固有の文脈ごとに再解析されます。

たとえば、上記の`puts()`関数は、異なる文脈依存度を与えられると、以下のコンテキストで解析されます:

| 文脈依存度 | 意味 | 文脈 |
|-------|---------|----------|
| 0 | 呼び出し元のみ | `puts` |
| 1 | 1つの呼び出し先と呼び出し元 | `alpha>puts` `beta>puts` `error>puts` |
| 2 | 2つの呼び出し先と呼び出し元 | `alpha>error>puts` `main>alpha>puts` `beta>error>puts` `main>beta>puts` |
| 3 | 3つの呼び出し先と呼び出し元 | `main>alpha>error>puts` `main>alpha>puts` `main>beta>error>puts` `main>beta>puts` |

文脈依存度を上げると、CFGからより多くの情報が得られます。
たとえば、文脈依存度が1の場合、CFGは`alpha`から呼び出されると`puts`は`alpha`に戻り、`error`から呼び出されると`puts`は`error`に戻る、というように示します。
文脈依存度が0の場合、CFGは単に`puts`が`alpha`、`beta`、`error` に戻ることを示しています。
これは具体的には、IDAで使用される文脈依存度です。
文脈依存度を上げることの欠点は、解析時間が指数関数的に増加することです。
