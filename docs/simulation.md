# シミュレーションと計装

angrで実行のステップを要求するとき、何かが実際にそのステップを実行しなければなりません。
angrは一連のエンジン（`SimEngine`クラスのサブクラス）を使って、与えられたコードのセクションが入力状態に与える影響をエミュレートします。
angrの実行コアは、利用可能なすべてのエンジンを順番に試し、そのステップを処理できる最初のものを選びます。
以下は、デフォルトのエンジンのリストです:

- failureエンジンは、前のステップで継続不可能な状態になったときに呼び出されます。
- syscallエンジンは、前のステップがsyscallで終了したときに呼び出されます。
- hookエンジンは、現在のアドレスがフックされたときに呼び出されます。
- unicornエンジンは、`UNICORN`オプションが有効で、状態にシンボリックデータがない場合に呼び出されます。
- VEXエンジンは、最終的なフォールバックとして呼び出されます。

## SimSuccessors

実際にすべてのエンジンを順番に試すコードは`project.factory.successors(state, **kwargs)`で、その引数を各エンジンに渡します。
この関数は`state.step()`と`simulation_manager.step()`の中核をなしています。
また、この関数は以前簡単に説明したSimSuccessorsオブジェクトを返します。
SimSuccessorsの目的は、さまざまなリスト属性に格納されている後継状態を簡単に分類することです。
その内容は以下の通りです:

| 属性 | ガード条件 | 命令ポインター | 説明 |
|-----------|-----------------|---------------------|-------------|
| `successors` | True（シンボリックでもよいが、Trueに制約されるもの）。 | シンボリックでもよい（ただし解が256個未満のものに限る、 `unconstrained_successors`を参照）。 | エンジンによって処理された状態の、通常の充足可能な後継状態です。この状態の命令ポインターはシンボリックであってもよいため（すなわち、ユーザー入力に基づいて計算されるジャンプ）、実際には、今後実行される可能性がある *複数の* 状態を表すかもしれません。 |
| `unsat_successors` | False (シンボリックでもよいが、Falseに制約されるもの)。 | シンボリックでもよい。 | 充足不能な後継者、つまりガード条件がfalseにしかならない後継者です（すなわち、条件が満たされないジャンプや、*必ず* 実行されるジャンプのデフォルト分岐）。 |
| `flat_successors` | True（シンボリックでもよいが、Trueに制約されるもの）。 | 具体的な値。 | 前述したように、`successors`リストに含まれる状態はシンボリックな命令ポインターを持つことができます。これは、コードの他の部分と同じように（つまり`SimEngineVEX.process`でその状態を前に進めるとき）、1つのプログラム状態がコード内の1つの場所の実行のみを表すと仮定しているため、かなりわかりにくいです。これを緩和するために、シンボリックな命令ポインターを持つ`successors`内の状態に遭遇したとき、それらに対して可能なすべての具体的な解（256個まで）を計算し、解ごとに状態のコピを作成します。このプロセスを「平坦化」と呼びます。これらの`flat_successors`は、それぞれに異なる具体的な命令ポインターを持つ状態です。たとえば、`successors`内の状態の命令ポインターが`X+5`で、`X`には`X > 0x800000`かつ`X <= 0x800010`という制約があった場合、これを16個の異なる`flat_successors`に平坦化し、命令ポインターが`0x800006`の状態、`0x800007`の状態、といったように、`0x800015`まで平坦化します。 |
| `unconstrained_successors` | True（シンボリックでもよいが、Trueに制約されるもの）。 | シンボリック（解が256個以上のもの)。 | 先に説明した平坦化の手順において、命令ポインターに対して可能な解が256個以上あると判明した場合、命令ポインターは制約のないデータ（すなわち、ユーザーデータによるスタックオーバーフロー）で上書きされたと仮定します。 *この仮定は一般に健全ではありません* 。このような状態は`unconstrained_successors`に置かれ、`successors`には置かれません。 |
| `all_successors` | 何でもよい | シンボリックでもよい。 | 之は`successors + unsat_successors + unconstrained_successors`です。 |

## ブレークポイント

TODO: シナリオを修正するために書き直す

普通の実行エンジンと同じように、angrはブレークポイントをサポートしています。これはかなりすごいことです！ポイントは以下のように設定されます:

```python
>>> import angr
>>> b = angr.Project('examples/fauxware/fauxware')

# 状態を取得します
>>> s = b.factory.entry_state()

# ブレークポイントを追加します。このブレークポイントは、メモリ書き込みが行われる直前にipdbを実行します。
>>> s.inspect.b('mem_write')

# 一方、メモリ書き込みが行われた*直後に*ブレークポイントのトリガーを設定することも可能です。
# また、ipdbを開く代わりにコールバック関数を実行させることもできます。
>>> def debug_func(state):
...     print("State %s is about to do a memory write!")

>>> s.inspect.b('mem_write', when=angr.BP_AFTER, action=debug_func)

# あるいは、組み込みのIPythonを実行することも可能です！
>>> s.inspect.b('mem_write', when=angr.BP_AFTER, action=angr.BP_IPYTHON)
```

メモリ書き込み以外にも、多くの場所にブレークポイントを設置できます。以下はそのリストです。それぞれのイベントに対してBP_BEFOREまたはBP_AFTERを指定できます。

| イベントタイプ | イベントの意味 |
|-------------------|------------------------------------------|
| mem_read          | メモリが読み込まれています。 |
| mem_write         | メモリが書き込まれています。 |
| address_concretization | シンボリックメモリアドレスが解決されています。 |
| reg_read          | レジスタが読み込まれています。 |
| reg_write         | レジスタが書き込まれています。 |
| tmp_read          | 一時変数が読み込まれています。 |
| tmp_write         | 一時変数が書き込まれています。 |
| expr              | 式が作成されています（すなわち、算術演算の結果やIRの定数）。 |
| statement         | IRステートメントが変換されています。 |
| instruction       | 新しい（ネイティブの）命令が翻訳されています。 |
| irsb              | 新しい基本ブロックが翻訳されています。 |
| constraints       | 新しい制約が状態に追加されています。 |
| exit              | 実行により後継者が生成されています。 |
| fork              | シンボリック実行状態が複数の状態にフォークされています。 |
| symbolic_variable | 新しいシンボリック変数が作成されています。 |
| call              | call命令が実行されています。 |
| return            | ret命令が実行されています。 |
| simprocedure      | simprocedure（またはsyscall）が実行されています。 |
| dirty             | dirty IRのコールバックが実行されています。 |
| syscall           | syscallが実行されています（simprocedureイベントに加えて呼び出されます）。 |
| engine_process    | SimEngineがコードを処理しようとしています。 |

これらのイベントは異なる属性を公開します:

| イベントタイプ | 属性の名前 | 属性が使えるとき | 属性の意味 |
|------------------------|----------------------------------------|------------------------|------------------------------------------|
| mem_read               | mem_read_address                       | BP_BEFORE or BP_AFTER  | 読み込まれているメモリアドレス。 |
| mem_read               | mem_read_expr                          | BP_AFTER               | そのアドレスにある式。 |
| mem_read               | mem_read_length                        | BP_BEFORE or BP_AFTER  | 読み込まれているメモリの長さ。 |
| mem_read               | mem_read_condition                     | BP_BEFORE or BP_AFTER  | メモリが読み込まれる条件。 |
| mem_write              | mem_write_address                      | BP_BEFORE or BP_AFTER  | 書き込まれているメモリアドレス。 |
| mem_write              | mem_write_length                       | BP_BEFORE or BP_AFTER  | 書き込まれているメモリの長さ。 |
| mem_write              | mem_write_expr                         | BP_BEFORE or BP_AFTER  | 書き込まれている式。 |
| mem_write              | mem_write_condition                    | BP_BEFORE or BP_AFTER  | メモリが書き込まれる条件。 |
| reg_read               | reg_read_offset                        | BP_BEFORE or BP_AFTER  | 読み込まれているレジスタのオフセット。 |
| reg_read               | reg_read_length                        | BP_BEFORE or BP_AFTER  | 読み込まれているレジスタの長さ。 |
| reg_read               | reg_read_expr                          | BP_AFTER               | レジスタ内の式。 |
| reg_read               | reg_read_condition                     | BP_BEFORE or BP_AFTER  | レジスタが読み込まれる条件。 |
| reg_write              | reg_write_offset                       | BP_BEFORE or BP_AFTER  | 書き込まれているレジスタのオフセット。 |
| reg_write              | reg_write_length                       | BP_BEFORE or BP_AFTER  | 書き込まれているレジスタの長さ。 |
| reg_write              | reg_write_expr                         | BP_BEFORE or BP_AFTER  | 書き込まれている式。 |
| reg_write              | reg_write_condition                    | BP_BEFORE or BP_AFTER  | レジスタが書き込まれる条件。 |
| tmp_read               | tmp_read_num                           | BP_BEFORE or BP_AFTER  | 読み込まれている一時変数の番号。 |
| tmp_read               | tmp_read_expr                          | BP_AFTER               | 読み込まれている一時変数の式。 |
| tmp_write              | tmp_write_num                          | BP_BEFORE or BP_AFTER  | 書き込まれている一時変数の番号。 |
| tmp_write              | tmp_write_expr                         | BP_AFTER               | 書き込まれている式。 |
| expr                   | expr                                   | BP_BEFORE or BP_AFTER  | IR式。 |
| expr                   | expr_result                            | BP_AFTER               | 式を評価した値（たとえば、AST）。 |
| statement              | statement                              | BP_BEFORE or BP_AFTER  | （IR基本ブロック内の）IRステートメントのインデックス。 |
| instruction            | instruction                            | BP_BEFORE or BP_AFTER  | ネイティブ命令のアドレス。 |
| irsb                   | address                                | BP_BEFORE or BP_AFTER  | 基本ブロックのアドレス。 |
| constraints            | added_constraints                      | BP_BEFORE or BP_AFTER  | 追加される制約のリスト |
| call                   | function_address                       | BP_BEFORE or BP_AFTER  | 呼び出される関数の名前。 |
| exit                   | exit_target                            | BP_BEFORE or BP_AFTER  | SimExitのターゲットを表す式。 |
| exit                   | exit_guard                             | BP_BEFORE or BP_AFTER  | SimExitのガードを表す式。 |
| exit                   | exit_jumpkind                          | BP_BEFORE or BP_AFTER  | SimExitの種類を表す式。 |
| symbolic_variable      | symbolic_name                          | BP_AFTER               | 作成されるシンボリック変数の名前。ソルバーエンジンはこの名前を変更することがあります（一意のIDと長さを追加します）。最終的なシンボリック式はsymbolic_exprを確認してください。 |
| symbolic_variable      | symbolic_size                          | BP_AFTER               | 作成されるシンボリック変数のサイズ。 |
| symbolic_variable      | symbolic_expr                          | BP_AFTER               | 新しいシンボリック変数を表す式。 |
| address_concretization | address_concretization_strategy        | BP_BEFORE or BP_AFTER  | アドレスに使用されるSimConcretizationStrategy。ブレークポイントハンドラーで、適用される戦略を変更できます。ブレークポイントハンドラーがこの属性をNoneに設定するとこの戦略はスキップされます。 |
| address_concretization | address_concretization_action          | BP_BEFORE or BP_AFTER  | メモリ操作を記録するために使用されるSimMemoryオブジェクト。 |
| address_concretization | address_concretization_memory          | BP_BEFORE or BP_AFTER  | アクションが実行されたSimMemoryオブジェクト。 |
| address_concretization | address_concretization_expr            | BP_BEFORE or BP_AFTER  | 解決されるメモリインデックスを表すAST。ブレークポイントハンドラーはこの属性を変更してアドレスの解決に影響を与えることができます。 |
| address_concretization | address_concretization_add_constraints | BP_BEFORE or BP_AFTER  | この読み取りに対して制約を追加すべきかどうか。 |
| address_concretization | address_concretization_result          | BP_AFTER               | 解決されたメモリアドレス（整数）のリスト。ブレークポイントハンドラーはこの属性を上書きして、異なる解決結果を設定できます。 |
| syscall                | syscall_name                           | BP_BEFORE or BP_AFTER  | システムコールの名前。 |
| simprocedure           | simprocedure_name                      | BP_BEFORE or BP_AFTER  | simprocedureの名前。 |
| simprocedure           | simprocedure_addr                      | BP_BEFORE or BP_AFTER  | simprocedureのアドレス。 |
| simprocedure           | simprocedure_result                    | BP_AFTER               | simprocedureの戻り値。BP_BEFOREで _上書き_ することも可能で、その場合は実際のsimproceduregがスキップされて、代わりにブレークポイントハンドラーの戻り値が使用されます。 |
| simprocedure           | simprocedure                           | BP_BEFORE or BP_AFTER  | 実際のSimProcedureオブジェクト。 |
| dirty                  | dirty_name                             | BP_BEFORE or BP_AFTER  | dirty callの名前。 |
| dirty                  | dirty_handler                          | BP_BEFORE              | dirty callを処理するために実行される関数。この属性を上書きすることが可能です。 |
| dirty                  | dirty_args                             | BP_BEFORE or BP_AFTER  | dirtyのアドレス。 |
| dirty                  | dirty_result                           | BP_AFTER               | dirty callの戻り値。BP_BEFOREで _上書き_ することも可能で、その場合は実際のdirty callがスキップされて、代わりにブレークポイントハンドラーの戻り値が使用されます。|
| engine_process         | sim_engine                             | BP_BEFORE or BP_AFTER  | 処理しているSimEngineです。 |
| engine_process         | successors                             | BP_BEFORE or BP_AFTER  | エンジンの結果を定義しているSimSuccessorsオブジェクトです。 |

適切なブレークポイントハンドラー内で`state.inspect`を参照することで、そのメンバーとしてこれらの属性にアクセスできます。
これらの値を変更して、さらにその値を使用するように変更できます！

```python
>>> def track_reads(state):
...     print('Read', state.inspect.mem_read_expr, 'from', state.inspect.mem_read_address)
...
>>> s.inspect.b('mem_read', when=angr.BP_AFTER, action=track_reads)
```

さらに、これらの属性はそれぞれ`inspect.b`のキーワード引数として使用することで、条件付きのブレークポイントを作成することができます:

```python
# アドレス0x1000に対して書き込みが発生した際にブレークします
>>> s.inspect.b('mem_write', mem_write_address=0x1000)

# 書き込み先のアドレスがシンボリック値で、その解が0x1000のみだった場合にブレークします
>>> s.inspect.b('mem_write', mem_write_address=0x1000, mem_write_address_unique=True)

# アドレス0x8000以降のメモリ読み込み命令で、読み込んだ値が0x1000だった場合にブレークします
>>> s.inspect.b('instruction', when=angr.BP_AFTER, instruction=0x8000, mem_read_expr=0x1000)
```

かっこいい！実は、条件として関数を指定することもできます:
```python
# これはなんでもできる複雑な条件です！この場合、RAXが0x41414141であることを確認します。
# また、0x8004で始まる基本ブロックが、パスの履歴の中に含まれていることも確認します。
>>> def cond(state):
...     return state.eval(state.regs.rax, cast_to=str) == 'AAAA' and 0x8004 in state.inspect.backtrace

>>> s.inspect.b('mem_write', condition=cond)
```

これは素晴らしいものです！

### `mem_read`ブレークポイントに関する注意点


もし、メモリからデータをロードする際に設定した`mem_read`ブレークポイントをトリガーさせたくない場合は、`state.memory.load`にキーワード引数`disable_actions=True`と`inspect=False`をつけて呼び出してください。

これは`state.find`にも当てはまり、同じキーワード引数を使って`mem_read`ブレークポイントがトリガーされないようにすることができます。
