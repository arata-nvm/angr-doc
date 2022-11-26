
# 始める前に

IPython（または他のPythonコマンドラインインタプリタ）でangrを使い、探索することは、私たちがangrを設計する際の主なユースケースです。
どのようなインターフェイスが利用できるかわからない場合、タブ補完はあなたの味方です！

ときどきIPythonのタブ補完が遅くなります。
次の方法でタブ補完の精度を低下させることなくこの問題を回避できます:

```python
# 毎回実行するのを避けるため、このファイルをIPythonのスタートアップディレクトリに保存します。
import IPython
py = IPython.get_ipython()
py.Completer.use_jedi = False
```

# コアコンセプト

angrを使い始める前に、基本的なangrの概念と、angrオブジェクトを構築する方法についていくつか知っておく必要があります。
バイナリをロードした後に、何が直接利用できるかを調べることで、この点について確認します！

常にangrでの最初のアクションは、バイナリを _プロジェクト_ にロードすることです。この例では`/bin/true`を使用します。

```python
>>> import angr
>>> proj = angr.Project('/bin/true')
```

プロジェクトはangrの制御基地です。
これを用いて、読み込んだ実行可能ファイルについて解析やシミュレーションを行うことができます。
angrで扱うほぼすべてのオブジェクトは、何らかの形でプロジェクトの存在に依存しています。

## 基本的なプロパティ

まず、プロジェクトに関する基本的なプロパティを取得します: CPUアーキテクチャ、ファイル名、エントリポイントのアドレス

```python
>>> import monkeyhex # これにより、数値の結果が16進数にフォーマットされます
>>> proj.arch
<Arch AMD64 (LE)>
>>> proj.entry
0x401670
>>> proj.filename
'/bin/true'
```

* _arch_ はプログラムがコンパイルされたアーキテクチャの`archinfo.Arch`オブジェクトのインスタンスです（この場合はリトルエンディアンのamd64）。このオブジェクトには実行するCPUに関する膨大な情報が含まれており、[自由に](https://github.com/angr/archinfo/blob/master/archinfo/arch_amd64.py)閲覧できます。一般的には、`arch.bits`、`arch.bytes`（これは[メイン`Arch`クラス](https://github.com/angr/archinfo/blob/master/archinfo/arch.py)の`@property`宣言です）、`arch.name`、`arch.memory_endness`が使用されます。
* _entry_ はバイナリのエントリポイントです！
* _filename_ はバイナリのファイル名です。楽しい！

## ローダー

バイナリファイルから仮想アドレス空間での表現を得るのは非常に複雑です！これを処理するために、CLEというモジュールがあります。CLEの結果はローダーと呼ばれ、`.loader`プロパティから利用できます。この使い方の詳細については[後ほど](./loading.md)説明しますが、angrがプログラムと一緒にロードした共有ライブラリを確認したり、ロードしたアドレス空間について基本的なクエリを実行したりするために使用できることを知っておいてください。

```python
>>> proj.loader
<Loaded true, maps [0x400000:0x5004000]>

>>> proj.loader.shared_objects # あなたの環境では結果が異なるかもしれません！
{'ld-linux-x86-64.so.2': <ELF Object ld-2.24.so, maps [0x2000000:0x2227167]>,
 'libc.so.6': <ELF Object libc-2.24.so, maps [0x1000000:0x13c699f]>}

>>> proj.loader.min_addr
0x400000
>>> proj.loader.max_addr
0x5004000

>>> proj.loader.main_object  # このプロジェクトにはいくつかのバイナリをロードしました。メインはこれです！
<ELF Object true, maps [0x400000:0x60721f]>

>>> proj.loader.main_object.execstack  # クエリの例: このバイナリはスタックが実行可能か？
False
>>> proj.loader.main_object.pic  # クエリの例: このバイナリは位置独立か?
True
```

## ファクトリー

angrにはたくさんのクラスがあり、そのほとんどはインスタンス化するためにプロジェクトを必要とします。プロジェクトをあちこちへ渡す代わりに、`project.factory`を提供しています。このファクトリーは頻繁に使うオブジェクトの便利なコンストラクターを持っています。

このセクションでは、いくつかの基本的なangrの概念の紹介も行います。準備はいいかい！

#### ブロック

まず、`project.factory.block()`は特定のアドレスからコードの[基本ブロック](https://en.wikipedia.org/wiki/Basic_block)を抽出するために使われます。これは重要な事実です。 _angrは基本ブロック単位でコードを解析します。_ Blockオブジェクトが返されるので、これを使ってコードのブロックについておもしろいことがいろいろとわかります:

```python
>>> block = proj.factory.block(proj.entry) # プログラムのエントリポイントからコードブロックをリフトする
<Block for 0x401670, 42 bytes>

>>> block.pp()                          # ディスアセンブルした結果を標準出力に整形して出力する
0x401670:       xor     ebp, ebp
0x401672:       mov     r9, rdx
0x401675:       pop     rsi
0x401676:       mov     rdx, rsp
0x401679:       and     rsp, 0xfffffffffffffff0
0x40167d:       push    rax
0x40167e:       push    rsp
0x40167f:       lea     r8, [rip + 0x2e2a]
0x401686:       lea     rcx, [rip + 0x2db3]
0x40168d:       lea     rdi, [rip - 0xd4]
0x401694:       call    qword ptr [rip + 0x205866]

>>> block.instructions                  # 命令は何個ある？
0xb
>>> block.instruction_addrs             # 命令のアドレスは？
[0x401670, 0x401672, 0x401675, 0x401676, 0x401679, 0x40167d, 0x40167e, 0x40167f, 0x401686, 0x40168d, 0x401694]
```

さらに、Blockオブジェクトを使用して、コードブロックの他の表現を取得できます:

```python
>>> block.capstone                       # Capstone Block
<CapstoneBlock for 0x401670>
>>> block.vex                            # VEX IRSB （Pythonの内部アドレスであり、プログラムアドレスではありません）
<pyvex.block.IRSB at 0x7706330>
```

#### 状態

ここでangrに関するもう1つの事実があります。`Project`オブジェクトはプログラムの「初期化イメージ」を表しているに過ぎません。angrで実行する場合、 _シミュレーションされたプログラムの状態_ を表す特定のオブジェクト`SimState`を使います。1つ手に入れてみましょう！

```python
>>> state = proj.factory.entry_state()
<SimState @ 0x401670>
```

SimStateにはある状態におけるプログラムのメモリ、レジスタ、ファイルシステムのデータなど、実行時に変更される可能性のある「ライブデータ」が含まれています。状態の扱い方について後ほど詳しく説明しますが、ここでは`state.regs`と`state.mem`を使ってこの状態のレジスタとメモリにアクセスしてみましょう:

```python
>>> state.regs.rip        # 現在の命令ポインタを取得する
<BV64 0x401670>
>>> state.regs.rax
<BV64 0x1c>
>>> state.mem[proj.entry].int.resolved  # エントリポイントのメモリをCのintとして解釈する
<BV32 0x8949ed31>
```

これらはPythonのintではありません！これらは _ビットベクトル_ です。Pythonの整数はCPU上のワードと同じセマンティクスを持ちません。たとえばオーバーフロー時の動作が異なります。したがってangrではCPUのデータを表現するためにビットベクトルを使っています。これは整数をビット列で表現したものと考えることができます。各ビットベクトルは何ビットの幅を持っているかを表す`.length`プロパティを持っています。

ビットベクトルをどう操作するかについてはすぐに学習しますが、まずはPythonのintをビットベクトルに変換する方法を説明します:

```python
>>> bv = state.solver.BVV(0x1234, 32)       # 値が0x1234の32ビット幅のビットベクトルを作成する
<BV32 0x1234>                               # BVVはBitVector Valueを表す
>>> state.solver.eval(bv)                # Pythonのintに変換する
0x1234
```

これらのビットベクトルはレジスタやメモリに格納できます。また、Pythonの整数を直接格納すると適切なサイズのビットベクトルに変換されます:

```python
>>> state.regs.rsi = state.solver.BVV(3, 64)
>>> state.regs.rsi
<BV64 0x3>

>>> state.mem[0x1000].long = 4
>>> state.mem[0x1000].long.resolved
<BV64 0x4>
```

`mem`インターフェイスはかなり強力なPythonマジックを使用しているため、最初は少し混乱します。使い方を簡単に説明すると、次のとおりです:

* array\[index\]記法を使ってアドレスを指定します。
* `.<type>`を使ってメモリを&lt;type&gt;として解釈することを指定します。（一般的な値: char, short, int, long, size_t, uint8_t, uint16_tなど）
* そこから、次のいずれかを実行できます:
  * ビットベクトルかPythonのintの値を格納します。
  * `.resolved`を使ってビットベクトルとして値を取得します。
  * `.concrete`を使ってPythonのintとして値を取得します。

より高度な使用方法は、あとで説明します！

最後に、さらにいくつかのレジスタを読んでみると、非常に奇妙な値に遭遇することがあります:

```python
>>> state.regs.rdi
<BV64 reg_48_11_64{UNINITIALIZED}>
```

これは64ビットのビットベクトルですが、数値は含まれていません。
その代わりに名前がついています！
これは _シンボリック変数_ と呼ばれ、シンボリック実行の基礎となるものです。
慌てないで！これから2章に渡って詳しく説明します。

#### シミュレーションマネージャー

もし、状態によってある時点でのプログラムを表現できるならば、それを _次の_ 時点に到達させる方法があるはずです。シミュレーションマネージャーは、状態を使って実行やシミュレーションを行うための、angrの主要なインターフェイスです。簡単な紹介として、さきほど作成した状態を使っていくつか基本ブロックを進める方法を示します。

まず、使用するシミュレーションマネージャーを作成します。コンストラクターには、1つの状態か状態のリストを渡すことができます。

```python
>>> simgr = proj.factory.simulation_manager(state)
<SimulationManager with 1 active>
>>> simgr.active
[<SimState @ 0x401670>]
```

シミュレーションマネージャーは、いくつかの状態の _スタッシュ_ を持つことができます。デフォルトのスタッシュである`active`は、コンストラクターに渡された状態で初期化されます。`simgr.active[0]`を使って、状態をさらに確認できます。

さあ… 準備をしましょう、実行します。

```python
>>> simgr.step()
```

基本ブロックのぶんだけシンボリック実行を行いました！アクティブなスタッシュをもう一度見ると、それが更新されていること、さらに元の状態が**変更されていない**ことがわかります。SimStateオブジェクトは実行時にイミュータブルなものとして扱われます。1つの状態を、複数回の実行の「ベース」として安全に使用できます。

```python
>>> simgr.active
[<SimState @ 0x1020300>]
>>> simgr.active[0].regs.rip                 # 新しくてエキサイティング！
<BV64 0x1020300>
>>> state.regs.rip                           # 相変わらず！
<BV64 0x401670>
```

`/bin/true`はシンボリック実行でおもしろいことをする方法を説明するにはよい例ではないので、今はここで止めておきます。

## 解析

angrにはいくつかのビルトイン解析があらかじめパッケージされており、これらを使ってプログラムから興味深い種類の情報を抽出できます。以下はその例です:

```
>>> proj.analyses.            # ここでIPythonでTABを押すと、すべての自動補完のリストが表示されます:
 proj.analyses.BackwardSlice        proj.analyses.CongruencyCheck      proj.analyses.reload_analyses       
 proj.analyses.BinaryOptimizer      proj.analyses.DDG                  proj.analyses.StaticHooker          
 proj.analyses.BinDiff              proj.analyses.DFG                  proj.analyses.VariableRecovery      
 proj.analyses.BoyScout             proj.analyses.Disassembly          proj.analyses.VariableRecoveryFast  
 proj.analyses.CDG                  proj.analyses.GirlScout            proj.analyses.Veritesting           
 proj.analyses.CFG                  proj.analyses.Identifier           proj.analyses.VFG                   
 proj.analyses.CFGEmulated          proj.analyses.LoopFinder           proj.analyses.VSA_DDG               
 proj.analyses.CFGFast              proj.analyses.Reassembler
```

いくつかは本書の後半で説明しますが、一般に、特定の解析の使用方法を知りたい場合は、[APIドキュメント](http://angr.io/api-doc/angr.html?highlight=cfg#module-angr.analysis)を読むべきです。非常に簡単な例として、制御フローグラフの作成方法と使用方法を示します:

```python
# もともと、バイナリをロードした際に、依存関係もすべて同じ仮想アドレス空間にロードされました
# これはほどんどの解析にとって望ましくありません。
>>> proj = angr.Project('/bin/true', auto_load_libs=False)
>>> cfg = proj.analyses.CFGFast()
<CFGFast Analysis Result at 0x2d85130>

# cfg.graphはCFGNodeインスタンスでいっぱいのnetworkx DiGraphです
# この使用方法は、networkx APIを調べてください！
>>> cfg.graph
<networkx.classes.digraph.DiGraph at 0x2da43a0>
>>> len(cfg.graph.nodes())
951

# 特定のアドレスのCFGNodeを取得するには、cfg.get_any_nodeを使用します
>>> entry_node = cfg.get_any_node(proj.entry)
>>> len(list(cfg.graph.successors(entry_node)))
2
```

## さて、どうしよう？

このページを読んで、angrの重要な概念を知ることができたと思います: 基本ブロック、状態、ビットベクトル、シミュレーションマネージャー、解析など。しかし、angrをデバッガーとして使う以外に、おもしろいことは何もできません！このまま読み続けると、より深い力が解き放たれるでしょう…
