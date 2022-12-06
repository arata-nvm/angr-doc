実行パイプラインを理解する
====================================

ここまでくれば、angr が非常に柔軟で、非常に操作しやすいエミュレータであることがおわかりいただけると思います。
このエミュレータを最大限に活用するために、`simgr.run()`を実行したときにどのような処理が行われるかを知っておくとよいでしょう。

これはより高度なドキュメントになることを意図しています。私たちが話していることを理解するためには、`SimulationManager`、`ExplorationTechnique`、`SimState`、`SimEngine`の機能と意図を理解しなければならないことがあるでしょう！
このドキュメントに合わせて、angrのソースを開いておくとよいでしょう。

各階層で、それぞれの関数は`**kwargs`を受け取り、それを次の関数に渡すため、階層のどのポイントでパラメータを渡しても、その下の関数に伝わります。

## シミュレーションマネージャー

さて、これで解析の準備は整いました。さあ、旅立ちの時です。

### `run()`

`SimulationManager.run()`はいくつかのオプションの引数を取ります。これらはすべて、いつステップのループから抜け出すかをコントロールするものです。
注目すべきは`n`と`until`です。
`n`はすぐに使用されます。run関数はループし、`step()`関数を呼び出して、`n`ステップが発生するか、他の終了条件が満たされるまですべてのパラメータを受け渡します。`n`が指定されない場合は、`until`関数が指定されない限り、デフォルトで 1 が指定され、その場合はループに数値的な上限はありません。
さらに、使用中のスタッシュも考慮され、それが空になると実行を終了します。

つまり、`run()`を呼び出すと、以下のいずれかが満たされるまでループ内で`step()`が呼び出されます。

1. `n`回のステップが経過した。
2. `until`関数がtrueを返した。
3. 探索手法の`complete()`フック（`SimulationManager.completion_mode`パラメーター/属性で指定する: デフォルトでは`any`ビルトイン関数ですが`all`などに変更可能）が解析完了を通知した。
4. 実行中のスタッシュが空になった。

#### `explore()`についての余談

`SimulationManager.explore()`は`run()`の非常に薄いラッパーで、`Explorer`探索手法を追加しています。
そのコード全体は以下のとおりです。

```
num_find += len(self._stashes[find_stash]) if find_stash in self._stashes else 0
tech = self.use_technique(Explorer(find, avoid, find_stash, avoid_stash, cfg, num_find))

try:
    self.run(stash=stash, n=n, **kwargs)
finally:
    self.remove_technique(tech)

return self
```

### 探索手法のフック

ここからは、シミュレーションマネージャーのすべての関数が探索手法によって制御されるようになります。
具体的な仕組みとしては、`SimulationManager.use_technique()`を呼び出すと、angrがシミュレーションマネージャーをモンキーパッチし、探索手法の本体で実装されている関数を、最初に探索手法の関数を呼び出し2回目に元の関数を呼び出す関数に置き換えます。
これは実装がやや面倒でスレッドセーフではありませんが、探索手法がステップ操作を制御するクリーンで強力なインターフェイスとなり、元の関数が呼ばれる前か後に、元の関数を呼ぶかどうかさえ選択できます。
さらに、モンキーパッチされた関数は単に次に適用されるフックにとっての「オリジナル」関数になるので、複数の探索手法が同じ関数をフックすることができます。

### `step()`

`step()`には、縮退したケースを処理するための複雑な処理がたくさんあります。そのほとんどは、`deadended`スタッシュの実装、`save_unsat`オプションの処理、そして`filter()`探索手法フックの呼び出しです。
それらの処理が終わると、`stash`引数で指定されたスタッシュをループして、それぞれの状態に対して`step_state()`を呼び出し、`step_state()`の結果をスタッシュのリストに適用します。
最後に、`step_func`引数が渡されていれば、ステップが終了する前にシミュレーションマネージャーをパラメータとして呼び出します。

### `step_state()`

デフォルトの`step_state()`はシンプルです。`successors()`を呼び出し、`SimSuccessors`オブジェクトを返します。
また、エラー処理も実装しています。`successors()`がエラーを発生させると、それをキャッチして`ErrorRecord`を`SimulationManager.errored`に格納します。

### `successors()`

SimulationManagerからほぼ抜け出せました。
`successors()`は、探索手法によって制御することもできます。状態を取得して前に進め、その後継者を分類した`SimSuccessors`オブジェクトを、スタッシュの処理とは関係なく返すことになっています。
もし`successor_func`引数が指定されていれば、その戻り値が直接返されます。
この引数が指定されていない場合は、`project.factory.successors`メソッドを使用して状態を進め、`SimSuccessors`を取得します。

## エンジン

後継者を生成する段階になったら、実際にどのように実行するかを考える必要があります。
このページに辿り着くまでに、`SimEngine`は状態を受け取ってその後継を生成する方法を知っている装置であると理解できるように、angrのドキュメントが構成されていることを望みます。
「デフォルトエンジン」は1つのプロジェクトに1つしかありませんが、`engine`パラメータを指定することでステップを実行する際にどのエンジンを使用するかを指定できます。

このパラメータは、`.step()`、`.explore()`、`.run()`など実行を開始する関数に対して指定でき、このレベルまでフィルタリングされることを覚えておいてください。
追加されたパラメータは、エンジン内の目的の場所に到達するまで下に渡され続けます。
エンジンは理解できないパラメータはすべて破棄します。

一般的にエンジンのメインエントリーポイントは`SimEngine.process()`で、これは任意の結果を返すことができます。しかしシミュレーションマネージャーの場合、エンジンは`SuccessorsMixin`を使う必要があります。これは`process()`メソッドを提供し、`SimSuccessors`オブジェクトを作ってから `process_successors()`を呼び出し、他のmixinがそれを処理できるようにします。

angrのデフォルトエンジンである`UberEngine`は`process_successors()`メソッドを提供するいくつかのmixinを含んでいます:

- `SimEngineFailure` - 特定のjumpkindに到達した状態を処理します。
- `SimEngineSyscall` - システムコールの実行が必要な状態を処理します。
- `HooksMixin` - フックされたアドレスに到達した際、フックの実行が必要な状態を処理します。
- `SimEngineUnicorn` - Unicornエンジンを使って機械語を実行します。
- `SootMixin` - SOOT IRを介してJavaバイトコードを実行します。
- `HeavyVEXMixin` - VEX IRを介して機械語を実行します。

これらのmixinは、現在の状態を処理できる場合に`SimSuccessors`オブジェクトを埋めるように実装されており、そうでない場合は`super()`を呼び出してスタックの次のクラスに処理を渡します。

## エンジンのmixin

`SimEngineFailure`はエラーとなるケースを処理します。
これは、直前のjumpkindが`Ijk_EmFail`、`Ijk_MapFail`、`Ijk_Sig*`、`Ijk_NoDecode`（ただしアドレスがフックされていない場合のみ）、`Ijk_Exit` のいずれかであるときのみ使用されます。
最初の4つのケースでは、例外を発生させます。
最後のケースでは、後継者を生成しません。

`SimEngineSyscall`はシステムコールを処理します。
これは、直前のjumpkindが`Ijk_Sys*`という形式である場合に使用されます。
`SimOS`を呼び出して、このシステムコールに応答するために実行すべきSimProcedureを取得し、それを実行することで機能します。とてもシンプルですね。

`HooksMixin`はangrのフック機能を提供します。
これは、状態がフックされたアドレスにあり、前のjumpkindが`Ijk_NoHook` *でない* 場合に使用されます。
これは単に関連するSimProcedureを検索し、その状態に対して実行します。
また、引数`procedure`を受け取り、アドレスがフックされていない場合でも、指定されたをプロシージャーを現在のステップで実行します。

`SimEngineUnicorn`は、Unicornエンジンを使用して具体的な実行を行います。
これは、状態のオプション`o.UNICORN`が有効で、最大限の効率を得るために設計された他の無数の条件 (以下で説明) が満たされているときに使用されます。

`SootMixin`はSOOT IR上で実行されます。Javaバイトコードを解析するのでなければ、あまり重要ではありませんが、その場合は非常に重要です。

`SimEngineVEX`は大物です。
前のどれかが使えないときに使います。
これは、現在のアドレスからIRSBにバイトを移動し、そのIRSBをシンボリックに実行しようとします。
このプロセスを制御できるパラメータは膨大な数にのぼるので、それらを説明した[APIリファレンス](http://angr.io/api-doc/angr.html#angr.engines.vex.engine.SimEngineVEX.process)にリンクするだけにしておきます。

SimEngineVEXがIRSBを掘り下げる正確なプロセスは少し複雑ですが、基本的にはブロックのすべてのステートメントを順番に実行します。
このコードは、angrのシンボリック実行の真の内核を見たいのであれば、読む価値があります。

# Unicornエンジンを使う場合

`o.UNICORN`状態オプションを追加すると、各ステップで`SimEngineUnicorn`が呼び出され、具体的な実行のためにUnicornを使用できるかどうかを確認します。

必要なのは、定義済みのオプションセット`o.unicorn`（小文字）を状態に追加することです。

```python
unicorn = { UNICORN, UNICORN_SYM_REGS_SUPPORT, INITIALIZE_ZERO_REGISTERS, UNICORN_HANDLE_TRANSMIT_SYSCALL }
```

これらは、いくつかの追加機能とデフォルトを有効にし、あなたの体験を大きく向上させます。
さらに、`state.unicorn`プラグインで調整できるオプションはたくさんあります。

unicornがどのように動作するかを理解するには、unicornのサンプル実行からのログ出力（`logging.getLogger('angr.engines.unicorn_engine').setLevel('DEBUG'); logging.getLogger('angr.state_plugins.unicorn_engine').setLevel('DEBUG')`）を検証してみるとよいでしょう。

```
INFO    | 2017-02-25 08:19:48,012 | angr.state_plugins.unicorn | started emulation at 0x4012f9 (1000000 steps)
```

ここで、angrはUnicornエンジンに分岐し、0x4012f9の基本ブロックから開始します。
最大ステップ数は1000000に設定されているので、1000000個のブロックがUnicornで実行されると、自動的にangrに処理が戻ります。
これは、無限ループに陥るのを避けるためです。
ブロック数は変数`state.unicorn.max_steps`で設定可能です。

```
INFO    | 2017-02-25 08:19:48,014 | angr.state_plugins.unicorn | mmap [0x401000, 0x401fff], 5 (symbolic)
INFO    | 2017-02-25 08:19:48,016 | angr.state_plugins.unicorn | mmap [0x7fffffffffe0000, 0x7fffffffffeffff], 3 (symbolic)
INFO    | 2017-02-25 08:19:48,019 | angr.state_plugins.unicorn | mmap [0x6010000, 0x601ffff], 3
INFO    | 2017-02-25 08:19:48,022 | angr.state_plugins.unicorn | mmap [0x602000, 0x602fff], 3 (symbolic)
INFO    | 2017-02-25 08:19:48,023 | angr.state_plugins.unicorn | mmap [0x400000, 0x400fff], 5
INFO    | 2017-02-25 08:19:48,025 | angr.state_plugins.unicorn | mmap [0x7000000, 0x7000fff], 5
```

angrは、Unicornエンジンがアクセスするデータに対して遅延マッピングを行います。たとえば、0x401000は実行中の命令のページ、0x7fffffffe0000はスタック、といった具合です。これらのページのいくつかはシンボリックであり、アクセスするとUnicornの実行を中断させるようなデータを少なくとも含んでいます。

```
INFO    | 2017-02-25 08:19:48,037 | angr.state_plugins.unicorn | finished emulation at 0x7000080 after 3 steps: STOP_STOPPOINT
```

3つの基本ブロックがUnicornで実行され（必要な設定を考慮すると、計算の無駄）、その後simprocedureの場所に到達し、angrのsimprocを実行するために処理を戻します。

```
INFO    | 2017-02-25 08:19:48,076 | angr.state_plugins.unicorn | started emulation at 0x40175d (1000000 steps)
INFO    | 2017-02-25 08:19:48,077 | angr.state_plugins.unicorn | mmap [0x401000, 0x401fff], 5 (symbolic)
INFO    | 2017-02-25 08:19:48,079 | angr.state_plugins.unicorn | mmap [0x7fffffffffe0000, 0x7fffffffffeffff], 3 (symbolic)
INFO    | 2017-02-25 08:19:48,081 | angr.state_plugins.unicorn | mmap [0x6010000, 0x601ffff], 3
```

simprocedureの後、実行はUnicornに戻ります。

```
WARNING | 2017-02-25 08:19:48,082 | angr.state_plugins.unicorn | fetching empty page [0x0, 0xfff]
INFO    | 2017-02-25 08:19:48,103 | angr.state_plugins.unicorn | finished emulation at 0x401777 after 1 steps: STOP_EXECNONE
```

バイナリがゼロページにアクセスしたため、実行はほぼすぐにUnicornから戻されます。

```
INFO    | 2017-02-25 08:19:48,120 | angr.engines.unicorn_engine | not enough runs since last unicorn (100)
INFO    | 2017-02-25 08:19:48,125 | angr.engines.unicorn_engine | not enough runs since last unicorn (99)
```

Unicornの実行がsimprocedureやシステムコール以外で中断された場合、Unicornに戻る前に特定の条件（Xブロックの間、シンボリックメモリーへのアクセスがないなど）が満たされるまで待機するクールダウン（`state.unicorn`プラグインの属性）が用意されています。
ここでは、Unicornへ戻る前に100個のブロックが実行されることを待っています。
