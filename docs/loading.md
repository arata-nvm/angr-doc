# バイナリのロード - CLEとangrのProject

ここまで、angrのロード機能のほんの一部を見ただけでした。`/bin/true`をロードし、共有ライブラリなしで再度ロードしました。また、`proj.loader`ができるいくつかのことを見てきました。では、これらのインターフェイスのニュアンスと、それらが教えてくれることについて深堀りしてみましょう。

バイナリをロードするangrのコンポーネントであるCLEについて簡単に触れました。CLEは"CLE Loads Everything"の略で、バイナリ（とそれが依存するすべてのライブラリ）を受け取り、それを扱いやすい形でangrの残りの部分に渡す役割を担っています。

## Loader

`examples/fauxware/fauxware`をロードして、ローダーを扱う方法を詳しく見てみましょう。

```python
>>> import angr, monkeyhex
>>> proj = angr.Project('examples/fauxware/fauxware')
>>> proj.loader
<Loaded fauxware, maps [0x400000:0x5008000]>
```

### ロードしたオブジェクト

CLEローダー（`cle.Loader`）は単一のメモリ空間にロードおよびマップされた、 _バイナリオブジェクト_ の全体を表します。
それぞれのバイナリオブジェクトは、そのファイル形式を処理できるローダーバックエンド（`cle.Backend`のサブクラス）によってロードされます。
たとえば、`cle.ELF`はELFバイナリをロードするために使用されます。

ロードされたバイナリに関係ないオブジェクトもメモリ内に存在します。
たとえば、スレッドローカルストレージのサポートを提供するために使用されるオブジェクトや、未解決のシンボルを提供するために使用されるexternsオブジェクトがあります。

CLEがロードしたオブジェクトのすべてのリストは`loader.all_objects`で取得できます。また、さらに対象を絞ったいくつかの分類もあります。

```python
# 読み込まれたすべてのオブジェクト
>>> proj.loader.all_objects
[<ELF Object fauxware, maps [0x400000:0x60105f]>,
 <ELF Object libc-2.23.so, maps [0x1000000:0x13c999f]>,
 <ELF Object ld-2.23.so, maps [0x2000000:0x2227167]>,
 <ELFTLSObject Object cle##tls, maps [0x3000000:0x3015010]>,
 <ExternObject Object cle##externs, maps [0x4000000:0x4008000]>,
 <KernelObject Object cle##kernel, maps [0x5000000:0x5008000]>]

# プロジェクトをロードするときに直接指定した「メイン」オブジェクト
>>> proj.loader.main_object
<ELF Object fauxware, maps [0x400000:0x60105f]>

# 共有オブジェクト名からオブジェクトへの辞書
>>> proj.loader.shared_objects
{ 'fauxware': <ELF Object fauxware, maps [0x400000:0x60105f]>,
  'libc.so.6': <ELF Object libc-2.23.so, maps [0x1000000:0x13c999f]>,
  'ld-linux-x86-64.so.2': <ELF Object ld-2.23.so, maps [0x2000000:0x2227167]> }

# ELFファイルからロードされたすべてのオブジェクト
# これがWindowsプログラムの場合、all_pe_objectsを使用します！
>>> proj.loader.all_elf_objects
[<ELF Object fauxware, maps [0x400000:0x60105f]>,
 <ELF Object libc-2.23.so, maps [0x1000000:0x13c999f]>,
 <ELF Object ld-2.23.so, maps [0x2000000:0x2227167]>]

# 未解決のインポートとangr内部のアドレスを提供するために使用する「externsオブジェクト」
>>> proj.loader.extern_object
<ExternObject Object cle##externs, maps [0x4000000:0x4008000]>

# エミュレートされたシステムコールのアドレスを提供するために使用するオブジェクト
>>> proj.loader.kernel_object
<KernelObject Object cle##kernel, maps [0x5000000:0x5008000]>

# アドレスを指定してオブジェクトへの参照を取得できます
>>> proj.loader.find_object_containing(0x400000)
<ELF Object fauxware, maps [0x400000:0x60105f]>
```

これらのオブジェクトを直接操作して、メタデータを抽出できます:

```python
>>> obj = proj.loader.main_object

# オブジェクトのエントリポイント
>>> obj.entry
0x400580

>>> obj.min_addr, obj.max_addr
(0x400000, 0x60105f)

# ELFのセグメントとセクションを取得します
>>> obj.segments
<Regions: [<ELFSegment memsize=0xa74, filesize=0xa74, vaddr=0x400000, flags=0x5, offset=0x0>,
           <ELFSegment memsize=0x238, filesize=0x228, vaddr=0x600e28, flags=0x6, offset=0xe28>]>
>>> obj.sections
<Regions: [<Unnamed | offset 0x0, vaddr 0x0, size 0x0>,
           <.interp | offset 0x238, vaddr 0x400238, size 0x1c>,
           <.note.ABI-tag | offset 0x254, vaddr 0x400254, size 0x20>,
            ...etc
            
# 特定のアドレスを含むセグメントやセクションを取得できます:
>>> obj.find_segment_containing(obj.entry)
<ELFSegment memsize=0xa74, filesize=0xa74, vaddr=0x400000, flags=0x5, offset=0x0>
>>> obj.find_section_containing(obj.entry)
<.text | offset 0x580, vaddr 0x400580, size 0x338>

# シンボルのPLTエントリのアドレスを取得します
>>> addr = obj.plt['strcmp']
>>> addr
0x400550
>>> obj.reverse_plt[addr]
'strcmp'

# リンク時に設定されたオブジェクトのベースアドレスと、CLEによって実際にメモリにマッピングされるアドレスを表示します
>>> obj.linked_base
0x400000
>>> obj.mapped_base
0x400000
```

### シンボルと再配置

また、CLEを使用してシンボルを扱うこともできます。
シンボルは実行可能ファイル形式の世界では基本的な概念で、名前とアドレスを効率的に対応させます。

CLEからシンボルを取得するもっとも簡単な方法は`loader.find_symbol`で、名前かアドレスを受け取ってSymbolオブジェクトを返します。

```python
>>> strcmp = proj.loader.find_symbol('strcmp')
>>> strcmp
<Symbol "strcmp" in libc.so.6 at 0x1089cd0>
```

シンボルのもっとも便利な属性は、名前、所有者、アドレスですが、シンボルの「アドレス」は曖昧な場合があります。
Symbolオブジェクトはアドレスを知るための3つの方法を持っています:

- `.rebased_addr`はグローバルアドレス空間におけるアドレスです。これはprintの出力に表示されるアドレスです。
- `.linked_addr`はバイナリがリンクされたベースアドレスからの相対的なアドレスです。これはたとえば`readelf(1)`で表示されるアドレスです。
- `.relative_addr`はオブジェクトのベースからの相対的なアドレスです。これは文献（とくにWindowsの文献）ではRVA（Relative Virtual Address）として知られています。

```python
>>> strcmp.name
'strcmp'

>>> strcmp.owner
<ELF Object libc-2.23.so, maps [0x1000000:0x13c999f]>

>>> strcmp.rebased_addr
0x1089cd0
>>> strcmp.linked_addr
0x89cd0
>>> strcmp.relative_addr
0x89cd0
```

シンボルはデバッグ情報のほか、動的リンクに関する情報も提供します。
libcはstrcmpシンボルをエクスポートし、メインバイナリはそれに依存しています。
もしメインオブジェクトから直接strcmpのシンボルを取得すると、これは _インポートシンボル_ であるとCLEに言われるでしょう。
インポートシンボルに意味のあるアドレスは関連付けられていませんが、`.resolvedby`として解決されたシンボルへの参照を提供します。

```python
>>> strcmp.is_export
True
>>> strcmp.is_import
False

# Loaderではシンボルを見つけるために検索操作を行うため、メソッドはfind_symbolを使います。
# 個々のオブジェクトでは与えられた名前のシンボルは1つしかないため、メソッドはget_symbolを使います。
>>> main_strcmp = proj.loader.main_object.get_symbol('strcmp')
>>> main_strcmp
<Symbol "strcmp" in fauxware (import)>
>>> main_strcmp.is_export
False
>>> main_strcmp.is_import
True
>>> main_strcmp.resolvedby
<Symbol "strcmp" in libc.so.6 at 0x1089cd0>
```

インポートとエクスポートの間のリンクをメモリ上に登録する具体的な方法は、 _再配置_ という別の概念で処理されます。
再配置とは、「 _\[インポート\]_ とエクスポートのシンボルをマッチングさせたとき、エクスポートのアドレスを _\[ロケーション\]_ に _\[フォーマット\]_ の形式で書き込んでください」というものです。
オブジェクトの再配置の全一覧は、`obj.relocs`として（`Relocation`のインスタンスとして）見ることができ、シンボル名から再配置へのマッピングだけを`obj.imports`として見ることもできます。
エクスポートシンボルに対応する一覧はありません。

再配置に対応するインポートシンボルには`.symbol`としてアクセスできます。
再配置によって書き込まれるアドレスにはSymbolで使用できる任意のアドレス識別子からアクセスでき、再配置を要求するオブジェクトへの参照は`.owner`から取得できます。

```python
# Relocationはうまくpretty-printできないため、これらのアドレスはPython内部のもので、私達のプログラムとは関係ありません
>>> proj.loader.shared_objects['libc.so.6'].imports
{'__libc_enable_secure': <cle.backends.elf.relocation.amd64.R_X86_64_GLOB_DAT at 0x7ff5c5fce780>,
 '__tls_get_addr': <cle.backends.elf.relocation.amd64.R_X86_64_JUMP_SLOT at 0x7ff5c6018358>,
 '_dl_argv': <cle.backends.elf.relocation.amd64.R_X86_64_GLOB_DAT at 0x7ff5c5fd2e48>,
 '_dl_find_dso_for_object': <cle.backends.elf.relocation.amd64.R_X86_64_JUMP_SLOT at 0x7ff5c6018588>,
 '_dl_starting_up': <cle.backends.elf.relocation.amd64.R_X86_64_GLOB_DAT at 0x7ff5c5fd2550>,
 '_rtld_global': <cle.backends.elf.relocation.amd64.R_X86_64_GLOB_DAT at 0x7ff5c5fce4e0>,
 '_rtld_global_ro': <cle.backends.elf.relocation.amd64.R_X86_64_GLOB_DAT at 0x7ff5c5fcea20>}
```

共有ライブラリが見つからないなどの理由からインポートがどのエクスポートでも解決できない場合、CLEは自動的にexternsオブジェクト（`loader.extern_obj`）を更新して、そのシンボルがエクスポートとして提供されているものとして扱います。

## ローディングの設定

`angr.Project`で何かをロードするときに、Projectによって暗黙的に生成される`cle.Loader`のインスタンスにオプションを渡したい場合、Projectのコンストラクターにキーワード引数を直接渡せばそれがCLEに渡されます。
渡すことができるすべてのオプションを知りたい場合は[CLE APIドキュメント](http://angr.io/api-doc/cle.html)を参照すべきですが、ここでは重要かつ頻繁に利用されるオプションについて説明します。

#### 基本的なオプション

`auto_load_libs`についてはすでに説明しましたが、これはCLEが共有ライブラリの依存関係を自動で解決しようとするのを有効または無効にするもので、デフォルトでは有効になっています。
さらに、その反対として`except_missing_libs`があり、これをtrueに設定するとバイナリがもつ共有ライブラリの依存関係が解決できなかった場合に例外がスローされます。

`force_load_libs`に文字列のリストを渡すと、リストに含まれる名前の共有ライブラリへの依存関係はすべて未解決として扱われます。また、`skip_libs`に文字列のリストを渡すと、その名前のライブラリが依存関係として解決されないようにします。
さらに、文字列のリスト（あるいは1つの文字列）を`ld_path`に渡すと、共有ライブラリの検索パスとして使用されます。これはデフォルトの検索パス（ロードされたプログラムと同じディレクトリ、現在の作業ディレクトリ、システムライブラリ）よりも優先されます。

#### バイナリごとのオプション

CLEでは特定のバイナリオブジェクトにのみ適用されるオプションを指定することも可能です。引数の`main_opts`と`lib_opts`がこれらのオプションを辞書として受け取ります。`main_opts`はオプション名からオプションの値へのマッピングで、`lib_opts`はライブラリ名からオプション名とオプションの値をマッピングした辞書へのマッピングです。

使用できるオプションはバックエンドによって異なりますが、一般的なものを紹介します:

* `backend` - 使用するバックエンドをクラス名か名前で指定します
* `base_addr` - 使用するベースアドレス
* `entry_point` - 使用するエントリポイント
* `arch` - 使用するアーキテクチャの名前

例:

```python
>>> angr.Project('examples/fauxware/fauxware', main_opts={'backend': 'blob', 'arch': 'i386'}, lib_opts={'libc.so.6': {'backend': 'elf'}})
<Project examples/fauxware/fauxware>
```

### バックエンド

現在CLEは、ELF、PE、CGC、Mach-O、ELFコアダンプファイルを静的にロードするバックエンドと、フラットアドレス空間へファイルをロードするバックエンドを備えています。CLEはほとんどの場合、使用する正しいバックエンドを自動で検出するため、かなり奇妙なことをしないかぎり、使用するバックエンドを指定する必要はありません。

CLEが特定のバックエンドを使用するよう強制するには、上記のようにオプションの辞書にキーを含めます。バックエンドの中には、どのアーキテクチャを使用するかを自動検出できないものがあり、`arch`を _必ず_ 指定する必要があります。このキーはアーキテクチャのリストと一致する必要はありません。angrは、サポートされているアーキテクチャのほとんどすべての共通識別子から、あなたがどのアーキテクチャを指しているかを特定します。

バックエンドを指定するには、この表の名前を使います:

| バックエンド名| 説明 | `arch`が必要か？ |
| --- | --- | --- |
| elf | PyELFToolsに基づくELFファイル用の静的ローダー | いいえ |
| pe | PEFileに基づくPEファイル用の静的ローダー | いいえ |
| mach-o | Mach-Oファイル用の静的ローダー。動的リンクやリベースはサポートしない。 | いいえ |
| cgc | Cyber Grand Challengeバイナリ用の静的ローダー | いいえ |
| backedcgc | メモリとレジスタのバッカーを指定できるCGCバイナリ用の静的ローダー | いいえ |
| elfcore | ELFコアダンプ用の静的ローダー | いいえ |
| blob | ファイルをフラットイメージとしてロードする | はい |

## 関数のサマリー

デフォルトでは、Projectは _SimProcedures_ と呼ばれるシンボリックサマリーを使用して、ライブラリ関数への外部呼び出しを置き換えようとします。これは事実上、ライブラリ関数による状態への変化を模倣する単なるPythonの関数です。私達は[多くの関数](https://github.com/angr/angr/tree/master/angr/procedures)をSimProcedureとして実装しています。これらのビルトイン関数は`angr.SIM_PROCEDURES`辞書から利用できます。この辞書は2つの階層に分かれており、最初にパッケージ名（libc、posix、win32、stubs）、次にライブラリ関数の名前をキーにしています。システムからロードされる実際のライブラリ関数の代わりにSimProcedureを実行することで解析が非常に容易になりますが、その代償として[不正確である可能性もあります](/docs/gotchas.md)。

ある関数について、そのようなサマリーが利用できない場合:

* `auto_load_libs`が`True`の場合（デフォルト）、代わりに _実際の_ ライブラリ関数が実行されます。これは、実際の関数によって、望むものであったりそうでなかったりします。たとえば、libcの関数の中には解析が非常に困難なものがあり、それを実行しようとするパスの状態数が爆発的に増加する可能性が高いです。
* `auto_load_libs`が`False`の場合、外部関数を未解決とし、Projectは`ReturnUnconstrained`と呼ばれる汎用「スタブ」SimProcedureとして解決します。これはその名のとおり、呼び出されるたびに制約のない一意なシンボリック値を返します。
* `use_sim_procedures`（`cle.Loader`ではなく`angr.Project`の引数）が`False`（デフォルトは`True`）の場合、externsオブジェクトによって提供されるシンボルのみがSimProceduresへの置換の対象となり、何もせずシンボリック値を返すスタブSimProcedureで置き換えられます。
* `angr.Project`の引数`exclude_sim_procedures_list`と`exclude_sim_procedures_func`によって、SimProcedureに置き換えないシンボルを指定できます。
* 正確なアルゴリズムは`angr.Project._register_object`のコードを参照してください。

#### フック

angrがライブラリのコードをPythonのサマリーに書き換える仕組みはフックと呼ばれていて、あなたも使うことができます！シミュレーションを行う際、angrは各ステップで現在のアドレスがフックされているかどうかを確認し、フックされていればそのアドレスのバイナリコードの代わりにフックを実行します。これを行うためのAPIは`proj.hook(addr, hook)`で、`hook`はSimProcedureのインスタンスです。プロジェクトのフックは`.is_hooked`、`.unhook`、`.hooked_by`で管理できますが、説明は不要でしょう。

アドレスをフックするための代替APIとして、`proj.hook(addr)`を関数デコレータとして使用することでフックとして使用する独自の即席の関数を指定できます。この場合、`length`キーワード引数をオプションとして指定し、フック終了後に実行するアドレスを何バイトか先にジャンプさせることも可能です。

```python
>>> stub_func = angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained'] # これはクラスです
>>> proj.hook(0x10000, stub_func())  # クラスのインスタンスでフックします

>>> proj.is_hooked(0x10000)            # これらの関数はほとんど自明なはずです
True
>>> proj.hooked_by(0x10000)
<ReturnUnconstrained>
>>> proj.unhook(0x10000)

>>> @proj.hook(0x20000, length=5)
... def my_hook(state):
...     state.regs.rax = 1

>>> proj.is_hooked(0x20000)
True
```

さらに、`proj.hook_symbol(name, hook)`の最初の引数にシンボルの名前を渡して呼び出すと、そのシンボルが存在するアドレスをフックできます。
この関数の非常に重要な使い方の1つは、angrのビルトインライブラリのSimProcedureの挙動を拡張することです。
これらのライブラリ関数は単なるクラスなので、サブクラス化して動作の一部をオーバーライドし、そのサブクラスをフックで使用できます。

## いまのところ順調です！

ここまでで、CLEローダーとangrのProjectのレベルで、解析が行われる環境を制御する方法について理解されたことでしょう。
また、angrは複雑なライブラリ関数を、関数の効果を要約するSimProcedureにフックすることで分析を単純化する合理的な試みを行っていることも理解していただけると思います。

CLEローダーとそのバックエンドでできることをすべて見るには、[CLE APIドキュメント](http://angr.io/api-doc/cle.html)を参照してください。
