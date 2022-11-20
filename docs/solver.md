# シンボリック式と制約解消

angrはエミュレーターではなく、 _シンボリック変数_ と呼ばれるものを使って実行できるのが特徴です。
_具体的な_ 数値を持つ変数ではなく、 _シンボル_ 、つまり名前だけを持つ変数と言えます。
そして、その変数に対して算術演算を行うと、演算を表す木（コンパイラ理論から _Abstract Syntax Tree_ 、 _AST_ と呼ばれます）を得ることができます。
ASTはz3などの _SMTソルバー_ で、 _「この一連の演算の出力が与えられたとき、入力は何でなければならなかったか」_ という質問をするための制約に変換できます。
ここでは、これに答えるためのangrの使い方を学びます。

## ビットベクトルを使用する

ダミーのプロジェクトと状態を用意して、数字で遊んでみましょう。

```python
>>> import angr, monkeyhex
>>> proj = angr.Project('/bin/true')
>>> state = proj.factory.entry_state()
```

ビットベクトルは単なるビットの並びで、算術用のbounded integerのセマンティクスで解釈されます。
いくつか作ってみましょう。

```python
# 1と100の具体的な値を持つ64bitのビットベクトル
>>> one = state.solver.BVV(1, 64)
>>> one
 <BV64 0x1>
>>> one_hundred = state.solver.BVV(100, 64)
>>> one_hundred
 <BV64 0x64>

# 9の具体的な値を持つ27bitのビットベクトル
>>> weird_nine = state.solver.BVV(9, 27)
>>> weird_nine
<BV27 0x9>
```

このように任意のビット列を作ることができ、これらをビットベクトルと呼びます。
これらを使って計算もできます:

```python
>>> one + one_hundred
<BV64 0x65>

# Pythonの整数をすると、適切な型に強制されます:
>>> one_hundred + 0x100
<BV64 0x164>

# 通常のラップアラウンドを含む算術演算のセマンティクスが適用されます
>>> one_hundred - one*200
<BV64 0xffffffffffffff9c>
```

`one + weird_nine`と言うことはできません。
異なる長さのビットベクトルに対して演算を行うと型エラーになります。
しかし、`weird_nine`を拡張して適切なビット数を持つようにすることは可能です:

```python
>>> weird_nine.zero_extend(64 - 27)
<BV64 0x9>
>>> one + weird_nine.zero_extend(64 - 27)
<BV64 0xa>
```

`zero_extend`はビットベクトルの左側を指定された数のゼロビットで埋めます。
また`sign_extend`は最上位ビットと同じ値で埋め、2の補数符号付き整数のセマンティクスのもとでビットベクトルの値を保持できます。

さて、ここでいくつかのシンボルを導入してみましょう。

```python
# 長さ64ビットのビットベクトルのシンボル"x"を作成する
>>> x = state.solver.BVS("x", 64)
>>> x
<BV64 x_9_64>
>>> y = state.solver.BVS("y", 64)
>>> y
<BV64 y_10_64>
```

現在`x`と`y`は _シンボリック変数_ になっています。これは、あなたが7年生の代数の授業で習った変数のようなものです。
指定された名前にインクリメントカウンターが追加され、マングルされていることに注意してください。
これらを使っていくらでも算術演算ができますが、数値は返ってこず、代わりにASTが返ってきます。

```python
>>> x + one
<BV64 x_9_64 + 0x1>

>>> (x + one) / 2
<BV64 (x_9_64 + 0x1) / 0x2>

>>> x - y
<BV64 x_9_64 - y_10_64>
```

技術的には`x`も`y`も`one`もASTです。木の深さが1層であっても、すべてのビットベクトルは演算を表す木です。
これを理解するために、ASTの処理方法について学びましょう。

それぞれのASTは`.op`と`.args`を持ちます。
opは実行される操作の名前を示す文字列で、argsはその操作が入力として受け取る値です。
opが`BVV`や`BVS`（と、他のいくつか…）でない限り、argsはすべて他のASTで、木は最終的にBVVやBVSで終端します。

```python
>>> tree = (x + 1) / (y + 2)
>>> tree
<BV64 (x_9_64 + 0x1) / (y_10_64 + 0x2)>
>>> tree.op
'__floordiv__'
>>> tree.args
(<BV64 x_9_64 + 0x1>, <BV64 y_10_64 + 0x2>)
>>> tree.args[0].op
'__add__'
>>> tree.args[0].args
(<BV64 x_9_64>, <BV64 0x1>)
>>> tree.args[0].args[1].op
'BVV'
>>> tree.args[0].args[1].args
(1, 64)
```

今後は、最上位の演算がビットベクトルのを生成するASTを指して「ビットベクトル」という言葉を使うことにします。
ASTで表現されるデータ型は他にもあり、浮動小数点数や、これから見るようなブーリアンも含まれます。

## 制約

2つの同じような型のASTで比較演算を行うと、ビットベクトルではなくsymbolic booleanが得られます。

```python
>>> x == 1
<Bool x_9_64 == 0x1>
>>> x == one
<Bool x_9_64 == 0x1>
>>> x > 2
<Bool x_9_64 > 0x2>
>>> x + y == one_hundred + 5
<Bool (x_9_64 + y_10_64) == 0x69>
>>> one_hundred > 5
<Bool True>
>>> one_hundred > -5
<Bool False>
```

この例からわかることは、デフォルトで比較が符号無しで行われるということです。
最後の例の-5は`<BV64 0xfffffffffffffffb>`に強制されますが、これは間違いなく100より小さい値ではありません。
もし比較を符号有りにしたいならば、`one_hundred.SGT(-5z)`（これは"signed greater-than"です）と言えばよいでしょう。
演算の全一覧はこの章の最後にあります。

このスニペットは、angrを使用する際の重要な点も示しています。
演算の結果が具体的な真理値を持っていない場合があるため、if文やwhile文の条件に変数間の比較を直接使ってはいけません。
具体的な真理値を持っていたとしても、`if one > one_hundred`は例外が発生します。
代わりに、制約解消をせずに具体的な真偽をテストする`solver.is_true`と`solver.is_false`を使うべきです。

```python
>>> yes = one == 1
>>> no = one == 2
>>> maybe = x == y
>>> state.solver.is_true(yes)
True
>>> state.solver.is_false(yes)
False
>>> state.solver.is_true(no)
False
>>> state.solver.is_false(no)
True
>>> state.solver.is_true(maybe)
False
>>> state.solver.is_false(maybe)
False
```

## 制約解消

任意のsymbolic booleanを状態の _制約_ として追加することで、シンボリック変数の有効な値についてのアサーションとして扱うことができます。
そして、シンボリック式の評価を求めることで、シンボリック変数の有効な値を得ることができます。

ここでは、説明するよりも例を挙げたほうがわかりやすいでしょう:

```python
>>> state.solver.add(x > y)
>>> state.solver.add(y > 2)
>>> state.solver.add(10 > x)
>>> state.solver.eval(x)
4
```

このように制約を状態に追加することで、制約ソルバーが返すすべての値について満たすべきアサーションとしてみなすように強制しました。
このコードを実行するとxの値は異なるかもしれませんが、その値は3より大きく（yは2より大きく、xはyより大きいため）、10より小さくなるはずです。
さらに、`state.solver.eval(y)`を実行すると、xの値に応じたふさわしいyの値が得られます。
もし2つのクエリの間に制約を加えなければ、結果は互いに整合性があるものになるはずです。

ここから、冒頭で提案した課題、つまり与えられた出力を生み出す入力を見つける方法を簡単に理解できます。

```python
# 制約のない新しい状態を得る
>>> state = proj.factory.entry_state()
>>> input = state.solver.BVS('input', 64)
>>> operation = (((input + 4) * 3) >> 1) + input
>>> output = 200
>>> state.solver.add(operation == output)
>>> state.solver.eval(input)
0x3333333333333381
```

繰り返しになりますが、この解はビットベクトルのセマンティクスにおいてのみ有効であることに注意してください。
もし整数の範囲で操作した場合、解は存在しないでしょう！

制約を満たす変数の値がないような矛盾した制約を追加した場合、その状態は _充足できない_ あるいはunsatとなり、これに対するクエリは例外を発生させます。
状態が充足可能であるかどうかは`state.satisfiable()`で確認できます。

```python
>>> state.solver.add(input < 2**32)
>>> state.satisfiable()
False
```

また、単一の変数だけでなく、複雑な式を評価することもできます。

```python
# 新しい状態
>>> state = proj.factory.entry_state()
>>> state.solver.add(x - y >= 4)
>>> state.solver.add(y > 0)
>>> state.solver.eval(x)
5
>>> state.solver.eval(y)
1
>>> state.solver.eval(x + y)
6
```

このことから、`eval`は任意のビットベクトルを状態の整合性を保ちながらPythonのプリミティブに変換できる汎用的なメソッドであることがわかります。
このため、具体的なビットベクトルからPythonのintへの変換も`eval`を使って行います！

またxとyの変数は古い状態を使用して作成されたにもかかわらず、この新しい状態で使用できることに注意してください。
変数はどの状態にも縛られることなく、自由に存在できます。

## 浮動小数点数

z3はIEEE754浮動小数点数の理論をサポートしているため、angrでも同様に使用できます。
ビットベクトルとの主な違いは、幅の代わりに浮動小数点数には _種類_ があることです。
`FPV`や`FPS`で浮動小数点数のシンボルや値を作成できます。

```python
# 新しい状態
>>> state = proj.factory.entry_state()
>>> a = state.solver.FPV(3.2, state.solver.fp.FSORT_DOUBLE)
>>> a
<FP64 FPV(3.2, DOUBLE)>

>>> b = state.solver.FPS('b', state.solver.fp.FSORT_DOUBLE)
>>> b
<FP64 FPS('FP_b_0_64', DOUBLE)>

>>> a + b
<FP64 fpAdd('RNE', FPV(3.2, DOUBLE), FPS('FP_b_0_64', DOUBLE))>

>>> a + 4.4
<FP64 FPV(7.6000000000000005, DOUBLE)>

>>> b + 2 < 0
<Bool fpLT(fpAdd('RNE', FPS('FP_b_0_64', DOUBLE), FPV(2.0, DOUBLE)), FPV(0.0, DOUBLE))>
```

まず、ここで少し説明することがあります。はじめに、浮動小数点数のpretty-printはそれほどきちんとしていません。
そしてほとんどの演算は、二項演算子を使用する際に暗黙的に追加される、丸めモードを第3のパラメーターとして持っています。
IEEE754仕様では複数の丸めモード（round-to-nearest、round-to-zero、round-to-positiveなど）をサポートしているため、z3もそれらをサポートしなければなりません。
もし演算の丸めモードを指定したい場合は、丸めモード（`solver.fp.RM_*`のいずれか）を第1引数に渡して、明示的にfp演算（たとえば`solver.fpAdd`）を使用してください。

ビットベクトルと同じように制約と解を扱うことができますが、`eval`は浮動小数点数を返します:

```python
>>> state.solver.add(b + 2 < 0)
>>> state.solver.add(b + 2 > -1)
>>> state.solver.eval(b)
-2.4999999999999996
```

これはよいことなのですが、floatのビットベクトルとしての表現を直接操作したい場合があります。
`raw_to_bv`と`raw_to_fp`というメソッドを使うことで、ビットベクトルをfloatとして解釈したり、その逆をしたりできます。

```python
>>> a.raw_to_bv()
<BV64 0x400999999999999a>
>>> b.raw_to_bv()
<BV64 fpToIEEEBV(FPS('FP_b_0_64', DOUBLE))>

>>> state.solver.BVV(0, 64).raw_to_fp()
<FP64 FPV(0.0, DOUBLE)>
>>> state.solver.BVS('x', 64).raw_to_fp()
<FP64 fpToFP(x_1_64, DOUBLE)>
```

これらの変換はfloatポインターをintポインターにキャストした場合、またはその逆の場合のようにビットパターンを保持します。
しかし、floatをintにキャストする（あるいはその逆）ように、できるだけ値の精度を保って変換したい場合には`val_to_fp`と`val_to_bv`という別のメソッド群を使用できます。
これらのメソッドは浮動小数点数の性質上、対象となる値のサイズや種類と引数として渡す必要があります。

```python
>>> a
<FP64 FPV(3.2, DOUBLE)>
>>> a.val_to_bv(12)
<BV12 0x3>
>>> a.val_to_bv(12).val_to_fp(state.solver.fp.FSORT_FLOAT)
<FP32 FPV(3.0, FLOAT)>
```

これらのメソッドは`signed`引数をとり、ソースまたはターゲットのビットベクトルの符号を指定することもできます。

## 解を求めるその他のメソッド

`eval`は式の解を1つだけ与えてくれますが、複数の解が欲しい場合はどうすればよいでしょうか？
また、解が一意であることを確認したい場合はどうすればよいでしょうか？
ソルバーには、一般的な解のパターンに対するいくつかのメソッドが用意されています:

- `solver.eval(expression)`は与えられた式に対する1つの考えられる解を返します。
- `solver.eval_one(expression)`は与えられた式の解を返しますが、複数の解がある場合にはエラーを投げます。
- `solver.eval_upto(expression, n)`は与えられた式の解を最大n個まで返し、可能な解の個数がn個より少ない場合はn個未満の解を返します。
- `solver.eval_atleast(expression, n)`は与えられた式の解をn個返し、解がn個より少ない場合はエラーを投げます。
- `solver.eval_exact(expression, n)`は与えられた式の解をn個返し、n個より少ないか多い場合はエラーを投げます。
- `solver.min(expression)`は与えられた式において考えられる最小の解を返します。
- `solver.max(expression)`は与えられた式において考えられる最大の解を返します。

さらに、これらのメソッドはすべて以下のキーワード引数を渡すことができます:

- `extra_constraints`には制約のタプルを渡すことができます。
  これらの制約は呼び出し時の評価において考慮されますが、状態には追加されません。
- `cast_to`には結果をキャストするためのデータ型を渡すことができます。
  現在のところ`int`と`bytes`のみを渡すことができ、これによりメソッドはデータに対応する表現を返します。

## サマリー

すごい量でした！！
これを読んであなたはビットベクトル、ブーリアン、浮動小数点数を作成して操作し、演算の木を形成し、制約の下で考えられる解を状態に付随する制約ソルバへ聞くことができるようになるはずです。
この時点で、計算を表現するためにASTを使用することの威力と、制約ソルバーの力を理解していただけたと思います。

[付録には](appendices/ops.md)、ASTに適用できるすべての演算のリファレンスが表として掲載されており、手早く確認できます。
