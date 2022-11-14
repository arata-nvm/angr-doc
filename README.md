# angrとは何か、どのように使うのか

angrはマルチアーキテクチャ対応のバイナリ解析ツールキットであり、動的シンボリック実行（Mayhem、KLEEなど）とさまざまな静的解析を実行する機能を備えています。使い方を知りたいなら、ぜひ参考にしてください！

私たちは、angrをできるだけ簡単に使用できるよう努めてきました。私達の目標は、ユーザーフレンドリーなバイナリ解析スイートを構築することです。これにより、ユーザーはIPythonを起動するだけで、いくつかのコマンドでバイナリ解析を簡単に行えるようになります。そうは言っても、バイナリ解析は複雑であり、それがangrを複雑にしています。このドキュメントは、angrとその設計について物語的に説明し、探求していくことで、それを支援する試みです。

プログラムでバイナリを解析するためには、いくつかの課題を克服する必要があります。それらは、大まかには次のとおりです:

* 解析プログラムへバイナリをロードする。
* バイナリを中間表現（IR）に変換する。
* バイナリを実際に解析する。これは次のようになります:
  * プログラムの一部または全体の静的解析（すなわち、依存関係の解析、プログラムスライシング）
  * プログラムの状態空間のシンボリック探索（すなわち、「オーバーフローが見つかるまで実行できるか？」）
  * 上記の組み合わせ（すなわち、「オーバーフローを見つけるために、メモリ書き込みにつながるプログラムスライスのみを実行しよう。」）

angrには、これらの課題をすべてクリアするコンポーネントがあります。本書では、それぞれがどのように機能し、どのようにそれらを使って邪悪な目標を達成できるかを説明します。

## はじめに

インストール方法は[こちら](INSTALL.md)をご覧ください。

angrの機能を理解するには、[トップレベルのメソッド](./docs/toplevel.md)から読んでください。

このドキュメントのHTMLバージョンは[docs.angr.io](https://docs.angr.io/)にあり、HTML APIリファレンスは[angr.io/api-doc](https://angr.io/api-doc/)にあります。

もしCTFを楽しんでいて、同じようにangrを学びたいならば、[angr_ctf](https://github.com/jakespringer/angr_ctf)はangrのシンボリック実行機能に慣れるための楽しい方法でしょう。[angr_ctfリポジトリ](https://github.com/jakespringer/angr_ctf)は[@jakespringer](https://github.com/jakespringer)によってメンテナンスされています。

## angrの引用

もし学術論文でangrを使用する場合は、angrが開発された論文を引用してください：

```bibtex
@article{shoshitaishvili2016state,
  title={SoK: (State of) The Art of War: Offensive Techniques in Binary Analysis},
  author={Shoshitaishvili, Yan and Wang, Ruoyu and Salls, Christopher and Stephens, Nick and Polino, Mario and Dutcher, Audrey and Grosen, Jessie and Feng, Siji and Hauser, Christophe and Kruegel, Christopher and Vigna, Giovanni},
  booktitle={IEEE Symposium on Security and Privacy},
  year={2016}
}

@article{stephens2016driller,
  title={Driller: Augmenting Fuzzing Through Selective Symbolic Execution},
  author={Stephens, Nick and Grosen, Jessie and Salls, Christopher and Dutcher, Audrey and Wang, Ruoyu and Corbetta, Jacopo and Shoshitaishvili, Yan and Kruegel, Christopher and Vigna, Giovanni},
  booktitle={NDSS},
  year={2016}
}

@article{shoshitaishvili2015firmalice,
  title={Firmalice - Automatic Detection of Authentication Bypass Vulnerabilities in Binary Firmware},
  author={Shoshitaishvili, Yan and Wang, Ruoyu and Hauser, Christophe and Kruegel, Christopher and Vigna, Giovanni},
  booktitle={NDSS},
  year={2015}
}
```

## サポート

angrのヘルプを得るには、以下の方法で質問できます:

* slackチャンネル: [angr.slack.com](https://angr.slack.com)、 [こちら](https://angr.io/invite/)からアカウントを取得できます。
* 適切なGitHubリポジトリでissueを開く。

## さらに詳しく

[この論文](https://www.cs.ucsb.edu/~vigna/publications/2016_SP_angrSoK.pdf)では、内部構造、アルゴリズム、使用されている手法が説明されており、内部で何が起こっているのかをより深く理解できます。
