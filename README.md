# LoonSelf

个人 Loon 配置与规则发布仓库，基于 [YohakuSama/loonkit](https://github.com/YohakuSama/loonkit) 精简。当前保留 25 个策略组，订阅 28 个上游规则集，另有 6 条本地规则。Lumen 固定直连；GitHub Raw 跟随 GitHub 策略。

## 使用

将仓库设为 **Public**，默认分支为 `main`。首次上传后，在 Actions 中手动运行 **Update verified Loon rules**，程序会根据当前仓库地址生成配置中的规则链接。

固定订阅链接格式如下，请将 `Ch40sEr3n` 替换成实际 GitHub 用户名：

```text
https://raw.githubusercontent.com/Ch40sEr3n/LoonSelf/main/LoonKit.lcf
```

在 Loon 中导入这条配置链接后，自行添加机场订阅。公开文件不包含节点或订阅密钥；这些内容保存在私有仓库 `LoonSelf-BackUP`。

日常只有远程规则内容更新时，更新 Loon 的规则订阅即可。若修改了个人主配置，需要重新更新或导入主配置；操作前导出当前配置和节点信息，核对 Loon 的覆盖选项。

## 自动更新

- 每天北京时间 08:23 检查上游 `main` 中的正式发布清单，支持手动触发。
- 获取同一上游提交中的清单和配置，并校验配置 SHA256。
- 仅同步 `config/sync.json` 中列出的 28 个上游规则，不恢复已删策略。
- 每份规则均校验 SHA256、条目数和 Loon 原生语法，然后保存到 `rules/upstream/`。
- 保留个人策略、顺序、同名规则标签、Lumen 和所有本地规则。
- 上游规则改名、缺失、策略归属变化或发生大幅内容变化时停止更新，保持线上旧版本。大幅变化可审阅后通过手动触发选项放行。
- 校验全部通过后才由 Actions 提交。Git 历史保存每次已发布内容，可按提交回退。
- 每月记录一次成功检查状态，减少长期无更新导致定时任务因仓库不活跃而停用的可能性。

Actions 定时触发可能延迟；若长时间没有运行，检查 Actions 页面。参见 [GitHub 定时触发说明](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule)。

## 维护个人内容

| 路径 | 用途 |
| --- | --- |
| `config/base.lcf` | 个人配置源，修改策略和本地规则时编辑这里 |
| `config/sync.json` | 需要跟踪的上游规则清单 |
| `LoonKit.lcf` | 自动生成的订阅入口，不直接编辑 |
| `rules/upstream/` | 自动同步的上游规则副本，不直接编辑 |
| `rules/custom/` | 自己维护的规则，不被自动覆盖 |
| `configs/` | 其他可以公开的自用配置 |
| `state/upstream.json` | 上游版本、来源提交和各规则摘要 |
| `LICENSES/` | 上游许可与来源声明 |

本地运行要求 Python 3.11 或以上，无第三方依赖：

```sh
python3 -m unittest discover -s tests -v
python3 scripts/sync_rules.py --repository Ch40sEr3n/LoonSelf
python3 scripts/sync_rules.py --check
```

生成的主配置使用本仓库 main 分支下的规则链接。Actions 每次只发布通过校验的完整版本。

## 初次设置

仓库的 Actions 需要允许工作流运行并拥有 `contents: write` 权限。程序使用本仓库自动提供的 `GITHUB_TOKEN`，不需要额外提供个人访问令牌。不使用 GitHub Pages。

当前网络诊断插件要求 Loon 3.5.1（983）及以上，尚未在真实设备上验证本个人版本。

## 来源

个人修改包括策略删减、Lumen 直连、规则显示名统一及 GitHub Raw 分流一致性。上游规则和声明按原样保存；本项目原创脚本采用 GPL-2.0-only，第三方内容适用各自许可，见 `LICENSE`、`LICENSES/UPSTREAM_NOTICES.md` 及相应许可文本。
