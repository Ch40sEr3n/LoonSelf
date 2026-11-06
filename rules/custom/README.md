# 自定义规则

可在这里保存自己的 Loon 原生 .lsr 规则。自动更新不会覆盖这个目录。

需要启用时，在 config/base.lcf 的 [Remote Rule] 中添加该文件的公开 Raw 地址，policy 指向现有策略，tag 与 policy 相同；下次生成时保留该条目。自定义文件名应与上游规则文件名不同。只有新增上游规则时才需同步编辑 config/sync.json。

Lumen 当前通过 config/base.lcf 中的本地 DOMAIN-SUFFIX 规则固定直连。
