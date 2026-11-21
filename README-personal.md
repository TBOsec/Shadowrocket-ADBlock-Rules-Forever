# Shadowrocket Personal Builder

详细设计、部署、回滚与来源见 `优化方案.md`。

- 把本目录内容（含 `.github`）合并到自己仓库的默认分支，保留上游 LICENSE 和署名。
- 修改 `personal/settings.json`、`personal/priority.rules`、`personal/china-domain.rules`、`personal/host.rules`，不要编辑生成产物。
- `python3 -m unittest discover -s tests -v` 检查生成器。
- `python3 scripts/build.py` 从上游获取配置并生成 `dist/sr_personal.conf`。
- 日常构建：GitHub Actions 每日 09:23 北京时间；首次手动启用和运行。
- 工作流需 `contents: write`，并且默认分支允许发布提交。
- 不要提交私有节点、订阅链接、Token 或其他秘密。
- 默认配置不启用大规模 ChinaMaxNoIP、用户未确认的美团拦截或地区策略组。
- 上游规则修改版保留 CC BY-SA 4.0 及原作者信息。查看方案的许可章节。
- 本套件已通过模拟样例测试，尚未进行真实上游和 iPhone 端到端验收。
