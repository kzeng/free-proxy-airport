# Free Proxy Airport v7

机场级体验的 Clash Verge / Mihomo 免费节点订阅系统。GitHub Actions 每小时（以及每次 push 到 `main`）自动聚合公开免费节点源，执行真实延迟测试，剔除超时和无效节点，并按健康评分生成自动分组。

## Clash Verge 使用方式

Profiles -> Add URL:

```text
https://kzeng.github.io/docs/clash.yaml

```
## 自动更新

工作流名称：`AI Self-Healing Proxy v7`

节点源：

- snakem982 proxypool
- zhuhaiuk free-nodes
- kooker FreeSubsCheck
- free-node-hub
- Billow001 free-nodes-sub
- free-clash-v2ray GitHub Pages

核心能力：

- 每个节点最多测 3 次、至少成功 2 次才收录
- 基于实测延迟和成功率排序
- HK / JP / US / LOW-LATENCY 自动分组（保留 AI-POOL 兼容别名）
- FALLBACK 自动降级
- OpenAI / ChatGPT / Claude / Anthropic 流量走低延迟组；不保证这些服务对节点开放

输出文件：

```text
output/clash.yaml
docs/clash.yaml
```

发布方式：工作流将 `docs/clash.yaml` 推送至 `kzeng/kzeng.github.io` 仓库的 `clash` 分支 `static/docs` 目录，由 GitHub Pages 托管为 https://kzeng.github.io/docs/clash.yaml。

请仅在遵守当地法律法规和相关服务条款的前提下使用。

updated: 2026-11-23 00:00:01
