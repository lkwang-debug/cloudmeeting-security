# OAST 接入（公共 interactsh）

- 服务：`https://oast.fun`（公共 interactsh，唯一子域由客户端生成）
- 客户端：`tools_cache/interactsh/interactsh-client.exe`（v1.4.1）
- 当前域名：`callback.example.test`
- 交互记录：`tools_cache/interactsh/interactions.jsonl`（JSONL，逐条 DNS/HTTP/SMTP 交互）
- 状态文件：`adapters/oast/oast_state.json`

## 用法

1. 启动（若未运行）：
   `interactsh-client.exe -json -o interactions.jsonl -v`，从 stderr 读取 `INFO ... <domain>.oast.fun`。
2. 生成测试回调地址：`http://<unique-token>.<domain>/<path>`（DNS 也可用 `nslookup`）。
3. 判定：在 `interactions.jsonl` 中查找 `full-id` 包含该 token 的记录；HTTP 记录里的 `remote-address` 为目标源 IP。

## 已知限制

- 公共 OAST 不发布 IPv6 AAAA 记录（客户端已提示）；IPv6-only 目标可能漏报。
- 回调元数据经过第三方服务（oast.fun），仅包含请求行/头与源 IP，不传目标数据；已获用户授权。
- 服务可用性依赖公网；若不可用则标记 OAST 阻塞。
