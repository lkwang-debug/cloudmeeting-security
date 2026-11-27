# 配置说明

先执行 `python tools/init_local.py`，再修改 `configs/scan.local.yaml`。除了专用检查策略，不要求修改源码中的地址或密码。

| 配置段 | 内容 | 必需条件 |
|---|---|---|
| env | 环境名称、实际产品版本 | 每个环境填写 |
| web | HTTPS基础地址、域名、应用IP | 基础检查填写；不要填写模板占位符 |
| accounts.admin | 后台测试管理员 | 后台登录及管理检查 |
| accounts.preflight_admin | 可选预检管理员 | 不填时复用admin |
| accounts.idor_a / idor_b | 不同部门的两个普通测试账号、密码、depart_id | 权限隔离检查；必须属于被测环境 |
| api | OpenAPI Key/Secret；可选OAuth Client ID/Secret | 对应鉴权能力 |
| recording | auto按A/B查询；manual填写自己的会议室、group等ID | 录制权限及下载检查需真实样本 |
| data_strategy | 自动创建开关或手工数据ID | 模板默认全部关闭自动创建 |
| ui | 本机ChromeDriver路径、匹配的Chrome主版本 | 仅Selenium相关能力 |
| hosts | SSH、数据库、Redis连接与口令 | 仅相应主机分析能力；不填则不具备该能力 |
| scan | 本地扫描报告、部署包、OAST域名、写链开关 | 按需准备；默认关闭写链 |
| report | 报告对象名称、输出目录 | 填写自己的报告对象 |
| port_scan / internal_exposure | 端口及内部暴露面 | 默认关闭，按目标范围启用 |

环境变量优先；配置中的 `${VAR}` 从当前进程读取。可用 `GATE_SCAN_CONFIG` 指定另一份本地YAML，默认路径不受项目所在盘符影响。

常用密码变量：`SEC_BACKEND_PASS`、`SEC_IDOR_A_PASS`、`SEC_IDOR_B_PASS`、`SEC_OPEN_KEY`、`SEC_OPEN_SECRET`。可选主机变量：`SEC_SSH_HOST`、`SEC_SSH_USER`、`SEC_SSH_PASSWORD`、`SEC_DB_HOST`、`SEC_DB_PASSWORD`、`SEC_REDIS_PASSWORD`；OAuth为 `SEC_CLIENT_ID` / `SEC_CLIENT_SECRET`。主机、口令也可由统一YAML的hosts段读取。

`configs/authorization_policy.yaml` 描述授权和写操作范围；`release_gate.yaml` 描述检查项和门禁规则；`web_automation.yaml` 的场景需按环境适配，模板默认关闭主动场景。它们是测试策略，不存放真实凭据。

身份池：可使用 `python adapters/api/identity_pool.py` 的参数帮助了解准备流程；它会创建真实测试数据，运行前需配置自己的环境和允许的数据范围。已有身份数据不要上传；参照 `fixtures/identities.example.json` 准备，运行产物为已忽略的 `fixtures/identities.json`。

本地单元测试不依赖这些账号。实际后台登录和跨部门/录制验证必须由使用者提供有效环境，单元测试通过不等于某个部署已经通过安全检查。
