# cloudmeeting-security

云会议 Web/API 安全检查、证据归档和发布门禁工具。支持配置驱动的接口检查、本地模拟服务回归、浏览器检查及可选主机/组件分析。

仓库是独立的发布副本：不携带真实环境凭据、客户报告、抓包、扫描结果、虚拟环境、客户端安装包或原项目 Git 历史。报告按本次执行生成，不代表任何目标已经通过安全验收。

## 安装与本地验证

推荐 Windows，64位 Python 3.10 或3.11。在克隆目录执行：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pytest
```

测试使用本地模拟服务器、临时目录及模拟凭据，不需要你的业务环境、客户报告、SSH或真实账号。Linux使用 `source .venv/bin/activate`。

需要完整复现本次核心依赖版本时，可改为安装 `requirements-lock.txt`。锁文件由干净环境实际安装生成；不包含机器路径。浏览器扩展另装：

```powershell
python -m pip install -r requirements-browser.txt
python -m playwright install chromium
```

自动后台登录使用提取的 `adapters/browser/admin_login.py`，需要 Chrome/Edge、Playwright、ddddocr和Pillow。不携带浏览器或OCR模型缓存；首次安装会从依赖来源取得相应组件。

## 配置自己的环境

```powershell
python tools/init_local.py
```

该命令只在本地生成 `configs/scan.local.yaml` 和输出目录；已存在的本地配置不会被覆盖。

只人工维护自己的 `configs/scan.local.yaml`，配置说明见 [docs/CONFIGURATION.md](docs/CONFIGURATION.md)。最少填写：环境版本、Web/API地址、管理员、不同部门的A/B账号及部门ID、OpenAPI Key/Secret、报告名称。

敏感值可直接写本地配置，也可引用环境变量，例如：

```yaml
web:
  base_url: "https://meeting.example.test:28443"
accounts:
  admin:
    username: "test_admin"
    password: "${SEC_BACKEND_PASS}"
api:
  openapi_key: "${SEC_OPEN_KEY}"
  openapi_secret: "${SEC_OPEN_SECRET}"
```

`scan.local.yaml`、证据、令牌、报告均被 `.gitignore` 排除。不要把真实配置覆盖到 `scan.example.yaml` 后提交。

## 执行

```powershell
# 参数帮助，不连接业务环境
python runner/run_scan.py --help

# 检查已填写配置、目标连通性、鉴权及样本条件
python runner/run_scan.py --check-only

# 快速检查 / 完整发布门禁
python runner/run_scan.py --profile quick
python runner/run_scan.py --profile release
```

`--check-only` 会访问你配置的目标进行预检，不等于离线单元测试。当前发布默认关闭写链、自动创建和内网扫描；按实际授权范围启用能力。配置模板里的空项不代表环境已经就绪。

缺少录制样本、账号、浏览器、主机凭据或外部工具时，对应能力应报告缺失/受阻，不能当作通过。完整门禁可能返回非零：需区分发现漏洞、配置缺失与执行错误。本次发布验证只运行本地测试，不自动扫描原项目环境。

## 目录

```text
adapters/          认证、身份池、OAST与浏览器登录适配
checks/            安全检查与结果解析
configs/           空白环境模板、检查策略及场景配置
fixtures/          场景定义、模拟扫描报告、身份模板
knowledge/         脱敏的协议库存、参数名称和检查规则
runner/            预检、扫描编排、门禁和通用报告工具
tests/             本地模拟测试与契约测试
tools/             初始化、库存生成和辅助工具
docs/              配置、扩展能力与发布说明
```

`reports/`、`evidence/`、`state/` 和 `tools_cache/` 由初始化或运行生成。检查证据一般在 `reports/final/gate/evidence/`，预检报告在 `reports/final/ENV_READINESS.md`。

## 可选组件与范围

外部扫描器、客户端样本、原始Excel/API文档和第三方项目不随仓库分发。参见 [docs/OPTIONAL_FEATURES.md](docs/OPTIONAL_FEATURES.md)。保留的协议库存仅含必要接口结构，已移除抓取时的请求头、请求体样本值及运行时间信息。

历史客户报告专用的固定结论生成脚本未纳入发布；通用报告工具保留。接口库存不是完整产品协议文档，换产品/版本需重新核对和生成。缺少输入时不能依靠旧报告得出新结论。

发布范围、验证结果和文件清单见 [docs/PUBLICATION.md](docs/PUBLICATION.md)。本仓库暂未授予额外开源许可；分享私有仓库时请通过GitHub协作者权限提供访问。
