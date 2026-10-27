# Telecom Phone Device ID Tools

一个本地运行的中国电信设备授权（DeviceId）获取工具，用于解决 Home Assistant `china_telecom` 集成登录时返回 **3006 设备未信任** 的问题。

## 特性

- **官方直连**：仅调用电信官方 `189.cn` 接口，不经过第三方网站
- **短信授权**：通过滑块验证 + 短信验证码完成设备信任绑定
- **本地运行**：全部凭证仅在本机内存处理，不写日志、不落盘
- **局域网可访问**：支持手机/其他设备在同一局域网内完成授权
- **安全保护**：每次打开/刷新页面签发随机访问令牌、尝试次数限制、会话自动过期

## 环境要求

- Python 3.10+
- `requests`、`pycryptodome`

## 安装

```bash
pip install requests pycryptodome
```

或：

```bash
pip install -r requirements.txt
```

## 使用方法

### 启动（仅本机）

```bash
python3 -m tools.telecom_auth
```

终端会显示访问地址，例如：

```
Open: http://127.0.0.1:8765/
```

在浏览器中打开该地址，按页面提示完成滑块、短信验证和设备授权。每次打开或刷新页面都会自动签发一个新的访问令牌，无需从终端复制。

### 启动（局域网可访问）

```bash
python3 -m tools.telecom_auth --host 0.0.0.0 --port 8765
```

终端会显示局域网地址，手机或其他设备在同一网络内打开即可操作。

> ⚠️ **安全提示**：使用 `--host 0.0.0.0` 或局域网地址绑定时，流量为明文 HTTP，请仅在可信局域网内使用。不要将该端口映射到公网。

### 指定端口

```bash
python3 -m tools.telecom_auth --host 0.0.0.0 --port 8080
```

## 授权流程

1. 输入需要授权的电信号码
2. 完成滑块验证（手动拖动到缺口位置）
3. 点击发送短信，接收 6 位验证码
4. 输入短信验证码，完成短信登录，页面显示 DeviceId（刷新或关闭页面前一直保留）
5. 点击“复制 DeviceId”，粘贴到 HA 集成的“短信授权 DeviceId”配置项中
6. （可选）输入电信服务密码，验证 DeviceId 有效性

## 运行测试

```bash
# 全部授权工具测试
python3 -m unittest discover -s tests -p 'test_telecom_auth_*.py'

# 前端行为测试（需 Node.js）
node --test tests/telecom_auth_frontend_harness.js
```

## 项目结构

```
tools/telecom_auth/
├── __init__.py          # 包入口
├── __main__.py          # CLI 启动入口
├── telecom.py           # 电信官方协议适配器
├── sessions.py          # 内存会话管理（10分钟过期）
├── security.py          # 访问令牌控制
├── server.py            # HTTP 服务 + API 路由
└── static/              # 前端页面
    ├── index.html
    ├── app.js
    └── style.css
```

## 安全说明

- 手机号、密码、验证码、令牌、DeviceId 均不写入日志
- 会话 10 分钟自动过期，进程退出即清除
- 每次打开/刷新页面签发独立随机令牌，空闲 30 分钟失效，授权成功后该令牌立即注销
- 滑块验证失败后可刷新重试，短信验证码最多尝试 5 次
- 目标域名仅允许 `appgologinsz.189.cn`、`appgologin.189.cn`、`appfuwu.189.cn`
- 强制 HTTPS 证书校验，禁止重定向

## 限制

- 仅支持中国电信手机号
- 服务密码为电信营业厅密码（6位数字），非短信验证码
- 图形滑块需人工完成，不支持自动识别
- 短信发送有频率限制，请勿重复请求

## 开源协议

[MIT License](LICENSE)

## 致谢

本项目协议实现参考了以下开源项目（详见 [NOTICE.md](NOTICE.md)）：

- [yahooor/cn-carrier-monitor](https://github.com/yahooor/cn-carrier-monitor)
- [hlhk2017/ChinaTelecomMonitor-Homeassistant-Integration](https://github.com/hlhk2017/ChinaTelecomMonitor-Homeassistant-Integration)
