# Contributing to Telecom Phone Device ID Tools

感谢你对本项目的贡献！

## 行为准则

- 尊重所有参与者
- 不接受涉及凭证共享、自动绕过滑块/验证码、或违反电信服务条款的贡献

## 如何贡献

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 提交 Pull Request

## 开发环境

```bash
# 克隆仓库
git clone <repo-url>
cd telecom-phone-device-id-tools

# 安装依赖
pip install -r requirements.txt

# 运行测试
python3 -m unittest discover -s tests -p 'test_telecom_auth_*.py'
node --test tests/telecom_auth_frontend_harness.js
```

## 代码规范

- Python：遵循 PEP 8，使用类型注解
- JavaScript：使用 ES6+，保持前端无外部依赖
- 所有敏感数据（手机号、密码、验证码、令牌、DeviceId）不得写入日志或测试文件

## 提交规范

- `feat:` 新功能
- `fix:` 修复 bug
- `test:` 测试相关
- `docs:` 文档更新
- `refactor:` 重构
- `chore:` 构建/工具链

## 安全漏洞报告

请不要在公开 issue 中报告安全漏洞。请查看 [SECURITY.md](SECURITY.md) 获取联系方式。
