# SM2 CoSign Lab

<p align="center">
  <a href="https://github.com/securitysheep/sm2-cosign-lab/stargazers"><img src="https://img.shields.io/github/stars/securitysheep/sm2-cosign-lab?style=flat-square" alt="stars"></a>
  <a href="https://github.com/securitysheep/sm2-cosign-lab/network/members"><img src="https://img.shields.io/github/forks/securitysheep/sm2-cosign-lab?style=flat-square" alt="forks"></a>
  <a href="https://github.com/securitysheep/sm2-cosign-lab/blob/main/LICENSE"><img src="https://img.shields.io/github/license/securitysheep/sm2-cosign-lab?style=flat-square" alt="license"></a>
  <a href="https://github.com/securitysheep/sm2-cosign-lab/commits/main"><img src="https://img.shields.io/github/last-commit/securitysheep/sm2-cosign-lab?style=flat-square" alt="last-commit"></a>
</p>

一个基于 SM2 与 SM3 的多方协同数字签名与验签演示平台，提供 C 后端、Web 前端、模块化接口层与 GMSSL 3.x 适配。

English: A practical SM2 multi-party collaborative signature demo with modular C backend and strict GMSSL 3.x adaptation.

## 目录

- 项目亮点
- 适用场景
- 快速开始
- 接口一览
- 项目结构
- 文档导航
- 开发路线图
- GitHub 首页信息填写建议
- 常见问题
- 贡献指南
- 许可证

## 项目亮点

- 端到端协同签名链路：初始化、组公钥生成、签名、验签
- endpoint 拆分清晰：init、group、sign、verify 独立实现
- 统一请求体处理与错误响应，包含请求体大小限制保护
- 健康检查与自动化回归脚本，便于持续验证
- GMSSL 3.x 适配层与业务解耦，降低密码库升级成本

## 适用场景

- 密码学教学与实验课程演示
- 多方协作签名流程验证与 PoC
- SM2 协同签名后端接口化实践

## 快速开始

### 1) 环境依赖

macOS:

~~~bash
brew install jansson libmicrohttpd gmssl
~~~

说明：默认优先使用系统或 Homebrew 动态库，不建议直接依赖仓库中历史静态库。

### 2) 构建

~~~bash
make clean
make
~~~

### 3) 启动后端

~~~bash
make run
~~~

默认地址：
- 服务地址: http://localhost:8888
- 健康检查: http://localhost:8888/health

### 4) 启动前端

~~~bash
make run-frontend
~~~

前端访问: http://localhost:8080/index.html

### 5) 运行回归测试

~~~bash
make test
~~~

该命令执行最小链路：init -> gen-group-key -> sign -> verify

## 接口一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | /health | 健康检查 |
| POST | /init | 初始化用户与服务器密钥 |
| POST | /gen-group-key | 生成组公钥 |
| POST | /sign | 协同签名 |
| POST | /verify | 验签 |

完整接口定义见 [docs/api.md](docs/api.md)。

## 项目结构

~~~text
assets/
  images/                         # 截图和架构图
docs/
  api.md
  architecture.md
  github-publish-guide.md
  manual/
scripts/
  regression_sm2_flow.sh
src/
  app.c                           # HTTP 服务入口
  runtime_state.c/.h              # 全局状态管理
  SM2.c/.h                        # SM2 封装
  SM2_Multi_party_collaborative_signature.c/.h
  crypto/
    gmssl3_adapter.c/.h           # GMSSL 3.x 适配层
  endpoints/
    http_utils.c/.h               # 请求与响应公共组件
    dispatcher.c                  # 路由分发
    init_endpoint.c
    group_endpoint.c
    sign_endpoint.c
    verify_endpoint.c
~~~

## 文档导航

- API 文档: [docs/api.md](docs/api.md)
- 架构文档: [docs/architecture.md](docs/architecture.md)
- 发布指南: [docs/github-publish-guide.md](docs/github-publish-guide.md)
- 协同签名模块化重构计划: [docs/plans/2026-03-14-backend-modularization.md](docs/plans/2026-03-14-backend-modularization.md)

## 开发路线图

- [x] endpoint 模块化拆分
- [x] GMSSL 3.x 适配层落地
- [x] 回归脚本与健康检查
- [ ] GitHub Actions 持续集成
- [ ] 前端可视化调试面板增强

## GitHub 首页信息填写建议

建议在仓库 About 区域填写：

- Description:
  SM2 multi-party co-signature demo with modular C backend, web frontend, and GMSSL 3.x adapter.
- Topics:
  sm2, sm3, gmssl, cryptography, digital-signature, multiparty-computation, c, microhttpd, security-demo

详细模板见 [docs/github-publish-guide.md](docs/github-publish-guide.md)。

## 常见问题

### 为什么签名阶段可能比普通签名慢？

协同签名需要多轮椭圆曲线运算与链式加解密，性能开销高于单方签名属于预期行为。

### 为什么要保留 GMSSL 3.x 适配层？

通过适配层隔离库调用细节，便于后续升级密码库或切换实现。

### 上线前最少要做哪些检查？

至少执行一次 make test 并确认回归链路通过。

## 贡献指南

参见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 许可证

本项目采用 MIT 许可证，见 [LICENSE](LICENSE)。
