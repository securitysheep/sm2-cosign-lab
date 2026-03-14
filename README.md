# SM2 CoSign Lab

SM2 CoSign Lab 是一个基于 SM2/SM3 的多方协同数字签名与验签演示平台，包含 C 后端、Web 前端与严格 GMSSL 3.x 适配层。

English tagline: A practical SM2 multi-party co-signature demo with modular C backend and GMSSL 3.x compatibility.

## 推荐仓库名

主推荐：sm2-cosign-lab

备选：
- sm2-multiparty-signature-lab
- gmssl-sm2-collab-sign-demo

## 核心能力

- 多方协同签名完整流程：初始化、组公钥生成、签名、验签
- endpoint 模块化：init/group/sign/verify 独立实现
- 统一请求体处理与错误返回，支持 body 超限保护
- 健康检查接口与自动化回归脚本
- 严格 GMSSL 3.x 适配层，便于迁移与替换

## 目录结构

```text
assets/
  images/                         # 项目截图、架构图
docs/
  api.md                          # 接口说明
  architecture.md                 # 架构说明
  github-publish-guide.md         # GitHub 发布与填写模板
  manual/                         # 原始操作手册
scripts/
  regression_sm2_flow.sh          # 回归脚本
src/
  app.c                           # HTTP 服务入口
  runtime_state.c/.h              # 全局状态与资源生命周期
  SM2.c/.h                        # SM2 封装
  SM2_Multi_party_collaborative_signature.c/.h
  crypto/
    gmssl3_adapter.c/.h           # GMSSL 3.x 适配层
  endpoints/
    http_utils.c/.h               # 请求解析与响应封装
    dispatcher.c                  # 路由分发
    init_endpoint.c
    group_endpoint.c
    sign_endpoint.c
    verify_endpoint.c
```

## 环境依赖

macOS:

```bash
brew install jansson libmicrohttpd gmssl
```

说明：
- 默认优先使用系统或 Homebrew 动态库。
- 不建议直接依赖仓库内 lib 目录中的历史静态库文件。

## 快速开始

1) 构建

```bash
make clean
make
```

2) 启动后端

```bash
make run
```

3) 启动前端静态页面

```bash
make run-frontend
```

4) 访问地址

- 前端：http://localhost:8080/index.html
- 后端：http://localhost:8888
- 健康检查：http://localhost:8888/health

## 回归测试

```bash
make test
```

该命令执行最小端到端链路：
/init -> /gen-group-key -> /sign -> /verify

## 接口与架构文档

- API: docs/api.md
- Architecture: docs/architecture.md

## GitHub 发布与页面填写

详细步骤和可复制模板见：docs/github-publish-guide.md

## 常见问题

1. 为什么 sign 可能耗时偏高？

协同签名过程包含多轮椭圆曲线运算与链式加解密，在调试构建或低性能设备上耗时会更明显。

2. 为什么要做 GMSSL 3.x 适配层？

将核心业务逻辑与具体密码库调用隔离，便于后续升级和替换。

3. 发布前最少要做什么检查？

至少执行一次 make test 并确认回归链路通过。

## Contributing

See CONTRIBUTING.md

## License

MIT, see LICENSE
