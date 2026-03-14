# 架构说明（第二阶段）

## 模块划分

- app.c
  - 服务启动与路由分发
  - CORS OPTIONS 处理
  - /health 健康检查

- handlers.c
  - `/init` `/gen-group-key` `/sign` `/verify` 业务处理
  - 请求体收集与大小限制
  - JSON 序列化与响应输出

- runtime_state.c
  - 全局运行时资源持有
  - 统一 reset_global_state 清理生命周期

- SM2.c / SM2_Multi_party_collaborative_signature.c
  - 密码算法与多方协同签名核心流程

## 关键设计点

1. 响应内存策略
- 使用 `MHD_RESPMEM_MUST_COPY`，避免释放后返回脏数据。

2. 生命周期统一
- `reset_global_state` 负责用户、服务器、曲线、组公钥全量清理。

3. 可测试性
- 提供 `/health` 便于脚本等待服务就绪。
- `scripts/regression_sm2_flow.sh` 提供最小端到端回归。

4. 构建策略
- 默认链接系统/Homebrew 库。
- `USE_LOCAL_CRYPTO=1` 时才链接工作区 `lib/` 目录。
