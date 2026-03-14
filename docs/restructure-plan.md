# 中等重构规划与落地说明

## 目标

在不改变现有接口路径的前提下，完成一轮可运行、可维护、可扩展的中等重构。

## 已落地优化

1. 构建与工程化
- 新增 Makefile，统一构建入口。
- 新增 .gitignore，隔离构建产物与系统垃圾文件。

2. 后端稳定性
- 重写请求体收集流程，统一连接上下文管理。
- 增加请求体大小上限检查，避免 buffer overflow。
- 使用统一失败返回与清理路径，降低内存泄漏风险。

3. 生命周期与崩溃修复
- 组公钥改为全局持有，不在生成后立即释放。
- 验签前增加系统状态检查和组公钥状态检查。
- 初始化流程重置全局状态，避免脏状态影响下一轮请求。

4. 前端行为修复
- 删除“验签恒 true”临时代码。
- 删除“非 JSON 响应字符串修补”临时代码。
- 签名随机点读取改为真实字段 kg。

5. 密码模块内存管理
- 删除源文件互相 include 的反模式。
- 用户结构统一初始化，补充 P_group/KG 的分配与释放。
- 避免在签名循环中重复分配 KG 坐标导致泄漏。

## 推荐目标结构（下一阶段）

```text
src/
  backend/
    http_server.c
    handlers/
      init_handler.c
      group_key_handler.c
      sign_handler.c
      verify_handler.c
    core/
      runtime_state.c
  crypto/
    sm2_core.c
    sm2_collab.c
  frontend/
    index.html
include/
  project/
    runtime_state.h
    handlers.h
docs/
  restructure-plan.md
  api.md
  test-plan.md
```

## 迁移策略

- 第一阶段（本次）：稳定性修复 + 构建统一。
- 第二阶段：按功能拆分 app.c，接口保持不变。
- 第三阶段：补测试、补文档、补观测，最后再做性能优化。

## 风险与控制

- 风险：历史代码对全局状态依赖较重，拆分时容易遗漏清理路径。
- 控制：每次拆分只迁移一个接口，保持端到端回归可执行。
