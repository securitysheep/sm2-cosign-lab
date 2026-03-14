# Contributing Guide

## Branch Naming

- feat/<topic>
- fix/<topic>
- docs/<topic>

## Commit Message

建议使用 Conventional Commits：

- feat: add endpoint module
- fix: handle request body overflow
- docs: update api spec

## Development Flow

1. 安装依赖
2. 运行 `make`
3. 运行 `make test`
4. 提交 PR（附测试结果）

## Pull Request Checklist

- [ ] 本地构建通过
- [ ] 回归测试通过
- [ ] 文档已更新
- [ ] 未引入无关改动
