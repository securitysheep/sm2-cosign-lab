# GitHub Publish Guide

## 1. 仓库命名建议

主推荐：
- sm2-cosign-lab

备选：
- sm2-multiparty-signature-lab
- gmssl-sm2-collab-sign-demo

## 2. 创建仓库页面填写模板

Create a new repository 页面建议：

- Repository name: sm2-cosign-lab
- Description: Multi-party collaborative signature and verification platform based on SM2/SM3 with strict GMSSL 3.x adapter
- Visibility: Public 或 Private
- Add a README file: No
- Add .gitignore: No
- Choose a license: No

说明：本项目已包含 README、.gitignore、LICENSE，本地版本优先。

## 3. 仓库 About 区域填写模板

Description:

SM2 multi-party co-signature demo with modular C backend, web frontend, and GMSSL 3.x adapter.

Website:

- 若暂无项目主页可留空
- 如后续部署演示页可填写项目文档地址

Topics 建议：

- sm2
- sm3
- gmssl
- cryptography
- digital-signature
- multiparty-computation
- c
- microhttpd
- security-demo

## 4. 首次发布前本地步骤

```bash
git init
git add .
git commit -m "feat: sm2 cosign platform initial open-source release"
git branch -M main
git remote add origin <your-repo-url>
git push -u origin main
```

如果已经存在 origin，改用：

```bash
git remote set-url origin <your-repo-url>
git push -u origin main
```

## 5. Releases 页面建议填写

Tag:

- v1.0.0

Release title:

- v1.0.0 Initial Open Source Release

Release notes 模板：

```text
## Highlights
- Modular endpoint architecture for init/group/sign/verify
- Strict GMSSL 3.x adapter integration
- End-to-end regression script and health endpoint

## Build and Run
- make clean && make
- make run
- make test

## Documentation
- API: docs/api.md
- Architecture: docs/architecture.md
```

## 6. 首页内容建议

README 首屏建议保持：

- 一句话项目定位
- 快速启动（构建/运行/测试）
- API 与架构文档入口
- 贡献与许可证入口

## 7. Issue 与 PR 模板使用建议

- 在仓库设置中开启 Issues
- 使用 .github/ISSUE_TEMPLATE 下模板收集问题
- 使用 .github/pull_request_template.md 统一提交规范

## 8. 发布后可选增强

- 保护 main 分支，要求 PR 合并
- 增加 CI（构建与 make test）
- 增加项目截图到 assets/images 并在 README 引用
