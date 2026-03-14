# Phase 3 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Complete endpoint-level modularization, strict GMSSL 3.x crypto adaptation, repository structure cleanup, and GitHub-ready documentation.

**Architecture:** Split HTTP endpoints into dedicated translation units with shared HTTP utilities and dispatcher. Replace placeholder transfer crypto with a strict GMSSL 3.x adapter. Reorganize assets/docs and provide publish-ready repo metadata templates.

**Tech Stack:** C11, libmicrohttpd, jansson, OpenSSL compatibility layer, GMSSL 3.x

---

### Task 1: Endpoint modularization

**Files:**
- Create: src/endpoints/http_utils.h
- Create: src/endpoints/http_utils.c
- Create: src/endpoints/init_endpoint.c
- Create: src/endpoints/group_endpoint.c
- Create: src/endpoints/sign_endpoint.c
- Create: src/endpoints/verify_endpoint.c
- Create: src/endpoints/dispatcher.c
- Modify: src/handlers.h
- Modify: src/app.c
- Modify: Makefile
- Delete: src/handlers.c

**Verification:** `make clean && make`

### Task 2: Strict GMSSL 3.x crypto adaptation

**Files:**
- Create: src/crypto/gmssl3_adapter.h
- Create: src/crypto/gmssl3_adapter.c
- Modify: src/SM2.c
- Modify: src/SM2_Multi_party_collaborative_signature.c
- Modify: Makefile

**Verification:** `make clean && make && make test`

### Task 3: Structure and cleanup

**Files:**
- Create: assets/images/.gitkeep
- Create: docs/manual/
- Move: 操作手册 docx to docs/manual/
- Delete: src/错误.txt
- Delete: .DS_Store, include/.DS_Store

**Verification:** `find . -maxdepth 3 -type f | sort`

### Task 4: GitHub-ready docs and metadata

**Files:**
- Modify: README.md
- Create: LICENSE
- Create: CONTRIBUTING.md
- Create: .github/pull_request_template.md
- Create: .github/ISSUE_TEMPLATE/bug_report.md
- Create: .github/ISSUE_TEMPLATE/feature_request.md
- Create: docs/github-publish-guide.md

**Verification:** `make test`
