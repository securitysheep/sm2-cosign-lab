# Backend Modularization Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Keep existing HTTP APIs unchanged while modularizing backend into router, runtime state, and handlers.

**Architecture:** Keep `src/app.c` as thin entrypoint and route dispatcher. Move global runtime resources to a dedicated state module and move endpoint logic into a handler module to reduce coupling and centralize lifecycle management.

**Tech Stack:** C11, libmicrohttpd, jansson, OpenSSL/GmSSL

---

### Task 1: Introduce runtime state module

**Files:**
- Create: `src/runtime_state.h`
- Create: `src/runtime_state.c`
- Modify: `src/app.c`

**Step 1: Write failing build check**
Run: `make`
Expected: references not found after moving symbols, proving module boundaries are active.

**Step 2: Add state declarations/definitions**
- Add shared state symbols and reset function declaration/implementation.

**Step 3: Wire app.c to state module**
- Replace local static state with module state.

**Step 4: Run build**
Run: `make`
Expected: link success for state symbols.

### Task 2: Introduce handlers module

**Files:**
- Create: `src/handlers.h`
- Create: `src/handlers.c`
- Modify: `src/app.c`

**Step 1: Build should fail before wiring**
Run: `make`
Expected: undefined handler references.

**Step 2: Move endpoint logic to handlers.c**
- Move init/gen-group-key/sign/verify handlers.
- Keep utility body collector and response helper in handlers module.

**Step 3: Simplify app.c routing only**
- Keep options handling and path dispatching.

**Step 4: Run build**
Run: `make`
Expected: build success.

### Task 3: Add minimum regression script

**Files:**
- Create: `scripts/regression_sm2_flow.sh`
- Modify: `README.md`

**Step 1: Add script**
- Start server, call `/init`, `/gen-group-key`, `/sign`, `/verify` with curl.

**Step 2: Verify script failure mode**
Run script before server ready to ensure it fails clearly.

**Step 3: Verify script pass mode**
Run script end-to-end.
Expected: output contains `valid:true`.

### Task 4: Final verification

**Files:**
- Modify: `README.md`

**Step 1: Build verification**
Run: `make clean && make`
Expected: success.

**Step 2: Static diagnostics**
Run language diagnostics check.
Expected: no new errors in changed files.

**Step 3: Summarize outcomes and residual risks**
- Report what is validated and what still depends on local runtime environment.
