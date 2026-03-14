# API 文档

基础地址：`http://localhost:8888`

## GET /health

用途：服务健康检查。

响应示例：

```json
{"status":"ok"}
```

## POST /init

请求示例：

```json
{"user_count": 3}
```

响应字段：
- server.private, server.px, server.py
- users[].private, users[].px, users[].py

## POST /gen-group-key

请求示例：

```json
{"user_count": 3}
```

响应字段：
- users[].group_public_x, users[].group_public_y
- group_public.x, group_public.y

## POST /sign

请求示例：

```json
{"message": "message digest"}
```

响应字段：
- kg[].x, kg[].y
- r, s

## POST /verify

请求示例：

```json
{"message": "message digest", "r": "...", "s": "..."}
```

响应示例：

```json
{"valid": true}
```

## 错误响应

统一格式：

```json
{"error":"..."}
```

典型错误：
- Invalid JSON format
- Request body too large
- Invalid sign request
- Invalid verify request
