# ============================================================
# Dockerfile — 自动化漏洞管理与修复平台
# 多阶段构建：先编译 Vue 前端，再组装 Flask 后端
# ============================================================

# ---- Stage 1: 构建前端 ----
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci
COPY frontend/ .
RUN npm run build

# ---- Stage 2: 后端运行时 ----
FROM python:3.12-slim
WORKDIR /app

# 安装系统依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 安装 Python 依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制后端代码
COPY . .
# 复制前端构建产物
COPY --from=frontend-builder /app/frontend/dist frontend/dist

EXPOSE 5000
CMD ["python", "app.py"]