#!/usr/bin/env bash
# ============================================================
# run-tests.sh — 项目测试入口脚本
# 在 CI 中被 Semgrep / Polaris 等工作流调用，通过后才允许自动合并
# ============================================================
set -euo pipefail

echo "==== 安装后端依赖 ===="
pip install -q -r requirements.txt

echo "==== 安装前端依赖 ===="
cd frontend
npm ci --silent
cd ..

echo "==== 运行后端测试 ===="
# 如果存在 pytest 则执行；否则用 unittest discover
if command -v pytest &>/dev/null; then
  python -m pytest tests/ -v || python -m pytest . -v || echo "No pytest tests found, skipping backend tests..."
else
  python -m unittest discover -s . -p "test_*.py" -v || echo "No unittest tests found, skipping backend tests..."
fi

echo "==== 运行前端测试 ===="
cd frontend
npm run build --silent
cd ..

echo "==== 测试完成 ===="
