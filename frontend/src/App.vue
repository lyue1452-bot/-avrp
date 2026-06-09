<template>
  <router-view />
</template>

<script setup>
import { useAuthStore } from './stores/auth'

// 初始化时尝试从 localStorage 恢复 token
const auth = useAuthStore()
auth.loadFromStorage()
</script>

<style>
body {
  margin: 0;
  font-family: 'Segoe UI', 'PingFang SC', 'Microsoft YaHei', sans-serif;
  background: #f0f2f5;
}
</style>
