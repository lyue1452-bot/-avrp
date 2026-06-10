<template>
  <el-container style="height: 100vh">
    <el-aside width="220px" class="sidebar">
      <div class="logo">
        <el-icon :size="22"><Lock /></el-icon>
        <span>自动化漏洞管理与修复平台</span>
      </div>
      <el-menu
        :default-active="activeMenu"
        router
        background-color="#001529"
        text-color="rgba(255,255,255,0.65)"
        active-text-color="#fff"
      >
        <el-menu-item index="/dashboard">
          <el-icon><DataAnalysis /></el-icon>
          <span>数据看板</span>
        </el-menu-item>
        <el-menu-item index="/vulnerabilities">
          <el-icon><WarningFilled /></el-icon>
          <span>漏洞库</span>
        </el-menu-item>
        <el-menu-item index="/tasks">
          <el-icon><List /></el-icon>
          <span>任务管理</span>
        </el-menu-item>
        <el-menu-item index="/reports">
          <el-icon><Document /></el-icon>
          <span>报告管理</span>
        </el-menu-item>
        <el-menu-item index="/pipeline">
          <el-icon><Connection /></el-icon>
          <span>流水线</span>
        </el-menu-item>
        <el-menu-item index="/settings">
          <el-icon><Setting /></el-icon>
          <span>系统设置</span>
        </el-menu-item>
        <el-menu-item v-if="auth.user?.role === 'admin'" index="/users">
          <el-icon><UserFilled /></el-icon>
          <span>用户管理</span>
        </el-menu-item>
      </el-menu>
    </el-aside>
    <el-container>
      <el-header class="header">
        <div class="header-left">
          <span class="page-title">{{ route.meta?.title || '' }}</span>
        </div>
        <div class="header-right">
          <el-tag v-if="auth.user" size="small" type="info">
            {{ auth.user.display_name || auth.user.username }}
            <template v-if="auth.user.role === 'admin'"> (管理员)</template>
          </el-tag>
          <el-button size="small" type="danger" plain @click="handleLogout" style="margin-left:12px">
            退出登录
          </el-button>
        </div>
      </el-header>
      <el-main class="main-content">
        <router-view />
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup>
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAuthStore } from '../stores/auth'
import { ElMessageBox } from 'element-plus'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()

const activeMenu = computed(() => route.path)

async function handleLogout() {
  try {
    await ElMessageBox.confirm('确认退出登录？', '提示')
    auth.logout()
    router.push('/login')
  } catch { /* cancel */ }
}
</script>

<style scoped>
.sidebar {
  background: #001529;
  overflow-y: auto;
}
.logo {
  height: 60px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: #fff;
  font-size: 16px;
  font-weight: 600;
  gap: 8px;
  border-bottom: 1px solid rgba(255,255,255,0.1);
}
.header {
  background: #fff;
  display: flex;
  align-items: center;
  justify-content: space-between;
  border-bottom: 1px solid #e8e8e8;
  height: 60px;
  padding: 0 24px;
}
.page-title {
  font-size: 18px;
  font-weight: 600;
  color: #333;
}
.main-content {
  background: #f0f2f5;
  padding: 20px;
  overflow-y: auto;
}
.el-menu {
  border-right: none;
}
</style>
