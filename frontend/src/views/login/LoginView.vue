<template>
  <div class="login-page">
    <div class="login-card">
      <h2 class="login-title">
        <el-icon :size="28" style="vertical-align:middle"><Lock /></el-icon>
        自动化漏洞管理与修复平台
      </h2>
      <p class="login-desc">漏洞管理与自动化修复系统</p>

      <!-- 首次初始化管理员 -->
      <div v-if="showInit" class="init-box">
        <p style="color:#999;font-size:13px">首次使用，请创建管理员账号</p>
        <el-input v-model="initForm.username" placeholder="管理员用户名" style="margin-bottom:12px">
          <template #prepend>用户名</template>
        </el-input>
        <el-input v-model="initForm.password" type="password" placeholder="密码" show-password style="margin-bottom:12px">
          <template #prepend>密码</template>
        </el-input>
        <el-button type="primary" style="width:100%" @click="handleInit" :loading="loading">
          创建管理员
        </el-button>
        <el-button text size="small" style="margin-top:8px" @click="showInit = false">
          已有账号？去登录
        </el-button>
      </div>

      <!-- 登录 -->
      <el-form v-else @submit.prevent="handleLogin">
        <el-input v-model="form.username" placeholder="用户名" style="margin-bottom:16px">
          <template #prefix><el-icon><User /></el-icon></template>
        </el-input>
        <el-input v-model="form.password" type="password" placeholder="密码" show-password style="margin-bottom:20px">
          <template #prefix><el-icon><Lock /></el-icon></template>
        </el-input>
        <el-button type="primary" native-type="submit" style="width:100%" :loading="loading">
          登录
        </el-button>
      </el-form>

      <p v-if="errorMsg" style="color:#e6422e;font-size:13px;margin-top:12px">{{ errorMsg }}</p>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '../../stores/auth'
import { ElMessage } from 'element-plus'

const router = useRouter()
const auth = useAuthStore()
const form = ref({ username: 'admin', password: 'admin123' })
const initForm = ref({ username: 'admin', password: 'admin123' })
const loading = ref(false)
const showInit = ref(false)
const errorMsg = ref('')

onMounted(async () => {
  // 检测是否已初始化（如果登录失败提示未初始化则显示初始化面板）
  try {
    const resp = await fetch('/api/auth/init', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })
    const data = await resp.json()
    if (data.ok) {
      showInit.value = true
    }
  } catch { /* ignore */ }
})

async function handleLogin() {
  loading.value = true
  errorMsg.value = ''
  try {
    const res = await auth.login(form.value.username, form.value.password)
    if (res.ok) {
      ElMessage.success('登录成功')
      router.push('/dashboard')
    } else {
      errorMsg.value = res.msg || '登录失败'
    }
  } catch (e) {
    errorMsg.value = e.response?.data?.msg || '网络错误'
  } finally {
    loading.value = false
  }
}

async function handleInit() {
  loading.value = true
  errorMsg.value = ''
  try {
    const res = await auth.initAdmin(initForm.value.username, initForm.value.password)
    if (res.ok) {
      ElMessage.success('管理员创建成功，请登录')
      showInit.value = false
    } else {
      errorMsg.value = res.msg
    }
  } catch (e) {
    errorMsg.value = e.response?.data?.msg || '创建失败'
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login-page {
  height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
}
.login-card {
  background: #fff;
  padding: 40px;
  border-radius: 12px;
  box-shadow: 0 8px 32px rgba(0,0,0,0.3);
  width: 380px;
}
.login-title {
  text-align: center;
  margin-bottom: 4px;
  color: #333;
}
.login-desc {
  text-align: center;
  color: #999;
  font-size: 13px;
  margin-bottom: 28px;
}
.init-box {
  text-align: center;
}
</style>
