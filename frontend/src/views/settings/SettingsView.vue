<template>
  <div>
    <el-card shadow="hover">
      <template #header><span style="font-weight:600">系统设置</span></template>

      <el-form :model="form" label-width="160px" style="max-width:600px">
        <el-form-item label="Ansible 模式">
          <el-select v-model="form.ansible_mode" style="width:100%">
            <el-option label="自动检测" value="auto" />
            <el-option label="演示模式（模拟）" value="simulate" />
            <el-option label="WSL" value="wsl" />
            <el-option label="原生" value="native" />
          </el-select>
          <div style="color:#999;font-size:12px;margin-top:4px">当前: {{ currentMode }}</div>
        </el-form-item>

        <el-form-item label="Ansible 超时（秒）">
          <el-input-number v-model="form.ansible_timeout" :min="30" :max="600" style="width:100%" />
        </el-form-item>

        <el-form-item label="修复后验证">
          <el-switch v-model="form.verify_after_fix" />
          <div style="color:#999;font-size:12px;margin-top:4px">关闭后修复完成直接标记成功，不执行验证</div>
        </el-form-item>

        <el-form-item>
          <el-button type="primary" @click="saveSettings" :loading="saving">保存设置</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card shadow="hover" style="margin-top:16px">
      <template #header><span style="font-weight:600">修复规则列表</span></template>
      <el-table :data="rules" stripe>
        <el-table-column prop="id" label="规则ID" width="160" />
        <el-table-column prop="name" label="名称" min-width="200" />
        <el-table-column prop="playbook" label="剧本" width="180" />
        <el-table-column label="类型" width="80">
          <template #default="{ row }">
            <el-tag v-if="row.manual" type="warning" size="small">需人工</el-tag>
            <el-tag v-else type="success" size="small">自动</el-tag>
          </template>
        </el-table-column>
      </el-table>
    </el-card>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { settingsAPI } from '../../api/auth'
import { ElMessage } from 'element-plus'

const form = ref({
  ansible_mode: 'auto',
  ansible_timeout: 120,
  verify_after_fix: true,
})
const currentMode = ref('检测中...')
const saving = ref(false)
const rules = ref([])

onMounted(async () => {
  const res = await settingsAPI.get()
  if (res.ok) {
    if (res.data.ansible_mode) form.value.ansible_mode = res.data.ansible_mode
    if (res.data.ansible_timeout) form.value.ansible_timeout = parseInt(res.data.ansible_timeout)
    if (res.data.verify_after_fix === 'false' || res.data.verify_after_fix === '0') form.value.verify_after_fix = false
  }

  try {
    const r = await fetch('/rules')
    const data = await r.json()
    rules.value = data
  } catch { /* ignore */ }
})

async function saveSettings() {
  saving.value = true
  try {
    const res = await settingsAPI.update({
      ansible_mode: form.value.ansible_mode,
      ansible_timeout: String(form.value.ansible_timeout),
      verify_after_fix: form.value.verify_after_fix ? '1' : '0',
    })
    if (res.ok) ElMessage.success('设置已保存')
  } finally {
    saving.value = false
  }
}
</script>
