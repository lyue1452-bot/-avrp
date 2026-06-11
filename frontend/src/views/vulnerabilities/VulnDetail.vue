<template>
  <div>
    <el-button size="small" @click="$router.push('/vulnerabilities')" style="margin-bottom:16px">
      返回漏洞库
    </el-button>

    <el-card v-if="vuln" shadow="hover">
      <el-descriptions :column="2" border>
        <el-descriptions-item label="漏洞名称" :span="2">{{ vuln.vuln_name }}</el-descriptions-item>
        <el-descriptions-item label="资产">{{ vuln.asset_ip }}:{{ vuln.port }}</el-descriptions-item>
        <el-descriptions-item label="URL">{{ vuln.url || '-' }}</el-descriptions-item>
        <el-descriptions-item label="级别">
          <el-tag :type="severityType(vuln.severity)" size="small">{{ vuln.severity }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="状态">
          <el-tag :type="statusType(vuln.fix_status)" size="small">{{ vuln.fix_status_label || fixStatusLabel(vuln.fix_status) }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="CVE" :span="2">{{ vuln.cve || '-' }}</el-descriptions-item>
        <el-descriptions-item label="修复规则" :span="2">{{ vuln.remediation_rule || '-' }}</el-descriptions-item>
        <el-descriptions-item label="描述" :span="2">
          <div class="desc-box">{{ vuln.description || '-' }}</div>
        </el-descriptions-item>
        <el-descriptions-item label="修复建议" :span="2">
          <div class="desc-box">{{ vuln.solution || '-' }}</div>
        </el-descriptions-item>
        <el-descriptions-item v-if="vuln.has_fix_log" label="最近修复日志" :span="2">
          <div class="desc-box">{{ vuln.last_fix_msg }}</div>
        </el-descriptions-item>
        <el-descriptions-item v-if="displayVerifyHint(vuln)" label="验证建议" :span="2">
          <div class="desc-box verify-hint">{{ vuln.verify_hint || buildVerifyHint(vuln) }}</div>
        </el-descriptions-item>
      </el-descriptions>

      <div style="margin-top:16px">
        <el-button type="danger" :disabled="!vuln.auto_fixable" @click="fixVuln" :loading="fixing">
          执行自动修复
        </el-button>
        <el-button type="warning" plain @click="showDelete" style="margin-left:12px">删除漏洞</el-button>
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { vulnAPI } from '../../api/auth'
import { fixStatusLabel, fixStatusType } from '../../utils/fixStatus'
import { buildVerifyHint } from '../../utils/verifyHint'
import { ElMessage, ElMessageBox } from 'element-plus'

const route = useRoute()
const router = useRouter()
const vuln = ref(null)
const fixing = ref(false)

onMounted(loadDetail)

async function loadDetail() {
  const res = await vulnAPI.detail(route.params.id)
  if (res.ok) vuln.value = res.data
}

function severityType(s) {
  if (!s) return 'info'
  if (s.includes('严重') || s.includes('Critical')) return 'danger'
  if (s.includes('高') || s.includes('High')) return 'warning'
  if (s.includes('中') || s.includes('Medium')) return ''
  return 'info'
}
function statusType(s) {
  return fixStatusType(s)
}

function displayVerifyHint(row) {
  return !!(row?.verify_hint || row?.remediation_rule || row?.auto_fixable)
}

async function fixVuln() {
  fixing.value = true
  if (vuln.value) {
    vuln.value.fix_status = 'fixing'
    vuln.value.fix_status_label = fixStatusLabel('fixing')
  }
  try {
    const res = await vulnAPI.fix(route.params.id)
    ElMessage({ type: res.ok ? 'success' : 'error', message: res.msg })
    if (res.ok) loadDetail()
  } finally {
    fixing.value = false
  }
}

async function showDelete() {
  try {
    await ElMessageBox.confirm('确认删除此漏洞？', '警告')
    const res = await vulnAPI.delete(route.params.id)
    if (res.ok) {
      ElMessage.success('已删除')
      router.push('/vulnerabilities')
    }
  } catch { /* cancel */ }
}
</script>

<style scoped>
.desc-box { white-space: pre-wrap; max-height: 300px; overflow-y: auto; font-size: 13px; line-height: 1.6; }
.verify-hint { font-family: Consolas, monospace; font-size: 12px; color: #606266; }
</style>
