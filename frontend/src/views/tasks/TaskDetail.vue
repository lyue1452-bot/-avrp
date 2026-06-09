<template>
  <div>
    <el-button size="small" @click="$router.push('/tasks')" style="margin-bottom:16px">
      返回任务列表
    </el-button>

    <el-card v-if="task" shadow="hover">
      <el-descriptions :column="2" border>
        <el-descriptions-item label="任务ID">{{ task.id }}</el-descriptions-item>
        <el-descriptions-item label="漏洞ID">{{ task.vuln_id }}</el-descriptions-item>
        <el-descriptions-item label="规则">{{ task.rule_id }}</el-descriptions-item>
        <el-descriptions-item label="目标">{{ task.target_ip }}</el-descriptions-item>
        <el-descriptions-item label="状态" :span="2">
          <el-tag :type="statusType(task.status)" size="small">{{ task.status }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="创建时间">{{ task.created_at }}</el-descriptions-item>
        <el-descriptions-item label="开始时间">{{ task.started_at || '-' }}</el-descriptions-item>
        <el-descriptions-item label="完成时间" :span="2">{{ task.finished_at || '-' }}</el-descriptions-item>
        <el-descriptions-item label="创建者" :span="2">{{ task.created_by || '-' }}</el-descriptions-item>
      </el-descriptions>

      <div style="margin-top:16px">
        <h4 style="margin-bottom:8px">执行日志</h4>
        <pre class="log-box">{{ task.result_text || '无日志' }}</pre>
      </div>

      <div style="margin-top:16px">
        <el-button type="primary" :disabled="task.status === 'running'" @click="retryTask">重试任务</el-button>
        <el-button type="danger" plain @click="deleteTask" style="margin-left:12px">删除任务</el-button>
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { taskAPI } from '../../api/auth'
import { ElMessage, ElMessageBox } from 'element-plus'

const route = useRoute()
const router = useRouter()
const task = ref(null)

onMounted(loadDetail)

async function loadDetail() {
  const res = await taskAPI.detail(route.params.id)
  if (res.ok) task.value = res.data
}

function statusType(s) {
  if (s === 'success') return 'success'
  if (s === 'failed') return 'danger'
  if (s === 'running') return 'warning'
  return 'info'
}

async function retryTask() {
  try {
    await ElMessageBox.confirm('确认重试此任务？', '提示')
    const res = await taskAPI.retry(route.params.id)
    ElMessage({ type: res.ok ? 'success' : 'error', message: res.msg })
    loadDetail()
  } catch { /* cancel */ }
}

async function deleteTask() {
  try {
    await ElMessageBox.confirm('确认删除此任务？', '警告')
    const res = await taskAPI.delete(route.params.id)
    if (res.ok) {
      ElMessage.success('已删除')
      router.push('/tasks')
    }
  } catch { /* cancel */ }
}
</script>

<style scoped>
.log-box {
  background: #1e1e1e;
  color: #d4d4d4;
  padding: 16px;
  border-radius: 6px;
  max-height: 400px;
  overflow: auto;
  font-size: 12px;
  line-height: 1.5;
  white-space: pre-wrap;
  word-break: break-all;
}
</style>
