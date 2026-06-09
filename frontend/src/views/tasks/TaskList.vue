<template>
  <div>
    <el-card shadow="hover">
      <template #header>
        <div style="display:flex;justify-content:space-between;align-items:center">
          <span style="font-weight:600">修复任务列表</span>
          <el-select v-model="statusFilter" placeholder="状态筛选" clearable style="width:140px" @change="loadData">
            <el-option label="执行中" value="running" />
            <el-option label="成功" value="success" />
            <el-option label="失败" value="failed" />
            <el-option label="等待中" value="pending" />
          </el-select>
        </div>
      </template>

      <el-table :data="tasks" stripe v-loading="loading">
        <el-table-column prop="id" label="ID" width="60" />
        <el-table-column prop="vuln_id" label="漏洞ID" width="70" />
        <el-table-column prop="rule_id" label="规则" width="140" />
        <el-table-column prop="target_ip" label="目标" width="140" />
        <el-table-column label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="taskStatusType(row.status)" size="small">{{ row.status }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="created_at" label="创建时间" width="170" />
        <el-table-column prop="started_at" label="开始时间" width="170" />
        <el-table-column prop="finished_at" label="完成时间" width="170" />
        <el-table-column label="操作" width="140" fixed="right">
          <template #default="{ row }">
            <el-button size="small" @click="showDetail(row.id)">详情</el-button>
            <el-button size="small" type="primary" :disabled="row.status === 'running'" @click="retryTask(row.id)">重试</el-button>
          </template>
        </el-table-column>
      </el-table>

      <el-pagination
        v-model:current-page="page"
        :page-size="perPage"
        :total="total"
        layout="total, prev, pager, next"
        style="margin-top:16px;justify-content:center"
        @current-change="loadData"
      />
    </el-card>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { taskAPI } from '../../api/auth'
import { ElMessage, ElMessageBox } from 'element-plus'

const router = useRouter()
const tasks = ref([])
const loading = ref(false)
const page = ref(1)
const perPage = ref(20)
const total = ref(0)
const statusFilter = ref('')

onMounted(loadData)

async function loadData() {
  loading.value = true
  try {
    const res = await taskAPI.list({ page: page.value, per_page: perPage.value, status: statusFilter.value })
    if (res.ok) {
      tasks.value = res.data
      total.value = res.total
    }
  } finally {
    loading.value = false
  }
}

function taskStatusType(s) {
  if (s === 'success') return 'success'
  if (s === 'failed') return 'danger'
  if (s === 'running') return 'warning'
  return 'info'
}

function showDetail(id) {
  router.push(`/tasks/${id}`)
}

async function retryTask(id) {
  try {
    await ElMessageBox.confirm('确认重试此任务？', '提示')
    const res = await taskAPI.retry(id)
    ElMessage({ type: res.ok ? 'success' : 'error', message: res.msg })
    loadData()
  } catch { /* cancel */ }
}
</script>
