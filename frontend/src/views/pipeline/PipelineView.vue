<template>
  <div>
    <!-- ──────── 发起统一扫描 ──────── -->
    <el-card shadow="hover" style="margin-bottom:16px">
      <template #header>
        <span style="font-weight:600">发起统一扫描</span>
      </template>
      <el-form :model="scanForm" label-width="100px">
        <el-row :gutter="16">
          <el-col :span="12">
            <el-form-item label="扫描目标">
              <el-input v-model="scanForm.target" placeholder="IP 地址 / URL / 镜像名 (如 192.168.1.100)" />
            </el-form-item>
          </el-col>
          <el-col :span="12">
            <el-form-item label="扫描后修复">
              <el-switch v-model="scanForm.auto_fix" active-text="自动修复可修复的漏洞" />
            </el-form-item>
          </el-col>
        </el-row>
        <el-form-item label="扫描工具">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
            <el-button size="small" @click="installMissingTools" :loading="installingTools">
              安装缺失工具
            </el-button>
            <el-button size="small" @click="loadTools">刷新工具状态</el-button>
            <span style="font-size:12px;color:#909399">Gitleaks/Trivy/Nmap 支持 winget 自动安装；ZAP 使用内置 Web 探测</span>
          </div>
          <el-checkbox-group v-model="scanForm.tools">
            <el-checkbox v-for="t in availableTools" :key="t.id" :label="t.id" border style="margin-bottom:6px">
              {{ t.name }}
              <el-tag v-if="t.installed" type="success" size="small" style="margin-left:4px">可用</el-tag>
              <el-tag v-else type="warning" size="small" style="margin-left:4px">未安装</el-tag>
            </el-checkbox>
          </el-checkbox-group>
          <div style="font-size:12px;color:#909399;margin-top:4px">
            任务 #8 等历史记录为旧扫描结果；重启后端后重新扫描即可更新工具状态
          </div>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="startScan" :loading="scanning" :disabled="!scanForm.target">
            开始扫描
          </el-button>
          <el-button v-if="activeJob" type="danger" plain @click="cancelScan">
            取消扫描
          </el-button>
          <span v-if="scanning" style="margin-left:12px;color:#909399;font-size:13px">
            扫描中，请勿关闭页面...
          </span>
        </el-form-item>
      </el-form>
    </el-card>

    <!-- ──────── 扫描进度 ──────── -->
    <el-card v-if="activeJob" shadow="hover" style="margin-bottom:16px">
      <template #header>
        <div style="display:flex;align-items:center;justify-content:space-between">
          <span style="font-weight:600">扫描进度 #{{ activeJob.id }}</span>
          <el-tag :type="statusTagType(activeJob.status)" size="small">
            {{ statusLabel(activeJob.status) }}
          </el-tag>
        </div>
      </template>

      <div style="margin-bottom:16px">
        <div style="margin-bottom:6px;font-size:13px;color:#666">
          目标: {{ activeJob.target }}
        </div>
        <el-progress :percentage="progressPercent" :status="progressStatus" />
      </div>

      <el-table :data="toolProgressList" stripe size="small">
        <el-table-column prop="name" label="工具" width="180" />
        <el-table-column label="状态" width="120">
          <template #default="{ row }">
            <el-tag :type="row.tagType" size="small">{{ row.statusText }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="结果" min-width="200">
          <template #default="{ row }">
            <span v-if="row.result" style="font-size:13px">
              发现 {{ row.result.total }} 条
              <template v-if="row.result.auto_fixable">, 可修复 {{ row.result.auto_fixable }} 条</template>
            </span>
            <span v-else-if="row.error" style="color:#e6422e;font-size:13px">{{ row.error }}</span>
          </template>
        </el-table-column>
      </el-table>

      <div v-if="activeJob.summary" style="margin-top:12px;padding:8px 12px;background:#f0f9eb;border-radius:4px;font-size:13px">
        <el-icon style="vertical-align:middle"><SuccessFilled /></el-icon>
        {{ activeJob.summary }}
      </div>
    </el-card>

    <!-- ──────── 扫描历史 + 流水线记录 ──────── -->
    <el-card shadow="hover">
      <template #header>
        <div style="display:flex;align-items:center;justify-content:space-between">
          <span style="font-weight:600">扫描历史</span>
          <el-select v-model="historyView" style="width:140px" @change="loadScanJobs">
            <el-option label="扫描任务" value="scan" />
            <el-option label="流水线记录" value="pipeline" />
          </el-select>
        </div>
      </template>

      <!-- 扫描任务列表 -->
      <template v-if="historyView === 'scan'">
        <el-table :data="scanJobs" stripe v-loading="loadingScanJobs" @row-click="openScanDetail" style="cursor:pointer">
          <el-table-column prop="id" label="#" width="60" />
          <el-table-column prop="target" label="目标" min-width="160" />
          <el-table-column label="工具" min-width="200">
            <template #default="{ row }">
              <el-tag v-for="t in row.tools" :key="t" :type="toolTagType(t)" size="small" style="margin-right:4px;margin-bottom:2px">
                {{ t }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column label="状态" width="100">
            <template #default="{ row }">
              <el-tag :type="statusTagType(row.status)" size="small">{{ statusLabel(row.status) }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="summary" label="结果摘要" min-width="300">
            <template #default="{ row }">
              <span style="font-size:13px;color:#666">{{ row.summary || '-' }}</span>
            </template>
          </el-table-column>
          <el-table-column label="自动修复" width="90">
            <template #default="{ row }">
              <el-tag v-if="row.auto_fix" size="small" type="success">开启</el-tag>
              <el-tag v-else size="small" type="info">关闭</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="created_at" label="时间" width="170" />
          <el-table-column label="操作" width="140">
            <template #default="{ row }">
              <el-button size="small" @click.stop="openScanDetail(row)">详情</el-button>
              <el-button size="small" type="danger" @click.stop="deleteScanJob(row.id)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>
        <el-pagination
          v-model:current-page="scanPage"
          :page-size="20"
          :total="scanTotal"
          layout="total, prev, pager, next"
          style="margin-top:12px;justify-content:center"
          @current-change="loadScanJobs"
        />
      </template>

      <!-- 流水线记录（老视图） -->
      <template v-if="historyView === 'pipeline'">
        <el-table :data="pipelineRuns" stripe v-loading="loadingPipeline">
          <el-table-column prop="id" label="#" width="60" />
          <el-table-column prop="tool" label="工具" width="110">
            <template #default="{ row }">
              <el-tag :type="toolTagType(row.tool)" size="small">{{ row.tool }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="target" label="目标" min-width="180" />
          <el-table-column prop="total" label="发现数" width="80" />
          <el-table-column prop="inserted" label="新增" width="70" />
          <el-table-column prop="details" label="详情" min-width="200">
            <template #default="{ row }">
              <span style="font-size:13px;color:#666">{{ row.details }}</span>
            </template>
          </el-table-column>
          <el-table-column prop="status" label="状态" width="90">
            <template #default="{ row }">
              <el-tag :type="row.status === 'completed' ? 'success' : 'danger'" size="small">
                {{ row.status }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="created_at" label="时间" width="170" />
          <el-table-column label="操作" width="80">
            <template #default="{ row }">
              <el-button size="small" type="danger" @click="deletePipelineRun(row.id)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>
        <el-pagination
          v-model:current-page="pipelinePage"
          :page-size="20"
          :total="pipelineTotal"
          layout="total, prev, pager, next"
          style="margin-top:12px;justify-content:center"
          @current-change="loadPipelineRuns"
        />
      </template>
    </el-card>

    <!-- 扫描任务详情 -->
    <el-dialog v-model="detailVisible" :title="`扫描任务详情 #${detailJob?.id || ''}`" width="820px">
      <template v-if="detailJob">
        <el-descriptions :column="2" border size="small" style="margin-bottom:16px">
          <el-descriptions-item label="目标" :span="2">{{ detailJob.target }}</el-descriptions-item>
          <el-descriptions-item label="状态">
            <el-tag :type="statusTagType(detailJob.status)" size="small">{{ statusLabel(detailJob.status) }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="自动修复">
            <el-tag :type="detailJob.auto_fix ? 'success' : 'info'" size="small">{{ detailJob.auto_fix ? '开启' : '关闭' }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="开始时间">{{ detailJob.started_at || '-' }}</el-descriptions-item>
          <el-descriptions-item label="结束时间">{{ detailJob.finished_at || '-' }}</el-descriptions-item>
          <el-descriptions-item label="结果摘要" :span="2">{{ detailJob.summary || '-' }}</el-descriptions-item>
        </el-descriptions>

        <div style="font-weight:600;margin-bottom:8px">各工具执行结果</div>
        <el-table :data="detailToolList" stripe size="small" style="margin-bottom:16px">
          <el-table-column prop="name" label="工具" width="180" />
          <el-table-column label="状态" width="100">
            <template #default="{ row }">
              <el-tag :type="row.tagType" size="small">{{ row.statusText }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="详情" min-width="280">
            <template #default="{ row }">
              <span v-if="row.result && !row.error" style="font-size:13px">
                发现 {{ row.result.total }} 条
                <template v-if="row.result.auto_fixable != null">，可修复 {{ row.result.auto_fixable }} 条</template>
                <template v-if="row.result.fixed != null">，已修复 {{ row.result.fixed }}/{{ row.result.total }} 条</template>
              </span>
              <span v-else-if="row.error" style="color:#e6422e;font-size:13px">{{ row.error }}</span>
              <span v-else style="color:#909399">-</span>
            </template>
          </el-table-column>
        </el-table>

        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
          <span style="font-weight:600">关联漏洞（{{ detailJob.target }}）</span>
          <el-button size="small" @click="loadDetailVulns(detailJob.id)" :loading="loadingDetailVulns">刷新</el-button>
        </div>
        <el-table :data="detailVulns" stripe size="small" v-loading="loadingDetailVulns" max-height="260">
          <el-table-column prop="id" label="ID" width="55" />
          <el-table-column prop="vuln_name" label="漏洞" min-width="200" show-overflow-tooltip />
          <el-table-column prop="severity" label="级别" width="80" />
          <el-table-column label="可修复" width="70">
            <template #default="{ row }">
              <el-tag :type="row.auto_fixable ? 'success' : 'info'" size="small">{{ row.auto_fixable ? '是' : '否' }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="fix_status" label="状态" width="90" />
        </el-table>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { pipelineAPI } from '../../api/auth'
import { ElMessage, ElMessageBox } from 'element-plus'

// ── 工具列表 ──
const availableTools = ref([])
const installingTools = ref(false)
async function loadTools() {
  try {
    const res = await pipelineAPI.tools()
    if (res.ok) availableTools.value = res.data
  } catch { /* ignore */ }
}

async function installMissingTools() {
  installingTools.value = true
  try {
    const res = await pipelineAPI.installTools({})
    if (res.ok) {
      ElMessage.success(res.msg || '安装完成，请刷新工具状态')
    } else {
      const manual = (res.results || []).map(r => r.manual).filter(Boolean).join('；')
      ElMessage.warning((res.msg || '部分工具安装失败') + (manual ? `：${manual}` : ''))
    }
    await loadTools()
  } catch {
    ElMessage.error('安装请求失败')
  } finally {
    installingTools.value = false
  }
}

// ── 扫描表单 ──
const scanForm = ref({
  target: '',
  tools: [],
  auto_fix: true,
})
const scanning = ref(false)
const activeJob = ref(null)
const pollTimer = ref(null)

function startScan() {
  if (!scanForm.value.target) return
  scanning.value = true
  const tools = scanForm.value.tools.length > 0 ? scanForm.value.tools : []
  pipelineAPI.createScan({
    target: scanForm.value.target,
    tools: tools,
    auto_fix: scanForm.value.auto_fix,
  }).then(res => {
    if (res.ok) {
      ElMessage.success('扫描任务已创建')
      activeJob.value = { id: res.job_id, status: 'pending', target: scanForm.value.target, progress: {}, results: {}, summary: '' }
      startPolling(res.job_id)
    } else {
      ElMessage.error(res.msg || '创建失败')
      scanning.value = false
    }
  }).catch(e => {
    ElMessage.error('创建扫描任务失败')
    scanning.value = false
  })
}

function startPolling(jobId) {
  pollTimer.value = setInterval(async () => {
    try {
      const res = await pipelineAPI.scanStatus(jobId)
      if (res.ok) {
        activeJob.value = res.data
        if (['completed', 'failed', 'cancelled'].includes(res.data.status)) {
          stopPolling()
          scanning.value = false
          loadScanJobs()
          if (res.data.status === 'completed') {
            ElMessage.success('扫描完成')
          } else if (res.data.status === 'failed') {
            ElMessage.warning('扫描异常结束')
          }
        }
      }
    } catch { /* ignore */ }
  }, 1500)
}

function stopPolling() {
  if (pollTimer.value) {
    clearInterval(pollTimer.value)
    pollTimer.value = null
  }
}

function cancelScan() {
  if (!activeJob.value) return
  pipelineAPI.cancelScan(activeJob.value.id).then(res => {
    if (res.ok) {
      ElMessage.success('已取消扫描')
      stopPolling()
      scanning.value = false
      loadScanJobs()
    }
  })
}

// ── 进度计算 ──
const progressPercent = computed(() => {
  if (!activeJob.value) return 0
  const tools = activeJob.value.tools || []
  if (tools.length === 0) return 0
  const progress = activeJob.value.progress || {}
  const completed = tools.filter(t => ['completed', 'failed'].includes(progress[t])).length
  return Math.round((completed / tools.length) * 100)
})

const progressStatus = computed(() => {
  if (!activeJob.value) return ''
  if (activeJob.value.status === 'completed') return 'success'
  if (activeJob.value.status === 'failed') return 'exception'
  if (activeJob.value.status === 'cancelled') return 'warning'
  return ''
})

const toolProgressList = computed(() => {
  if (!activeJob.value) return []
  const tools = activeJob.value.tools || []
  const progress = activeJob.value.progress || {}
  const results = activeJob.value.results || {}
  return tools.map(t => ({
    name: toolLabel(t),
    tool: t,
    statusText: progressText(progress[t]),
    tagType: progressTagType(progress[t]),
    result: results[t] || null,
    error: results[t]?.error || null,
  }))
})

function toolLabel(t) {
  const found = availableTools.value.find(a => a.id === t)
  return found ? found.name : t
}

function progressText(s) {
  const m = { pending: '等待中', running: '运行中', completed: '已完成', failed: '失败' }
  return m[s] || s || '等待中'
}

function progressTagType(s) {
  const m = { pending: 'info', running: 'warning', completed: 'success', failed: 'danger' }
  return m[s] || 'info'
}

function statusLabel(s) {
  const m = { pending: '等待中', running: '运行中', completed: '已完成', failed: '失败', cancelled: '已取消' }
  return m[s] || s || '未知'
}

function statusTagType(s) {
  const m = { pending: 'info', running: 'warning', completed: 'success', failed: 'danger', cancelled: 'info' }
  return m[s] || 'info'
}

// ── 扫描历史 ──
const historyView = ref('scan')
const scanJobs = ref([])
const scanPage = ref(1)
const scanTotal = ref(0)
const loadingScanJobs = ref(false)

async function loadScanJobs() {
  loadingScanJobs.value = true
  try {
    const res = await pipelineAPI.scanJobs({ page: scanPage.value, per_page: 20 })
    if (res.ok) {
      scanJobs.value = res.data
      scanTotal.value = res.total
    }
  } finally {
    loadingScanJobs.value = false
  }
}

async function deleteScanJob(id) {
  try {
    await ElMessageBox.confirm('确认删除？', '提示')
    const res = await pipelineAPI.deleteScanJob(id)
    if (res.ok) {
      ElMessage.success('已删除')
      loadScanJobs()
    }
  } catch { /* cancel */ }
}

// ── 扫描任务详情 ──
const detailVisible = ref(false)
const detailJob = ref(null)
const detailVulns = ref([])
const loadingDetailVulns = ref(false)

const detailToolList = computed(() => {
  if (!detailJob.value) return []
  const tools = detailJob.value.tools || []
  const progress = detailJob.value.progress || {}
  const results = detailJob.value.results || {}
  return tools.map(t => ({
    name: toolLabel(t),
    tool: t,
    statusText: progressText(progress[t]),
    tagType: progressTagType(progress[t]),
    result: results[t] || null,
    error: results[t]?.error || null,
  }))
})

async function openScanDetail(row) {
  try {
    const res = await pipelineAPI.scanStatus(row.id)
    if (res.ok) {
      detailJob.value = res.data
      detailVisible.value = true
      loadDetailVulns(row.id)
    }
  } catch {
    detailJob.value = row
    detailVisible.value = true
    loadDetailVulns(row.id)
  }
}

async function loadDetailVulns(jobId) {
  loadingDetailVulns.value = true
  try {
    const res = await pipelineAPI.scanJobVulns(jobId)
    if (res.ok) detailVulns.value = res.data
  } finally {
    loadingDetailVulns.value = false
  }
}

// ── 流水线记录 ──
const pipelineRuns = ref([])
const pipelinePage = ref(1)
const pipelineTotal = ref(0)
const loadingPipeline = ref(false)

async function loadPipelineRuns() {
  loadingPipeline.value = true
  try {
    const res = await pipelineAPI.runs({ page: pipelinePage.value, per_page: 20 })
    if (res.ok) {
      pipelineRuns.value = res.data
      pipelineTotal.value = res.total
    }
  } finally {
    loadingPipeline.value = false
  }
}

async function deletePipelineRun(id) {
  try {
    await ElMessageBox.confirm('确认删除？', '提示')
    const res = await pipelineAPI.deleteRun(id)
    if (res.ok) {
      ElMessage.success('已删除')
      loadPipelineRuns()
    }
  } catch { /* cancel */ }
}

function toolTagType(tool) {
  const map = {
    trivy: 'danger', zap: 'warning', gitleaks: '',
    nmap: 'info', weakpass: '', db_scan: 'success',
    semgrep: 'warning', nuclei: '', nessus: 'info', burp: '',
  }
  return map[tool] || ''
}

onMounted(() => {
  loadTools()
  loadScanJobs()
  // 默认勾选所有工具
  pipelineAPI.tools().then(res => {
    if (res.ok) scanForm.value.tools = res.data.map(t => t.id)
  }).catch(() => {})
})

onUnmounted(() => {
  stopPolling()
})
</script>

<style scoped>
.el-checkbox { margin-right: 8px; }
</style>