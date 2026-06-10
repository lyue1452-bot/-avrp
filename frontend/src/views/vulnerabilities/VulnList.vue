<template>
  <div>
    <!-- 顶部操作栏 -->
    <el-card shadow="hover" style="margin-bottom:16px">
      <el-row :gutter="12" align="middle">
        <el-col :span="6">
          <el-input v-model="search" placeholder="搜索漏洞名/IP/描述/CVE" clearable @input="onSearch" />
        </el-col>
        <el-col :span="4">
          <el-select v-model="severityFilter" placeholder="严重级别" clearable @change="loadData" style="width:100%">
            <el-option v-for="s in filters.severity" :key="s" :label="s" :value="s" />
          </el-select>
        </el-col>
        <el-col :span="4">
          <el-select v-model="statusFilter" placeholder="修复状态" clearable @change="loadData" style="width:100%">
            <el-option v-for="s in filters.fix_status" :key="s" :label="s" :value="s" />
          </el-select>
        </el-col>
        <el-col :span="4">
          <el-button type="primary" @click="loadData">查询</el-button>
          <el-button @click="resetFilters">重置</el-button>
        </el-col>
        <el-col :span="6" style="text-align:right">
          <el-button @click="reclassifyAll" :loading="reclassifying">重匹配规则</el-button>
          <el-button type="success" :disabled="!selectedIds.length" @click="batchFix">
            批量修复 ({{ selectedIds.length }})
          </el-button>
        </el-col>
      </el-row>
    </el-card>

    <!-- 漏洞表格 -->
    <el-card shadow="hover">
      <el-table :data="vulns" stripe @selection-change="onSelectionChange" v-loading="loading">
        <el-table-column type="selection" width="40" />
        <el-table-column prop="id" label="ID" width="60" sortable />
        <el-table-column prop="source_tool" label="来源" width="80">
          <template #default="{ row }"><el-tag size="small">{{ row.source_tool }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="asset_ip" label="资产" width="140">
          <template #default="{ row }">{{ row.asset_ip }}:{{ row.port }}</template>
        </el-table-column>
        <el-table-column prop="vuln_name" label="漏洞名称" min-width="200" show-overflow-tooltip />
        <el-table-column prop="severity" label="级别" width="100">
          <template #default="{ row }">
            <el-tag :type="severityType(row.severity)" size="small">{{ row.severity }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="cve" label="CVE" width="120" />
        <el-table-column prop="fix_status" label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="statusType(row.fix_status)" size="small">{{ row.fix_status }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="180" fixed="right">
          <template #default="{ row }">
            <el-button size="small" @click="showDetail(row.id)">详情</el-button>
            <el-button size="small" type="danger" @click="fixOne(row.id)">修复</el-button>
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

    <!-- 详情对话框 -->
    <el-dialog v-model="detailVisible" title="漏洞详情" width="700px">
      <template v-if="detail">
        <el-descriptions :column="2" border>
          <el-descriptions-item label="漏洞名称" :span="2">{{ detail.vuln_name }}</el-descriptions-item>
          <el-descriptions-item label="资产">{{ detail.asset_ip }}:{{ detail.port }}</el-descriptions-item>
          <el-descriptions-item label="URL">{{ detail.url || '-' }}</el-descriptions-item>
          <el-descriptions-item label="级别">
            <el-tag :type="severityType(detail.severity)" size="small">{{ detail.severity }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="状态">
            <el-tag :type="statusType(detail.fix_status)" size="small">{{ detail.fix_status }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="CVE" :span="2">{{ detail.cve || '-' }}</el-descriptions-item>
          <el-descriptions-item label="CWE" :span="2">{{ detail.cwe || '-' }}</el-descriptions-item>
          <el-descriptions-item label="来源工具" :span="2">{{ detail.source_tool || '-' }}</el-descriptions-item>
          <el-descriptions-item label="修复规则" :span="2">{{ detail.remediation_rule || '-' }}</el-descriptions-item>
          <el-descriptions-item label="描述" :span="2"><div class="desc-text">{{ detail.description || '-' }}</div></el-descriptions-item>
          <el-descriptions-item label="修复建议" :span="2"><div class="desc-text">{{ detail.solution || '-' }}</div></el-descriptions-item>
          <el-descriptions-item label="最近修复日志" :span="2"><div class="desc-text">{{ detail.last_fix_msg || '-' }}</div></el-descriptions-item>
        </el-descriptions>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { vulnAPI } from '../../api/auth'
import { ElMessage, ElMessageBox } from 'element-plus'

const vulns = ref([])
const loading = ref(false)
const page = ref(1)
const perPage = ref(20)
const total = ref(0)
const search = ref('')
const severityFilter = ref('')
const statusFilter = ref('')
const filters = ref({ severity: [], fix_status: [] })
const selectedIds = ref([])
const detailVisible = ref(false)
const detail = ref(null)
const reclassifying = ref(false)

onMounted(loadData)

async function loadData() {
  loading.value = true
  try {
    const res = await vulnAPI.list({
      page: page.value,
      per_page: perPage.value,
      search: search.value,
      severity: severityFilter.value,
      status: statusFilter.value,
    })
    if (res.ok) {
      vulns.value = res.data
      total.value = res.total
      filters.value = res.filters
    }
  } finally {
    loading.value = false
  }
}

function onSearch() {
  page.value = 1
  loadData()
}

function resetFilters() {
  search.value = ''
  severityFilter.value = ''
  statusFilter.value = ''
  page.value = 1
  loadData()
}

function onSelectionChange(rows) {
  selectedIds.value = rows.map(r => r.id)
}

function severityType(s) {
  if (!s) return 'info'
  if (s.includes('严重') || s.includes('Critical')) return 'danger'
  if (s.includes('高') || s.includes('High')) return 'warning'
  if (s.includes('中') || s.includes('Medium')) return ''
  return 'info'
}

function statusType(s) {
  if (s === 'fixed') return 'success'
  if (s === 'failed') return 'danger'
  if (s === 'fixing') return 'warning'
  if (s === 'auto_fixable') return ''
  return 'info'
}

async function showDetail(id) {
  const res = await vulnAPI.detail(id)
  if (res.ok) {
    detail.value = res.data
    detailVisible.value = true
  }
}

async function reclassifyAll() {
  reclassifying.value = true
  try {
    const res = await vulnAPI.reclassify({})
    ElMessage({ type: res.ok ? 'success' : 'error', message: res.msg })
    if (res.ok) loadData()
  } finally {
    reclassifying.value = false
  }
}

async function fixOne(id) {
  try {
    await ElMessageBox.confirm('确认执行自动修复？', '提示')
    const res = await vulnAPI.fix(id)
    ElMessage({ type: res.ok ? 'success' : 'error', message: res.msg })
    if (res.ok) loadData()
  } catch { /* cancel */ }
}

async function batchFix() {
  if (!selectedIds.value.length) return
  try {
    await ElMessageBox.confirm(`确认批量修复 ${selectedIds.value.length} 个漏洞？`, '提示')
    const res = await vulnAPI.batchFix(selectedIds.value)
    ElMessage.success(`批量修复完成`)
    loadData()
  } catch { /* cancel */ }
}
</script>

<style scoped>
.desc-text { white-space: pre-wrap; max-height: 200px; overflow-y: auto; font-size: 13px; line-height: 1.6; }
</style>
