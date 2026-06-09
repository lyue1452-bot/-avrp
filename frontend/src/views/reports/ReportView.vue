<template>
  <div>
    <el-row :gutter="16">
      <!-- 导入区域 -->
      <el-col :span="12">
        <el-card shadow="hover">
          <template #header><span style="font-weight:600">导入报告</span></template>
          <el-upload
            drag
            action="#"
            :auto-upload="false"
            :show-file-list="true"
            :on-change="onFileChange"
            accept=".json,.jsonl,.xml,.csv,.nessus,.md,.markdown"
          >
            <el-icon :size="40"><UploadFilled /></el-icon>
            <div style="margin-top:8px">拖拽或点击选择报告文件</div>
          </el-upload>

          <div style="margin-top:12px">
            <el-upload
              action="#"
              :auto-upload="false"
              :show-file-list="true"
              :on-change="onMappingChange"
              accept=".yaml,.yml"
            >
              <el-button size="small">选择映射文件（可选）</el-button>
            </el-upload>
          </div>

          <el-button type="primary" style="width:100%;margin-top:12px" :loading="importing" @click="importReport">
            开始导入
          </el-button>

          <div v-if="importMsg" :class="['import-msg', importOk ? 'success' : 'error']" style="margin-top:12px">
            {{ importMsg }}
          </div>
        </el-card>
      </el-col>

      <!-- 导出区域 -->
      <el-col :span="12">
        <el-card shadow="hover">
          <template #header><span style="font-weight:600">导出报告</span></template>
          <p style="color:#666;font-size:13px;margin-bottom:16px">导出漏洞数据，支持 JSON 和 CSV 格式</p>
          <div style="display:flex;align-items:center;justify-content:space-between">
            <el-radio-group v-model="exportFormat">
              <el-radio value="json">JSON</el-radio>
              <el-radio value="csv">CSV</el-radio>
            </el-radio-group>
            <el-button type="primary" @click="exportReport">
              导出 ({{ exportFormat.toUpperCase() }})
            </el-button>
          </div>
        </el-card>

        <!-- 导出筛选 -->
        <el-card shadow="hover" style="margin-top:16px">
          <template #header><span style="font-weight:600">导出筛选</span></template>
          <el-select v-model="exportSeverity" placeholder="级别筛选" clearable style="width:100%;margin-bottom:12px">
            <el-option v-for="s in severityOptions" :key="s" :label="s" :value="s" />
          </el-select>
          <el-select v-model="exportStatus" placeholder="状态筛选" clearable style="width:100%">
            <el-option label="已修复" value="fixed" />
            <el-option label="修复失败" value="failed" />
            <el-option label="待修复" value="pending" />
          </el-select>
        </el-card>
      </el-col>
    </el-row>

    <!-- 导入历史 -->
    <el-card shadow="hover" style="margin-top:16px">
      <template #header><span style="font-weight:600">导入历史</span></template>
      <el-table :data="history" stripe v-loading="loading">
        <el-table-column prop="id" label="ID" width="60" />
        <el-table-column prop="filename" label="文件名" min-width="180" />
        <el-table-column prop="source_tool" label="来源" width="100" />
        <el-table-column prop="total" label="总数" width="60" />
        <el-table-column prop="inserted" label="新增" width="60" />
        <el-table-column prop="updated" label="更新" width="60" />
        <el-table-column prop="auto_fixable" label="可修复" width="70" />
        <el-table-column prop="created_at" label="时间" width="170" />
        <el-table-column label="操作" width="80">
          <template #default="{ row }">
            <el-button size="small" type="danger" @click="deleteHistory(row.id)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
      <el-pagination
        v-model:current-page="histPage"
        :page-size="20"
        :total="histTotal"
        layout="total, prev, pager, next"
        style="margin-top:12px;justify-content:center"
        @current-change="loadHistory"
      />
    </el-card>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { reportAPI } from '../../api/auth'
import { ElMessage, ElMessageBox } from 'element-plus'

const history = ref([])
const loading = ref(false)
const histPage = ref(1)
const histTotal = ref(0)

const importFile = ref(null)
const mappingFile = ref(null)
const importing = ref(false)
const importMsg = ref('')
const importOk = ref(false)

const exportFormat = ref('json')
const exportSeverity = ref('')
const exportStatus = ref('')
const severityOptions = ref(['严重', '高危', '中危', '低危', 'Critical', 'High', 'Medium', 'Low'])

onMounted(loadHistory)

async function loadHistory() {
  loading.value = true
  try {
    const res = await reportAPI.history({ page: histPage.value, per_page: 20 })
    if (res.ok) {
      history.value = res.data
      histTotal.value = res.total
    }
  } finally {
    loading.value = false
  }
}

function onFileChange(uf) {
  importFile.value = uf.raw
  importMsg.value = ''
}

function onMappingChange(uf) {
  mappingFile.value = uf.raw
}

async function importReport() {
  if (!importFile.value) {
    ElMessage.warning('请选择报告文件')
    return
  }
  importing.value = true
  importMsg.value = ''
  try {
    const fd = new FormData()
    fd.append('report', importFile.value)
    if (mappingFile.value) fd.append('mapping', mappingFile.value)
    const res = await reportAPI.import(fd)
    importMsg.value = res.msg
    importOk.value = true
    loadHistory()
  } catch (e) {
    importMsg.value = '导入失败'
    importOk.value = false
  } finally {
    importing.value = false
  }
}

async function exportReport() {
  try {
    const blob = await reportAPI.export({
      format: exportFormat.value,
      severity: exportSeverity.value,
      status: exportStatus.value,
    })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `rayscan_export.${exportFormat.value}`
    a.click()
    URL.revokeObjectURL(url)
    ElMessage.success('导出成功')
  } catch (e) {
    ElMessage.error('导出失败')
  }
}

async function deleteHistory(id) {
  try {
    await ElMessageBox.confirm('确认删除？', '提示')
    const res = await reportAPI.deleteHistory(id)
    if (res.ok) {
      ElMessage.success('已删除')
      loadHistory()
    }
  } catch { /* cancel */ }
}
</script>

<style scoped>
.import-msg { padding: 8px 12px; border-radius: 4px; font-size: 13px; }
.import-msg.success { background: #f0f9eb; color: #67c23a; }
.import-msg.error { background: #fef0f0; color: #e6422e; }
</style>
