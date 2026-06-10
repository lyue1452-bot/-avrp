<template>
  <div>
    <!-- 统计卡片 -->
    <el-row :gutter="16" style="margin-bottom:16px">
      <el-col :span="6" v-for="card in statCards" :key="card.label">
        <el-card shadow="hover">
          <div class="stat-card">
            <div class="stat-value" :style="{ color: card.color }">{{ card.value }}</div>
            <div class="stat-label">{{ card.label }}</div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 图表区 -->
    <el-row :gutter="16">
      <el-col :span="12">
        <el-card shadow="hover">
          <template #header><span style="font-weight:600">严重级别分布</span></template>
          <div ref="severityChart" style="height:300px"></div>
        </el-card>
      </el-col>
      <el-col :span="12">
        <el-card shadow="hover">
          <template #header><span style="font-weight:600">修复状态分布</span></template>
          <div ref="statusChart" style="height:300px"></div>
        </el-card>
      </el-col>
    </el-row>

    <el-row :gutter="16" style="margin-top:16px">
      <el-col :span="12">
        <el-card shadow="hover">
          <template #header><span style="font-weight:600">受影响资产 Top10</span></template>
          <div ref="assetChart" style="height:280px"></div>
        </el-card>
      </el-col>
      <el-col :span="12">
        <el-card shadow="hover">
          <template #header><span style="font-weight:600">近 30 天趋势</span></template>
          <div ref="trendChart" style="height:280px"></div>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted, nextTick } from 'vue'
import { dashboardAPI } from '../../api/auth'
import * as echarts from 'echarts'

const severityChart = ref(null)
const statusChart = ref(null)
const assetChart = ref(null)
const trendChart = ref(null)
let charts = []

const statCards = ref([
  { label: '总漏洞数', value: '...', color: '#409eff' },
  { label: '高危/严重', value: '...', color: '#e6422e' },
  { label: '已修复', value: '...', color: '#67c23a' },
  { label: '修复率', value: '...', color: '#e6a23c' },
])

onMounted(async () => {
  try {
    const res = await dashboardAPI.stats()
    if (res.ok) {
      const d = res.data
      statCards.value = [
        { label: '总漏洞数', value: d.total, color: '#409eff' },
        { label: '高危/严重', value: d.critical + d.high, color: '#e6422e' },
        { label: '已修复', value: d.fixed, color: '#67c23a' },
        { label: '修复率', value: d.fix_rate + '%', color: '#e6a23c' },
      ]

      await nextTick()
      renderSeverity(d.severity_distribution)
      renderStatus(d.status_distribution)
    }

    const assetRes = await dashboardAPI.topAssets()
    if (assetRes.ok) {
      await nextTick()
      renderAssets(assetRes.data)
    }

    const trendRes = await dashboardAPI.trend()
    if (trendRes.ok) {
      await nextTick()
      renderTrend(trendRes.data)
    }
  } catch (e) {
    console.error('Dashboard load failed:', e)
  }
})

onUnmounted(() => {
  charts.forEach(c => c.dispose())
})

function renderSeverity(data) {
  const chart = echarts.init(severityChart.value)
  charts.push(chart)
  chart.setOption({
    tooltip: { trigger: 'item' },
    series: [{
      type: 'pie',
      radius: ['40%', '70%'],
      data: data.map(d => ({ name: d.name, value: d.value })),
      label: { formatter: '{b}\n{d}%' },
    }],
  })
}

function renderStatus(data) {
  const chart = echarts.init(statusChart.value)
  charts.push(chart)
  chart.setOption({
    tooltip: { trigger: 'axis' },
    xAxis: { type: 'category', data: data.map(d => d.name) },
    yAxis: { type: 'value' },
    series: [{
      type: 'bar',
      data: data.map(d => ({ value: d.value, itemStyle: { color: d.name === '已修复' ? '#67c23a' : d.name === '修复失败' ? '#e6422e' : '#409eff' } })),
    }],
  })
}

function renderAssets(data) {
  const chart = echarts.init(assetChart.value)
  charts.push(chart)
  const names = data.map(d => d.asset_ip).reverse()
  const values = data.map(d => d.cnt).reverse()
  chart.setOption({
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
    xAxis: { type: 'value' },
    yAxis: { type: 'category', data: names },
    series: [{ type: 'bar', data: values, itemStyle: { color: '#409eff' } }],
  })
}

function renderTrend(data) {
  const chart = echarts.init(trendChart.value)
  charts.push(chart)
  chart.setOption({
    tooltip: { trigger: 'axis' },
    grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
    xAxis: { type: 'category', data: data.map(d => d.date.slice(5)), boundaryGap: false },
    yAxis: { type: 'value' },
    series: [{
      type: 'line',
      data: data.map(d => d.count),
      smooth: true,
      areaStyle: { opacity: 0.3 },
      lineStyle: { width: 2 },
      itemStyle: { color: '#409eff' },
    }],
  })
}
</script>

<style scoped>
.stat-card { text-align: center; padding: 8px 0; }
.stat-value { font-size: 32px; font-weight: 700; }
.stat-label { font-size: 14px; color: #666; margin-top: 4px; }
</style>
