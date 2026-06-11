/** 漏洞修复状态：内部英文码 → 中文展示 */
export const FIX_STATUS_LABELS = {
  pending: '待处理',
  auto_fixable: '待修复',
  fixing: '修复中',
  fixed: '已修复',
  failed: '修复失败',
  manual_only: '需人工处理',
}

export function fixStatusLabel(status) {
  if (!status) return '未知'
  return FIX_STATUS_LABELS[status] || status
}

export function fixStatusType(status) {
  if (status === 'fixed') return 'success'
  if (status === 'failed') return 'danger'
  if (status === 'fixing') return 'warning'
  if (status === 'auto_fixable') return ''
  if (status === 'manual_only') return 'info'
  return 'info'
}
