import request from './request'

export const authAPI = {
  init: (username, password) => request.post('/api/auth/init', { username, password }),
  login: (username, password) => request.post('/api/auth/login', { username, password }),
  me: () => request.get('/api/auth/me'),
  refresh: () => request.post('/api/auth/refresh'),
}

export const dashboardAPI = {
  stats: () => request.get('/api/dashboard/stats'),
  topAssets: () => request.get('/api/dashboard/top-assets'),
  trend: () => request.get('/api/dashboard/trend'),
}

export const vulnAPI = {
  list: (params) => request.get('/api/vulns', { params }),
  detail: (id) => request.get(`/api/vulns/${id}`),
  update: (id, data) => request.put(`/api/vulns/${id}`, data),
  delete: (id) => request.delete(`/api/vulns/${id}`),
  fix: (id) => request.post(`/api/vulns/${id}/fix`),
  batchFix: (ids) => request.post('/api/vulns/batch-fix', { ids }),
}

export const taskAPI = {
  list: (params) => request.get('/api/tasks', { params }),
  detail: (id) => request.get(`/api/tasks/${id}`),
  delete: (id) => request.delete(`/api/tasks/${id}`),
  retry: (id) => request.post(`/api/tasks/${id}/retry`),
}

export const reportAPI = {
  import: (formData) => request.post('/api/reports/import', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  }),
  history: (params) => request.get('/api/reports/history', { params }),
  deleteHistory: (id) => request.delete(`/api/reports/history/${id}`),
  export: (params) => request.get('/api/reports/export', { params, responseType: 'blob' }),
}

export const settingsAPI = {
  get: () => request.get('/api/settings'),
  update: (data) => request.put('/api/settings', data),
}

export const userAPI = {
  list: () => request.get('/api/users'),
  create: (data) => request.post('/api/users', data),
  update: (id, data) => request.put(`/api/users/${id}`, data),
  delete: (id) => request.delete(`/api/users/${id}`),
  resetPassword: (id, password) => request.put(`/api/users/${id}/password`, { password }),
}
