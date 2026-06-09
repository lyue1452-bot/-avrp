import axios from 'axios'
import { useAuthStore } from '../stores/auth'
import { ElMessage } from 'element-plus'

const request = axios.create({
  baseURL: '',  // 通过 vite proxy 转发
  timeout: 30000,
})

request.interceptors.request.use((config) => {
  const auth = useAuthStore()
  if (auth.token) {
    config.headers.Authorization = `Bearer ${auth.token}`
  }
  return config
})

request.interceptors.response.use(
  (res) => res.data,
  (error) => {
    const resp = error.response
    if (resp && resp.status === 401) {
      const auth = useAuthStore()
      auth.logout()
      window.location.href = '/login'
    }
    const msg = resp?.data?.msg || error.message || '请求失败'
    ElMessage.error(msg)
    return Promise.reject(error)
  }
)

export default request
