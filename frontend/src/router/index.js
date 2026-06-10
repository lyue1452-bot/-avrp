import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '../stores/auth'
import MainLayout from '../layouts/MainLayout.vue'
import LoginView from '../views/login/LoginView.vue'
import DashboardView from '../views/dashboard/DashboardView.vue'
import VulnList from '../views/vulnerabilities/VulnList.vue'
import VulnDetail from '../views/vulnerabilities/VulnDetail.vue'
import TaskList from '../views/tasks/TaskList.vue'
import TaskDetail from '../views/tasks/TaskDetail.vue'
import ReportView from '../views/reports/ReportView.vue'
import PipelineView from '../views/pipeline/PipelineView.vue'
import SettingsView from '../views/settings/SettingsView.vue'
import UserList from '../views/users/UserList.vue'

const routes = [
  { path: '/login', component: LoginView, meta: { noAuth: true } },
  {
    path: '/',
    component: MainLayout,
    redirect: '/dashboard',
    children: [
      { path: 'dashboard', component: DashboardView, meta: { title: '数据看板' } },
      { path: 'vulnerabilities', component: VulnList, meta: { title: '漏洞库' } },
      { path: 'vulnerabilities/:id', component: VulnDetail, meta: { title: '漏洞详情' } },
      { path: 'tasks', component: TaskList, meta: { title: '任务管理' } },
      { path: 'tasks/:id', component: TaskDetail, meta: { title: '任务详情' } },
      { path: 'reports', component: ReportView, meta: { title: '报告管理' } },
      { path: 'pipeline', component: PipelineView, meta: { title: '流水线' } },
      { path: 'settings', component: SettingsView, meta: { title: '系统设置' } },
      { path: 'users', component: UserList, meta: { title: '用户管理' } },
    ],
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

router.beforeEach((to, _, next) => {
  const auth = useAuthStore()
  if (!to.meta.noAuth && !auth.isAuthenticated) {
    return next('/login')
  }
  if (to.path === '/login' && auth.isAuthenticated) {
    return next('/dashboard')
  }
  next()
})

export default router
