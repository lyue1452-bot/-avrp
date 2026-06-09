<template>
  <div>
    <el-card shadow="hover">
      <template #header>
        <div style="display:flex;justify-content:space-between;align-items:center">
          <span style="font-weight:600">用户管理</span>
          <el-button type="primary" size="small" @click="showCreate = true">新增用户</el-button>
        </div>
      </template>

      <el-table :data="users" stripe v-loading="loading">
        <el-table-column prop="id" label="ID" width="60" />
        <el-table-column prop="username" label="用户名" width="140" />
        <el-table-column prop="display_name" label="显示名" width="140" />
        <el-table-column prop="role" label="角色" width="80">
          <template #default="{ row }">
            <el-tag :type="row.role === 'admin' ? 'danger' : 'info'" size="small">{{ row.role }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="80">
          <template #default="{ row }">
            <el-tag :type="row.is_active ? 'success' : 'info'" size="small">
              {{ row.is_active ? '启用' : '禁用' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="created_at" label="创建时间" width="170" />
        <el-table-column label="操作" width="260">
          <template #default="{ row }">
            <el-button size="small" @click="editUser(row)">编辑</el-button>
            <el-button size="small" @click="resetPwd(row)">重置密码</el-button>
            <el-button size="small" type="danger" @click="deleteUser(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- 新增用户对话框 -->
    <el-dialog v-model="showCreate" title="新增用户" width="450px">
      <el-form :model="createForm" label-width="100px">
        <el-form-item label="用户名">
          <el-input v-model="createForm.username" />
        </el-form-item>
        <el-form-item label="密码">
          <el-input v-model="createForm.password" type="password" show-password />
        </el-form-item>
        <el-form-item label="显示名">
          <el-input v-model="createForm.display_name" />
        </el-form-item>
        <el-form-item label="角色">
          <el-select v-model="createForm.role" style="width:100%">
            <el-option label="管理员" value="admin" />
            <el-option label="普通用户" value="user" />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showCreate = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="handleCreate">创建</el-button>
      </template>
    </el-dialog>

    <!-- 编辑用户对话框 -->
    <el-dialog v-model="showEdit" title="编辑用户" width="450px">
      <el-form :model="editForm" label-width="100px">
        <el-form-item label="用户名">
          <el-input v-model="editForm.username" disabled />
        </el-form-item>
        <el-form-item label="显示名">
          <el-input v-model="editForm.display_name" />
        </el-form-item>
        <el-form-item label="角色">
          <el-select v-model="editForm.role" style="width:100%">
            <el-option label="管理员" value="admin" />
            <el-option label="普通用户" value="user" />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showEdit = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="handleEdit">保存</el-button>
      </template>
    </el-dialog>

    <!-- 重置密码对话框 -->
    <el-dialog v-model="showPwd" title="重置密码" width="400px">
      <el-form :model="pwdForm" label-width="100px">
        <el-form-item label="新密码">
          <el-input v-model="pwdForm.password" type="password" show-password />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showPwd = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="handleResetPwd">确认</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { userAPI } from '../../api/auth'
import { ElMessage, ElMessageBox } from 'element-plus'

const users = ref([])
const loading = ref(false)
const saving = ref(false)

const showCreate = ref(false)
const showEdit = ref(false)
const showPwd = ref(false)
const editTarget = ref(null)

const createForm = ref({ username: '', password: '', display_name: '', role: 'user' })
const editForm = ref({ username: '', display_name: '', role: 'user' })
const pwdForm = ref({ password: '' })

onMounted(loadUsers)

async function loadUsers() {
  loading.value = true
  try {
    const res = await userAPI.list()
    if (res.ok) users.value = res.data
  } finally {
    loading.value = false
  }
}

async function handleCreate() {
  saving.value = true
  try {
    const res = await userAPI.create(createForm.value)
    if (res.ok) {
      ElMessage.success('用户已创建')
      showCreate.value = false
      createForm.value = { username: '', password: '', display_name: '', role: 'user' }
      loadUsers()
    }
  } finally {
    saving.value = false
  }
}

function editUser(row) {
  editTarget.value = row
  editForm.value = { username: row.username, display_name: row.display_name, role: row.role }
  showEdit.value = true
}

async function handleEdit() {
  saving.value = true
  try {
    const res = await userAPI.update(editTarget.value.id, {
      display_name: editForm.value.display_name,
      role: editForm.value.role,
    })
    if (res.ok) {
      ElMessage.success('已更新')
      showEdit.value = false
      loadUsers()
    }
  } finally {
    saving.value = false
  }
}

function resetPwd(row) {
  editTarget.value = row
  pwdForm.value = { password: '' }
  showPwd.value = true
}

async function handleResetPwd() {
  saving.value = true
  try {
    const res = await userAPI.resetPassword(editTarget.value.id, pwdForm.value.password)
    if (res.ok) {
      ElMessage.success('密码已重置')
      showPwd.value = false
    }
  } finally {
    saving.value = false
  }
}

async function deleteUser(row) {
  try {
    await ElMessageBox.confirm(`确认删除用户 "${row.username}"？`, '警告')
    const res = await userAPI.delete(row.id)
    if (res.ok) {
      ElMessage.success('已删除')
      loadUsers()
    }
  } catch { /* cancel */ }
}
</script>
