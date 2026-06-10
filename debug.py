from app import create_app
app = create_app()

with app.test_client() as c:
      # 先登录获取 token
      c.post('/api/auth/init', json={'username':'admin','password':'admin123'})
      r = c.post('/api/auth/login', json={'username':'admin','password':'admin123'})
      if r.status_code != 200:
          print(f'LOGIN FAILED: {r.status_code} {r.data[:200]}')
          exit()

      token = r.get_json()['access_token']
      h = {'Authorization': f'Bearer {token}'}

      # 测试关键端点
      for path in ['/api/dashboard/stats', '/api/dashboard/top-assets', '/api/dashboard/trend', '/api/pipeline/tools']:
          r = c.get(path, headers=h)
          ok = 'OK' if r.status_code == 200 else 'FAIL'
          print(f'{ok} {r.status_code} GET {path}')
          if r.status_code != 200:
              print(f'  BODY: {r.data[:300]}')