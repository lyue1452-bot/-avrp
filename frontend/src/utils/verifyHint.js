/** 修复后人工验证说明：成功/失败判定标准 */

function cmd(url, pattern) {
  return `curl -sI "${url}" | findstr /i "${pattern}"`
}

function block(title, url, checkCmd, successLines, failLines, extra = '') {
  return [
    `【${title}】`,
    '验证命令：',
    checkCmd,
    '',
    '✅ 判定为修复成功（响应中应出现）：',
    ...successLines.map(l => `  ${l}`),
    '',
    '❌ 判定为修复失败（出现以下情况）：',
    ...failLines.map(l => `  ${l}`),
    extra ? `\n${extra}` : '',
  ].join('\n')
}

function securityHeadersHint(url, headerName, headerKey, successExample) {
  return block(
    headerName,
    url,
    cmd(url, headerKey),
    [`${headerName}: ${successExample}`],
    [
      '命令无任何输出（该响应头缺失）',
      'curl 无法连接目标 URL',
    ],
    '批量检查全部安全头：.\\scripts\\verify_http_fix.ps1',
  )
}

export function buildVerifyHint(row) {
  const url = row.url || `http://${row.asset_ip}`
  const rule = row.remediation_rule || ''
  const name = (row.vuln_name || '').toLowerCase()

  if (rule === 'apache_server_tokens' || name.includes('server') || name.includes('版本')) {
    return block(
      'Server 版本隐藏',
      url,
      cmd(url, 'Server:'),
      [
        'Server: Apache',
        'Server: Apache/2.4（无 Win64、OpenSSL 等详细版本串也可接受）',
      ],
      [
        'Server: Apache/2.4.39 (Win64) OpenSSL/...（仍带完整版本号）',
        '命令无 Server 行且站点不可访问',
      ],
    )
  }

  if (name.includes('x-content-type-options') || name.includes('content-type-options')) {
    return securityHeadersHint(url, 'X-Content-Type-Options', 'X-Content-Type-Options', 'nosniff')
  }
  if (name.includes('x-frame-options') || name.includes('frame-options') || name.includes('clickjacking')) {
    return securityHeadersHint(url, 'X-Frame-Options', 'X-Frame-Options', 'SAMEORIGIN 或 DENY')
  }
  if (name.includes('referrer-policy') || name.includes('referrer')) {
    return securityHeadersHint(url, 'Referrer-Policy', 'Referrer-Policy', 'strict-origin-when-cross-origin 等有效策略值')
  }
  if (name.includes('content-security-policy') || name.includes('csp')) {
    return securityHeadersHint(url, 'Content-Security-Policy', 'Content-Security-Policy', "default-src 'self' ...")
  }

  if (rule === 'security_headers_bundle') {
    return block(
      'HTTP 安全响应头',
      url,
      cmd(url, 'Referrer-Policy X-Frame X-Content Content-Security'),
      [
        'X-Content-Type-Options: nosniff',
        'X-Frame-Options: SAMEORIGIN',
        'Referrer-Policy: strict-origin-when-cross-origin',
        'Content-Security-Policy: default-src ...',
        '（至少出现与本漏洞相关的一行；4 行全部存在 = 成功）',
      ],
      [
        'findstr 无任何输出',
        '仅有部分头、缺少本漏洞对应的那一项',
        'curl 连接超时或拒绝连接',
      ],
      '一键验证：.\\scripts\\verify_http_fix.ps1',
    )
  }

  if (rule === 'cookie_samesite' || name.includes('samesite')) {
    return block(
      'Cookie SameSite',
      url,
      cmd(url, 'Set-Cookie'),
      [
        'Set-Cookie: ... SameSite=Lax',
        'Set-Cookie: ... SameSite=Strict',
      ],
      [
        'Set-Cookie 中无 SameSite 属性',
        'SameSite=None 且无 Secure（不安全）',
      ],
    )
  }

  if (rule === 'cookie_secure_httponly' || name.includes('httponly') || name.includes('secure')) {
    return block(
      'Cookie Secure / HttpOnly',
      url,
      cmd(url, 'Set-Cookie'),
      ['Set-Cookie: ... HttpOnly', 'Set-Cookie: ... Secure（HTTPS 站点）'],
      ['Set-Cookie 缺少 HttpOnly 或 Secure'],
    )
  }

  return block(
    '通用验证',
    url,
    `# 请根据漏洞描述手动检查 ${url}`,
    ['目标上已不再出现漏洞描述中的问题特征', '重新扫描后该漏洞不再报告'],
    ['漏洞特征仍然存在', '仅平台状态为已修复但环境未变化'],
    '建议修复后重新扫描确认。',
  )
}
