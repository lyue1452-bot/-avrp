$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\ApacheCommon.ps1"

Deploy-ApacheSnippet -FileName 'rayscan-server-tokens.conf' -MatchToken 'rayscan-server-tokens' -Snippet @'
ServerTokens Prod
ServerSignature Off
'@

Restart-ApacheInstances
Write-Output 'NOTE: 若 Server 响应头未变化，请在 phpstudy 面板手动重启 Apache 使 ServerTokens 生效'
