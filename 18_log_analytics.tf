resource "azurerm_log_analytics_workspace" "main" {
  name                = "${var.project_prefix}-law2"
  resource_group_name = azurerm_resource_group.security.name     # Security-RG로 이동
  location            = azurerm_resource_group.security.location
  sku                 = "PerGB2018"
  retention_in_days   = 30

  # 인프라·서비스 관리자가 자기 리소스 로그만 조회 (리소스 컨텍스트 접근)
  allow_resource_only_permissions = true
}

resource "azurerm_sentinel_log_analytics_workspace_onboarding" "main" {
  workspace_id = azurerm_log_analytics_workspace.main.id
}