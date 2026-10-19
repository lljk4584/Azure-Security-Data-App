locals {
  diag_targets = {
    appgw    = azurerm_application_gateway.main.id
    firewall = azurerm_firewall.main.id
    bastion  = azurerm_bastion_host.bastion.id
    keyvault = azurerm_key_vault.main.id
    mysql    = azurerm_mysql_flexible_server.main.id
  }
}

resource "azurerm_monitor_diagnostic_setting" "to_law" {
  for_each                       = local.diag_targets
  name                           = "law"
  target_resource_id             = each.value
  log_analytics_workspace_id     = azurerm_log_analytics_workspace.main.id
  log_analytics_destination_type = "Dedicated" # 리소스별 테이블 (KQL 작성이 편함)

  # 같은 로그를 보안 RG의 Storage에도 장기 보관
  storage_account_id = azurerm_storage_account.security.id

  enabled_log {
    category_group = "allLogs"
  }

  enabled_metric {
    category = "AllMetrics"
  }
}

resource "azurerm_monitor_diagnostic_setting" "storage_blob_law" {
  name                       = "blob-law"
  target_resource_id         = "${azurerm_storage_account.security.id}/blobServices/default"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log { category = "StorageRead" }
  enabled_log { category = "StorageWrite" }
  enabled_log { category = "StorageDelete" }
}
