resource "azurerm_storage_account" "security" {
  name                = var.storage_account_name
  resource_group_name = azurerm_resource_group.security.name
  location            = azurerm_resource_group.security.location

  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_2"
  https_traffic_only_enabled      = true
  allow_nested_items_to_be_public = false
  shared_access_key_enabled       = false # Entra ID + RBAC로만 접근
  public_network_access_enabled = true
  cross_tenant_replication_enabled = false # 다른 테넌트로 객체 복제 유출 경로 차단

  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices", "Logging", "Metrics"]  # ★진단로그 쓰기 허용
    virtual_network_subnet_ids = [
      azurerm_subnet.web.id,
      azurerm_subnet.was.id
    ]
    ip_rules = [var.admin_public_ip]   # 포털/CLI로 로그 볼 때
  }

  immutability_policy {
    state = "Unlocked"
    period_since_creation_in_days = 1    # test로 1일만 지정
    allow_protected_append_writes = true
  }

  blob_properties {
    versioning_enabled = true
    delete_retention_policy {
      days = 7
    }
    container_delete_retention_policy {
      days = 7
    }
  }
}

resource "azurerm_storage_container" "security_data" {
  name                  = "log-data"
  storage_account_id    = azurerm_storage_account.security.id
  container_access_type = "private"
}

resource "azurerm_role_assignment" "tf_storage_blob" {
  scope                = azurerm_storage_account.security.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = data.azurerm_client_config.current.object_id
}
