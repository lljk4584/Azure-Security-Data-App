resource "azurerm_key_vault" "main" {
  name                = var.key_vault_name
  resource_group_name = azurerm_resource_group.security.name
  location            = azurerm_resource_group.security.location
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"

  rbac_authorization_enabled    = true
  purge_protection_enabled      = false # 최종 시연 환경에서는 true
  soft_delete_retention_days    = 7     # 최종 시연 환경에서는 90
  public_network_access_enabled = true  # 1차 배포용. 이후 Private Endpoint로 전환

  network_acls {
    default_action             = "Deny"
    bypass                     = "AzureServices"          # AppGW 등 신뢰 서비스
    virtual_network_subnet_ids = [azurerm_subnet.web.id, azurerm_subnet.was.id]
    ip_rules                   = [var.admin_public_ip]     # TF 비밀 생성/포털용
  }
}

resource "time_sleep" "wait_tf_kv_rbac" {
  depends_on      = [azurerm_role_assignment.sec_kv_admin]
  create_duration = "90s"
}

# 비상용 로컬 관리자 비밀번호를 Key Vault에 보관
resource "azurerm_key_vault_secret" "mysql_admin" {
  name         = "mysql-admin-password"
  value        = random_password.mysql_admin.result
  key_vault_id = azurerm_key_vault.main.id
  depends_on   = [time_sleep.wait_tf_kv_rbac]
}

# Let's Encrypt 인증서 가져오기
resource "azurerm_key_vault_certificate" "appgw" {
  name         = var.certificate_name
  key_vault_id = azurerm_key_vault.main.id

  certificate {
    contents = try(filebase64(var.pfx_path), "")
    password = var.pfx_password
  }

  lifecycle {
    ignore_changes = [certificate]
  }

  depends_on = [time_sleep.wait_tf_kv_rbac]
}

# App GW 관리 ID + Key Vault 비밀 사용자
resource "azurerm_user_assigned_identity" "appgw" {
  name                = "id-appgw"
  resource_group_name = azurerm_resource_group.infra.name
  location            = azurerm_resource_group.infra.location
}

resource "azurerm_role_assignment" "appgw_kv_secrets_user" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.appgw.principal_id
}

resource "time_sleep" "wait_appgw_kv_rbac" {
  depends_on      = [azurerm_role_assignment.appgw_kv_secrets_user]
  create_duration = "90s"
}

# Bastion "Azure Key Vault의 SSH 프라이빗 키" 방식 접속용 개인키 보관
# (VM에 등록된 공개키 id_rsa.pub 와 짝이 되는 id_rsa 개인키)
resource "azurerm_key_vault_secret" "ssh_privatekey" {
  name         = "team4-ssh-privatekey"
  value        = file(var.web_admin_ssh_private_key_path)
  key_vault_id = azurerm_key_vault.main.id
  depends_on   = [time_sleep.wait_tf_kv_rbac]
}