# MySQL이 Entra ID 토큰을 검증할 때 쓰는 관리 ID (서버 식별 + Entra 관리자 역할 겸용)
resource "azurerm_user_assigned_identity" "mysql" {
  name                = "id-mysql"
  resource_group_name = azurerm_resource_group.infra.name
  location            = azurerm_resource_group.infra.location
}

# WAS 앱이 MySQL 접속에 사용할 최소권한 전용 관리 ID (emp_db DML만)
resource "azurerm_user_assigned_identity" "was_app" {
  name                = "id-was-app"
  resource_group_name = azurerm_resource_group.infra.name
  location            = azurerm_resource_group.infra.location
}

# 로컬 관리자 비밀번호: 생성 시 필수. 사람은 쓰지 않고 Key Vault에 비상용(break-glass)으로만 보관
resource "random_password" "mysql_admin" {
  length           = 24
  special          = true
  override_special = "!#%*-_"
}

resource "azurerm_mysql_flexible_server" "main" {
  name                   = var.mysql_server_name
  resource_group_name    = azurerm_resource_group.infra.name
  location               = azurerm_resource_group.infra.location
  version                = "8.0.21"
  sku_name               = var.mysql_sku
  administrator_login    = var.mysql_admin_username
  administrator_password = random_password.mysql_admin.result

  delegated_subnet_id   = azurerm_subnet.db.id
  private_dns_zone_id   = azurerm_private_dns_zone.mysql.id
  backup_retention_days = 7

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.mysql.id]
  }

  lifecycle {
    ignore_changes = [zone] # Azure가 가용 영역을 자동 지정
  }

  depends_on = [
    azurerm_private_dns_zone_virtual_network_link.mysql_spoke,
    azurerm_private_dns_zone_virtual_network_link.mysql_hub,
  ]
}

resource "azurerm_mysql_flexible_database" "app" {
  name                = var.app_db_name
  resource_group_name = azurerm_resource_group.infra.name
  server_name         = azurerm_mysql_flexible_server.main.name
  charset             = "utf8mb4"
  collation           = "utf8mb4_unicode_ci"
}

# Entra ID 관리자 = id-mysql 관리 ID
# → WAS가 부팅 시 이 ID의 토큰으로 접속해 최소권한 앱 유저(was_app)를 자동 생성(수동 단계 제거)
resource "azurerm_mysql_flexible_server_active_directory_administrator" "main" {
  server_id   = azurerm_mysql_flexible_server.main.id
  identity_id = azurerm_user_assigned_identity.mysql.id
  login       = "id-mysql"
  object_id   = azurerm_user_assigned_identity.mysql.principal_id
  tenant_id   = data.azurerm_client_config.current.tenant_id

  depends_on = [azurerm_mysql_flexible_server_configuration.audit_events]
}

# 서버 보안 파라미터
resource "azurerm_mysql_flexible_server_configuration" "tls" {
  name                = "require_secure_transport"
  resource_group_name = azurerm_resource_group.infra.name
  server_name         = azurerm_mysql_flexible_server.main.name
  value               = "ON"
}

resource "azurerm_mysql_flexible_server_configuration" "audit" {
  name                = "audit_log_enabled"
  resource_group_name = azurerm_resource_group.infra.name
  server_name         = azurerm_mysql_flexible_server.main.name
  value               = "ON"

  # 서버 파라미터를 동시에 바꾸면 ServerBusy 오류가 날 수 있어 순서대로 적용
  depends_on = [azurerm_mysql_flexible_server_configuration.tls]
}

resource "azurerm_mysql_flexible_server_configuration" "audit_events" {
  name                = "audit_log_events"
  resource_group_name = azurerm_resource_group.infra.name
  server_name         = azurerm_mysql_flexible_server.main.name
  value               = "CONNECTION,DDL,DCL,ADMIN,DML_SELECT"
  depends_on = [azurerm_mysql_flexible_server_configuration.audit]
}

# 비밀번호 로그인 전면 차단 (Entra 전용). 앱·프로비저닝 모두 Entra 토큰이라 처음부터 ON 가능.
# break-glass로 team4 비번 접속이 필요하면 일시적으로 OFF 후 사용.
resource "azurerm_mysql_flexible_server_configuration" "entra_only" {
  name                = "aad_auth_only"
  resource_group_name = azurerm_resource_group.infra.name
  server_name         = azurerm_mysql_flexible_server.main.name
  value               = "ON"
  depends_on          = [azurerm_mysql_flexible_server_active_directory_administrator.main]
}
