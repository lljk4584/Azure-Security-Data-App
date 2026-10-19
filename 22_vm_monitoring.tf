# Web VM 운영 로그(SSH 로그인, sudo 등 Syslog)를 Log Analytics로 수집하고,
# Web VM 관리 ID가 Key Vault의 시크릿을 읽을 수 있게 하는 파일입니다.

# ── 워크스페이스 생성 직후 DCR이 거부되는 문제 방지용 대기 ──
resource "time_sleep" "wait_law_ready" {
  depends_on      = [azurerm_sentinel_log_analytics_workspace_onboarding.main]
  create_duration = "60s"
}

# ── 데이터 수집 규칙: Syslog → Log Analytics ──
resource "azurerm_monitor_data_collection_rule" "web_syslog" {
  name                = "dcr-web-syslog"
  resource_group_name = azurerm_resource_group.security.name
  location            = azurerm_resource_group.security.location
  kind                = "Linux"

  destinations {
    log_analytics {
      name                  = "law"
      workspace_resource_id = azurerm_log_analytics_workspace.main.id
    }
  }

  data_sources {
    syslog {
      name           = "web-syslog"
      streams        = ["Microsoft-Syslog"]
      facility_names = ["auth", "authpriv", "daemon", "syslog", "user", "local6"]
      log_levels     = ["Info", "Notice", "Warning", "Error", "Critical", "Alert", "Emergency"]
    }
  }

  data_flow {
    streams      = ["Microsoft-Syslog"]
    destinations = ["law"]
  }

  depends_on = [time_sleep.wait_law_ready]
}

# ── Azure Monitor Agent 설치 ──
resource "azurerm_virtual_machine_extension" "ama" {
  name                       = "AzureMonitorLinuxAgent"
  virtual_machine_id         = azurerm_linux_virtual_machine.web.id
  publisher                  = "Microsoft.Azure.Monitor"
  type                       = "AzureMonitorLinuxAgent"
  type_handler_version       = "1.0"
  auto_upgrade_minor_version = true
  automatic_upgrade_enabled  = true

  depends_on = [azurerm_firewall_policy_rule_collection_group.main]
}

# ── VM ↔ 데이터 수집 규칙 연결 ──
resource "azurerm_monitor_data_collection_rule_association" "web_syslog" {
  name                    = "dcra-web-syslog"
  target_resource_id      = azurerm_linux_virtual_machine.web.id
  data_collection_rule_id = azurerm_monitor_data_collection_rule.web_syslog.id

  depends_on = [azurerm_virtual_machine_extension.ama]
}

# ── WAS VM: Azure Monitor Agent 설치 (Flask 로그인 로그 수집용) ──
resource "azurerm_virtual_machine_extension" "ama_was" {
  name                       = "AzureMonitorLinuxAgent"
  virtual_machine_id         = azurerm_linux_virtual_machine.was.id
  publisher                  = "Microsoft.Azure.Monitor"
  type                       = "AzureMonitorLinuxAgent"
  type_handler_version       = "1.0"
  auto_upgrade_minor_version = true
  automatic_upgrade_enabled  = true

  depends_on = [azurerm_firewall_policy_rule_collection_group.main]
}

# ── WAS VM ↔ 동일 Syslog 수집 규칙 연결 ──
resource "azurerm_monitor_data_collection_rule_association" "was_syslog" {
  name                    = "dcra-was-syslog"
  target_resource_id      = azurerm_linux_virtual_machine.was.id
  data_collection_rule_id = azurerm_monitor_data_collection_rule.web_syslog.id

  depends_on = [azurerm_virtual_machine_extension.ama_was]
}