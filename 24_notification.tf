# ─────────────────────────────────────────────────────────────
# 인시던트 알림: Sentinel High 인시던트 → Gmail
# (테넌트에 Exchange 라이선스가 없어 Logic App 메일 대신 Azure Monitor 경보 사용)
# ─────────────────────────────────────────────────────────────

# 작업 그룹: 경보가 울리면 메일 발송
resource "azurerm_monitor_action_group" "soc" {
  name                = "${var.project_prefix}-work"
  resource_group_name = azurerm_resource_group.security.name
  short_name          = "team4soc" # 메일 제목에 표시 (최대 12자)

  email_receiver {
    name                    = "soc-email"
    email_address           = var.alert_email
    use_common_alert_schema = true
  }
    email_receiver {
    name                    = "soc-email-backup"
    email_address           = var.alert_email_backup
    use_common_alert_schema = true
  }
}

# 경보 규칙: 새로 생긴 High 인시던트 확인
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "sentinel_high" {
  name                 = "${var.project_prefix}-alert-sentinel-high"
  resource_group_name  = azurerm_resource_group.security.name
  location             = azurerm_resource_group.security.location
  display_name         = "[team4] Sentinel 심각도 높음 인시던트 발생"
  description          = "Sentinel에 심각도 High 인시던트가 새로 생성되면 보안 담당자에게 메일 발송"
  severity             = 1
  evaluation_frequency = "PT5M"
  window_duration      = "PT10M" # 로그 수집 지연을 감안해 2배로 확인
  scopes               = [azurerm_log_analytics_workspace.main.id]

  criteria {
    query = <<-KQL
      SecurityIncident
      | summarize arg_min(TimeGenerated, *) by IncidentNumber
      | where Severity == "High" and Status == "New"
      | where datetime_diff('second', LastModifiedTime, CreatedTime) < 60
      | project TimeGenerated, IncidentNumber = tostring(IncidentNumber), Title, Severity, IncidentUrl
    KQL

    time_aggregation_method = "Count"
    operator                = "GreaterThan"
    threshold               = 0

    # 인시던트별로 따로 경보가 생기고 메일에 번호·제목이 표시됨
    dimension {
      name     = "IncidentNumber"
      operator = "Include"
      values   = ["*"]
    }
    dimension {
      name     = "Title"
      operator = "Include"
      values   = ["*"]
    }

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  auto_mitigation_enabled = false

  action {
    action_groups = [azurerm_monitor_action_group.soc.id]
  }

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.main]
}

# 경보 규칙: 새로 생긴 Medium 인시던트 확인 → 동일 작업 그룹(soc)으로 메일
# (High는 위 규칙에서 처리. 내부 탐지 규칙 중 Medium: NSG·방화벽 변경, DB 사용자/권한 변경 등)
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "sentinel_medium" {
  name                 = "${var.project_prefix}-alert-sentinel-medium"
  resource_group_name  = azurerm_resource_group.security.name
  location             = azurerm_resource_group.security.location
  display_name         = "[team4] Sentinel 심각도 중간 인시던트 발생"
  description          = "Sentinel에 심각도 Medium 인시던트가 새로 생성되면 보안 담당자에게 메일 발송"
  severity             = 2
  evaluation_frequency = "PT5M"
  window_duration      = "PT10M" # 로그 수집 지연을 감안해 2배로 확인
  scopes               = [azurerm_log_analytics_workspace.main.id]

  criteria {
    query = <<-KQL
      SecurityIncident
      | summarize arg_min(TimeGenerated, *) by IncidentNumber
      | where Severity == "Medium" and Status == "New"
      | where datetime_diff('second', LastModifiedTime, CreatedTime) < 60
      | project TimeGenerated, IncidentNumber = tostring(IncidentNumber), Title, Severity, IncidentUrl
    KQL

    time_aggregation_method = "Count"
    operator                = "GreaterThan"
    threshold               = 0

    dimension {
      name     = "IncidentNumber"
      operator = "Include"
      values   = ["*"]
    }
    dimension {
      name     = "Title"
      operator = "Include"
      values   = ["*"]
    }

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  auto_mitigation_enabled = false

  action {
    action_groups = [azurerm_monitor_action_group.soc.id]
  }

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.main]
}