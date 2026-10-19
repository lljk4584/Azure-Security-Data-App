# ─────────────────────────────────────────────────────────────
# 자동 대응: 외부 공격 인시던트의 공격 IP → WAF 차단 목록에 자동 추가
# 흐름: SecurityIncident 경보 → 작업 그룹 → Logic App(HTTP) → WAF 정책 PUT + 인시던트 댓글
# ─────────────────────────────────────────────────────────────

resource "azurerm_logic_app_workflow" "autoblock" {
  name                = "${var.project_prefix}-waf-autoblock"
  resource_group_name = azurerm_resource_group.security.name
  location            = azurerm_resource_group.security.location

  identity {
    type = "SystemAssigned"
  }
}

# 최소 권한: WAF 정책 하나만 수정 가능
resource "azurerm_role_assignment" "autoblock_waf" {
  scope                = azurerm_web_application_firewall_policy.main.id
  role_definition_name = "Network Contributor"
  principal_id         = azurerm_logic_app_workflow.autoblock.identity[0].principal_id
}

# 인시던트 댓글 작성용
resource "azurerm_role_assignment" "autoblock_sentinel" {
  scope                = azurerm_log_analytics_workspace.main.id
  role_definition_name = "Microsoft Sentinel Responder"
  principal_id         = azurerm_logic_app_workflow.autoblock.identity[0].principal_id
}

# 트리거: 작업 그룹이 호출하는 HTTP 엔드포인트
resource "azurerm_logic_app_trigger_http_request" "alert" {
  name         = "alert-web"
  logic_app_id = azurerm_logic_app_workflow.autoblock.id
  schema       = "{}"
}

# 1. 경보 차원에서 공격 IP / 인시던트 ID 꺼내기
resource "azurerm_logic_app_action_custom" "filter_ip" {
  name         = "Filter_ip"
  logic_app_id = azurerm_logic_app_workflow.autoblock.id
  body = jsonencode({
    type = "Query"
    inputs = {
      from  = "@triggerBody()?['data']?['alertContext']?['condition']?['allOf']?[0]?['dimensions']"
      where = "@equals(item()?['name'], 'ClientIp')"
    }
    runAfter = {}
  })
}

resource "azurerm_logic_app_action_custom" "filter_incident" {
  name         = "Filter_incident"
  logic_app_id = azurerm_logic_app_workflow.autoblock.id
  body = jsonencode({
    type = "Query"
    inputs = {
      from  = "@triggerBody()?['data']?['alertContext']?['condition']?['allOf']?[0]?['dimensions']"
      where = "@equals(item()?['name'], 'IncidentName')"
    }
    runAfter = {}
  })
}

# 2. 현재 WAF 정책 읽기
resource "azurerm_logic_app_action_custom" "get_policy" {
  name         = "Get_policy"
  logic_app_id = azurerm_logic_app_workflow.autoblock.id
  body = jsonencode({
    type = "Http"
    inputs = {
      method = "GET"
      uri    = "https://management.azure.com${azurerm_web_application_firewall_policy.main.id}?api-version=2023-09-01"
      authentication = {
        type     = "ManagedServiceIdentity"
        audience = "https://management.azure.com/"
      }
    }
    runAfter = {
      Filter_ip       = ["Succeeded"]
      Filter_incident = ["Succeeded"]
    }
  })
  depends_on = [azurerm_logic_app_action_custom.filter_ip, azurerm_logic_app_action_custom.filter_incident]
}

# 🆕 2-1. 사용자 지정 규칙 중 AutoBlockedIP / 나머지 규칙 분리
#        (속도 제한 규칙이 추가돼서 순서가 아니라 이름으로 찾음)
resource "azurerm_logic_app_action_custom" "filter_auto" {
  name         = "Filter_autoblock_rule"
  logic_app_id = azurerm_logic_app_workflow.autoblock.id
  body = jsonencode({
    type = "Query"
    inputs = {
      from  = "@body('Get_policy')?['properties']?['customRules']"
      where = "@equals(item()?['name'], 'AutoBlockedIP')"
    }
    runAfter = { Get_policy = ["Succeeded"] }
  })
  depends_on = [azurerm_logic_app_action_custom.get_policy]
}

resource "azurerm_logic_app_action_custom" "filter_others" {
  name         = "Filter_other_rules"
  logic_app_id = azurerm_logic_app_workflow.autoblock.id
  body = jsonencode({
    type = "Query"
    inputs = {
      from  = "@body('Get_policy')?['properties']?['customRules']"
      where = "@not(equals(item()?['name'], 'AutoBlockedIP'))"
    }
    runAfter = { Get_policy = ["Succeeded"] }
  })
  depends_on = [azurerm_logic_app_action_custom.get_policy]
}

# ✏️ 3. AutoBlockedIP에만 IP를 추가하고 다른 규칙(속도 제한 등)은 그대로 유지 (union으로 중복 제거)
resource "azurerm_logic_app_action_custom" "build_policy" {
  name         = "Build_policy"
  logic_app_id = azurerm_logic_app_workflow.autoblock.id
  body = jsonencode({
    type = "Compose"
    inputs = {
      location   = "@body('Get_policy')?['location']"
      properties = "@setProperty(body('Get_policy')?['properties'], 'customRules', union(body('Filter_other_rules'), createArray(setProperty(first(body('Filter_autoblock_rule')), 'matchConditions', createArray(setProperty(first(body('Filter_autoblock_rule'))?['matchConditions']?[0], 'matchValues', union(first(body('Filter_autoblock_rule'))?['matchConditions']?[0]?['matchValues'], createArray(first(body('Filter_ip'))?['value']))))))))"
    }
    runAfter = {
      Filter_autoblock_rule = ["Succeeded"]
      Filter_other_rules    = ["Succeeded"]
    }
  })
  depends_on = [azurerm_logic_app_action_custom.filter_auto, azurerm_logic_app_action_custom.filter_others]
}

# 4. WAF 정책 반영
resource "azurerm_logic_app_action_custom" "put_policy" {
  name         = "Put_policy"
  logic_app_id = azurerm_logic_app_workflow.autoblock.id
  body = jsonencode({
    type = "Http"
    inputs = {
      method = "PUT"
      uri    = "https://management.azure.com${azurerm_web_application_firewall_policy.main.id}?api-version=2023-09-01"
      body   = "@outputs('Build_policy')"
      authentication = {
        type     = "ManagedServiceIdentity"
        audience = "https://management.azure.com/"
      }
    }
    runAfter = { Build_policy = ["Succeeded"] }
  })
  depends_on = [azurerm_logic_app_action_custom.build_policy]
}

# 5. Sentinel 인시던트에 대응 기록 남기기
resource "azurerm_logic_app_action_custom" "add_comment" {
  name         = "Add_incident_comment"
  logic_app_id = azurerm_logic_app_workflow.autoblock.id
  body = jsonencode({
    type = "Http"
    inputs = {
      method = "PUT"
      uri    = "https://management.azure.com${azurerm_log_analytics_workspace.main.id}/providers/Microsoft.SecurityInsights/incidents/@{first(body('Filter_incident'))?['value']}/comments/@{guid()}?api-version=2023-02-01"
      body = {
        properties = {
          message = "[자동 대응] 공격 IP @{first(body('Filter_ip'))?['value']} 를 WAF 차단 목록(AutoBlockedIP)에 추가했습니다."
        }
      }
      authentication = {
        type     = "ManagedServiceIdentity"
        audience = "https://management.azure.com/"
      }
    }
    runAfter = { Put_policy = ["Succeeded"] }
  })
  depends_on = [azurerm_logic_app_action_custom.put_policy]
}

# 작업 그룹: 경보 → Logic App 호출
resource "azurerm_monitor_action_group" "autoblock" {
  name                = "${var.project_prefix}-autoblock"
  resource_group_name = azurerm_resource_group.security.name
  short_name          = "t4autoblk"

  logic_app_receiver {
    name                    = "waf-autoblock"
    resource_id             = azurerm_logic_app_workflow.autoblock.id
    callback_url            = azurerm_logic_app_trigger_http_request.alert.callback_url
    use_common_alert_schema = true
  }
}

# ✏️ 경보 규칙: 외부 공격 인시던트(웹 공격, CVE, 스캔, 과다 요청)의 IP 엔터티 추출
#    Bastion(정상 관리자일 수 있음)과 차단된 IP 재접근(이미 차단됨)은 제외
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "waf_autoblock" {
  name                 = "${var.project_prefix}-alert-waf-autoblock"
  resource_group_name  = azurerm_resource_group.security.name
  location             = azurerm_resource_group.security.location
  display_name         = "[team4] WAF 공격 IP 자동 차단"
  description          = "외부 공격 인시던트(웹 공격·CVE·스캔·과다 요청)의 IP 엔터티를 Logic App으로 넘겨 WAF 차단 목록에 추가"
  severity             = 2
  evaluation_frequency = "PT5M"
  window_duration      = "PT10M"
  scopes               = [azurerm_log_analytics_workspace.main.id]

  criteria {
    query = <<-KQL
      SecurityIncident
      | summarize arg_min(TimeGenerated, *) by IncidentNumber
      | where Title contains "반복 웹 공격" or Title contains "CVE" or Title contains "취약점 스캔" or Title contains "과다 요청" or Title contains "무차별 대입"      | mv-expand AlertId = AlertIds to typeof(string)
      | join kind=inner (SecurityAlert | summarize arg_max(TimeGenerated, *) by SystemAlertId) on $left.AlertId == $right.SystemAlertId
      | mv-expand E = parse_json(Entities)
      | where tostring(E.Type) =~ "ip"
      | extend ClientIp = tostring(E.Address)
      | where isnotempty(ClientIp) and ClientIp !in (dynamic(${jsonencode(var.waf_autoblock_exclude)}))
      | distinct ClientIp, IncidentName
    KQL

    time_aggregation_method = "Count"
    operator                = "GreaterThan"
    threshold               = 0

    dimension {
      name     = "ClientIp"
      operator = "Include"
      values   = ["*"]
    }
    dimension {
      name     = "IncidentName"
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
    action_groups = [azurerm_monitor_action_group.autoblock.id]
  }

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.main]
}