resource "time_sleep" "wait_sentinel_ready" {
  depends_on      = [azurerm_sentinel_log_analytics_workspace_onboarding.main]
  create_duration = "180s"
}

locals {
  sentinel_ws_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
}

# ① 같은 IP에서 WAF 공격 탐지 반복
resource "azurerm_sentinel_alert_rule_scheduled" "waf_attack" {
  name                       = "team4-waf-attack"
  log_analytics_workspace_id = local.sentinel_ws_id
  display_name               = "[team4] 동일 IP의 반복 웹 공격 (WAF)"
  description                = "10분 동안 같은 IP에서 WAF 규칙이 5회 이상 탐지됨 (SQLi 942xxx, XSS 941xxx 등)"
  severity                   = "High"
  query_frequency            = "PT10M"
  query_period               = "PT10M"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["InitialAccess"]
  techniques                 = ["T1190"]

  query = <<-KQL
    AGWFirewallLogs
    | summarize Hits = count(), Rules = make_set(RuleId, 20), Uris = make_set(RequestUri, 10) by ClientIp
    | where Hits >= 5
  KQL

  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "ClientIp"
    }
  }
  depends_on = [time_sleep.wait_sentinel_ready]
}

# ② 알려진 CVE·원격 명령 실행 공격 (1번만 와도 High)
#    932xxx 원격 명령 실행, 933xxx PHP 인젝션, 944xxx Java 공격, 800xxx Microsoft 위협 인텔 CVE 규칙
resource "azurerm_sentinel_alert_rule_scheduled" "cve_attack" {
  name                       = "team4-ext-cve-attack"
  log_analytics_workspace_id = local.sentinel_ws_id
  display_name               = "[team4] CVE·원격 명령 실행 공격 시도 (WAF)"
  description                = "알려진 취약점(CVE) 또는 원격 명령 실행 패턴이 WAF에 탐지됨"
  severity                   = "High"
  query_frequency            = "PT10M"
  query_period               = "PT10M"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["InitialAccess", "Execution"]
  techniques                 = ["T1190", "T1059"]

  query = <<-KQL
    AGWFirewallLogs
    | where RuleId matches regex @"^(932|933|944|800)\d+"
    | summarize Hits = count(), Rules = make_set(RuleId, 20), Messages = make_set(Message, 5) by ClientIp
  KQL

  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "ClientIp"
    }
  }
  depends_on = [time_sleep.wait_sentinel_ready]
}

# ③ 외부 취약점 스캔: 존재하지 않는 경로를 대량으로 찾음
resource "azurerm_sentinel_alert_rule_scheduled" "scan" {
  name                       = "team4-ext-scan"
  log_analytics_workspace_id = local.sentinel_ws_id
  display_name               = "[team4] 외부 취약점 스캔 (404 다수)"
  description                = "10분 동안 같은 IP가 서로 다른 경로 20곳 이상에서 404를 30회 이상 받음"
  severity                   = "Medium"
  query_frequency            = "PT10M"
  query_period               = "PT10M"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["Reconnaissance"]
  techniques                 = ["T1595"]

  query = <<-KQL
    AGWAccessLogs
    | where HttpStatus == 404
    | summarize NotFound = count(), Paths = dcount(RequestUri), Sample = make_set(RequestUri, 10) by ClientIp
    | where NotFound >= 30 and Paths >= 20
  KQL

  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "ClientIp"
    }
  }
  depends_on = [time_sleep.wait_sentinel_ready]
}

# ④ 외부 과다 요청: 한 IP가 1분에 300건 이상
resource "azurerm_sentinel_alert_rule_scheduled" "flood" {
  name                       = "team4-ext-flood"
  log_analytics_workspace_id = local.sentinel_ws_id
  display_name               = "[team4] 외부 과다 요청 (요청 폭주)"
  description                = "같은 IP가 1분에 300건 이상 요청 (서비스 거부 또는 자동화 도구 의심)"
  severity                   = "Medium"
  query_frequency            = "PT10M"
  query_period               = "PT10M"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["Impact"]
  techniques                 = ["T1499"]

  query = <<-KQL
    AGWAccessLogs
    | summarize Requests = count() by ClientIp, bin(TimeGenerated, 1m)
    | where Requests >= 300
    | summarize PeakPerMin = max(Requests), Minutes = count() by ClientIp
  KQL

  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "ClientIp"
    }
  }
  depends_on = [time_sleep.wait_sentinel_ready]
}

# ⑤ 차단된 IP의 재접근 시도 (자동 차단이 동작 중이라는 확인용)
resource "azurerm_sentinel_alert_rule_scheduled" "blocked_retry" {
  name                       = "team4-ext-blocked-retry"
  log_analytics_workspace_id = local.sentinel_ws_id
  display_name               = "[team4] 차단된 IP의 재접근 시도"
  description                = "AutoBlockedIP 명단에 있는 IP가 10분 동안 10회 이상 다시 접근"
  severity                   = "Low"
  query_frequency            = "PT10M"
  query_period               = "PT10M"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["InitialAccess"]
  techniques                 = ["T1190"]

  query = <<-KQL
    AGWFirewallLogs
    | where RuleId == "AutoBlockedIP"
    | summarize Attempts = count(), Uris = make_set(RequestUri, 10) by ClientIp
    | where Attempts >= 10
  KQL

  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "ClientIp"
    }
  }
  depends_on = [time_sleep.wait_sentinel_ready]
}

# ⑥ Bastion: 최근 7일 동안 없던 사용자·IP 조합으로 접속 (외부에서 들어오는 관리자 접속)
resource "azurerm_sentinel_alert_rule_scheduled" "bastion_new_source" {
  name                       = "team4-bastion-new"
  log_analytics_workspace_id = local.sentinel_ws_id
  display_name               = "[team4] Bastion 새로운 출발지 접속"
  description                = "최근 7일 동안 보지 못한 사용자·IP 조합으로 VM 접속"
  severity                   = "Low"
  query_frequency            = "PT1H"
  query_period               = "P7D"

  query = <<-KQL
    let known = MicrosoftAzureBastionAuditLogs
      | where TimeGenerated between (ago(7d) .. ago(1h))
      | distinct UserName, ClientIpAddress;
    MicrosoftAzureBastionAuditLogs
    | where TimeGenerated > ago(1h)
    | summarize FirstSeen = min(TimeGenerated), Targets = make_set(TargetVMIPAddress, 10) by UserName, ClientIpAddress
    | join kind=leftanti known on UserName, ClientIpAddress
  KQL

  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "UserName"
    }
  }
  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "ClientIpAddress"
    }
  }
  depends_on = [time_sleep.wait_sentinel_ready]
}

# ⑦ 웹 로그인 무차별 대입 (Flask 로그인 실패 반복)
resource "azurerm_sentinel_alert_rule_scheduled" "web_login_bruteforce" {
  name                       = "team4-web-login-bruteforce"
  log_analytics_workspace_id = local.sentinel_ws_id
  display_name               = "[team4] 웹 로그인 무차별 대입 시도"
  description                = "5분 동안 같은 IP에서 웹 로그인 실패가 10회 이상 (크리덴셜 스터핑/브루트포스 의심)"
  severity                   = "High"
  query_frequency            = "PT5M"
  query_period               = "PT15M"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1110"]

  query = <<-KQL
    Syslog
    | where SyslogMessage has "TEAM4_LOGIN" and SyslogMessage has "result=FAIL"
    | extend SrcIp = extract(@"src=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", 1, SyslogMessage),
             TargetUser = extract(@"user=""([^""]*)""", 1, SyslogMessage)
    | summarize Fails = count(), Users = make_set(TargetUser, 20), FirstSeen = min(TimeGenerated) by SrcIp
    | where Fails >= 10
  KQL

  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "SrcIp"
    }
  }
  depends_on = [time_sleep.wait_sentinel_ready]
}
