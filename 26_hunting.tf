# Sentinel 헌팅 쿼리 = category "Hunting Queries" 저장 검색

# ① 상위 공격 IP (최근 7일)
resource "azurerm_log_analytics_saved_search" "hunt_top_attackers" {
  name                       = "team4-hunt-top-attackers"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  category                   = "Hunting Queries"
  display_name               = "[team4-hunt] 상위 공격 IP (7일)"
  query                      = <<-KQL
    AGWFirewallLogs
    | where TimeGenerated > ago(7d)
    | where Action in ("Blocked", "Matched")
    | summarize Hits = count(), Rules = make_set(RuleId, 20) by ClientIp
    | top 20 by Hits desc
  KQL
}

# ② 희귀 접근 경로 (평소 거의 없던 URI)
resource "azurerm_log_analytics_saved_search" "hunt_rare_uri" {
  name                       = "team4-hunt-rare-uri"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  category                   = "Hunting Queries"
  display_name               = "[team4-hunt] 희귀 요청 경로"
  query                      = <<-KQL
    AGWAccessLogs
    | where TimeGenerated > ago(7d)
    | summarize Reqs = count() by RequestUri
    | where Reqs <= 3
    | order by Reqs asc
  KQL
}

# ③ 로그인 실패 다수 후 성공 (계정 탈취 의심)
resource "azurerm_log_analytics_saved_search" "hunt_fail_then_success" {
  name                       = "team4-hunt-fail-then-success"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  category                   = "Hunting Queries"
  display_name               = "[team4-hunt] 로그인 실패 다수 후 성공"
  query                      = <<-KQL
    Syslog
    | where TimeGenerated > ago(1d)
    | where SyslogMessage has "TEAM4_LOGIN"
    | extend SrcIp = extract(@"src=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", 1, SyslogMessage),
             Result = extract(@"result=(\w+)", 1, SyslogMessage)
    | summarize Fails = countif(Result == "FAIL"), OKs = countif(Result == "OK") by SrcIp
    | where Fails >= 5 and OKs >= 1
  KQL
}

# ④ 차단된 IP가 계속 접근
resource "azurerm_log_analytics_saved_search" "hunt_blocked_persist" {
  name                       = "team4-hunt-blocked-persist"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  category                   = "Hunting Queries"
  display_name               = "[team4-hunt] 차단 IP의 지속 접근"
  query                      = <<-KQL
    AGWFirewallLogs
    | where TimeGenerated > ago(1d)
    | where RuleId == "AutoBlockedIP"
    | summarize Attempts = count(), Paths = dcount(RequestUri) by ClientIp
    | where Attempts >= 5
  KQL
}

# ─── 내부 행위 헌팅 쿼리 (분석규칙 7종의 공백: 상관분석·저신뢰도·이상탐지) ───

# ⑤ 권한 변경 직후 KV 접근 (같은 출발 IP 상관) — 권한 탈취→비밀 열람 체인
resource "azurerm_log_analytics_saved_search" "hunt_rolechange_then_kv" {
  name                       = "team4-hunt-rolechange-then-kv"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  category                   = "Hunting Queries"
  display_name               = "[team4-hunt] 권한변경 직후 KV 접근 (상관)"
  query                      = <<-KQL
    let roleChanges = AzureActivity
      | where TimeGenerated > ago(7d)
      | where OperationNameValue has "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/"
      | where ActivityStatusValue in ("Success", "Succeeded")
      | project ChangeTime = TimeGenerated, Caller, IP = CallerIpAddress;
    roleChanges
    | join kind=inner (
        AZKVAuditLogs
        | where TimeGenerated > ago(7d)
        | project KvTime = TimeGenerated, IP = CallerIpAddress, OperationName, Uri = tostring(Properties.requestUri)
      ) on IP
    | where KvTime between (ChangeTime .. (ChangeTime + 1h))
    | project ChangeTime, Caller, IP, KvTime, OperationName, Uri
    | order by ChangeTime desc
  KQL
}

# ⑥ 첫 등장 아웃바운드 FQDN (과거 14~1일 미등장 → 최근 1일 신규) — egress 이상탐지(성공 포함)
resource "azurerm_log_analytics_saved_search" "hunt_new_egress_fqdn" {
  name                       = "team4-hunt-new-egress-fqdn"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  category                   = "Hunting Queries"
  display_name               = "[team4-hunt] 신규 아웃바운드 FQDN (VM)"
  query                      = <<-KQL
    let seen = AZFWApplicationRule
      | where TimeGenerated between (ago(14d) .. ago(1d))
      | where SourceIp in ("10.20.1.4", "10.20.3.10")
      | distinct Fqdn;
    AZFWApplicationRule
    | where TimeGenerated > ago(1d)
    | where SourceIp in ("10.20.1.4", "10.20.3.10")
    | where isnotempty(Fqdn) and Fqdn !in (seen)
    | summarize Hits = count(), FirstSeen = min(TimeGenerated), Actions = make_set(Action, 5) by SourceIp, Fqdn
    | order by FirstSeen desc
  KQL
}

# ⑦ KV 시크릿 "성공" 대량 열람 — 자격증명 반출 (③은 거부만 봄, 이건 성공 대량)
resource "azurerm_log_analytics_saved_search" "hunt_kv_mass_read" {
  name                       = "team4-hunt-kv-mass-read"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  category                   = "Hunting Queries"
  display_name               = "[team4-hunt] KV 시크릿 대량 열람(성공)"
  query                      = <<-KQL
    AZKVAuditLogs
    | where TimeGenerated > ago(1d)
    | where OperationName == "SecretGet"
    | where toint(Properties.httpStatusCode) < 300
    | summarize Reads = count(), Secrets = dcount(tostring(Properties.requestUri)), Sample = make_set(tostring(Properties.requestUri), 10) by CallerIpAddress
    | where Reads >= 10
    | order by Reads desc
  KQL
}

# ⑧ DB 대량 SELECT / 비정상 시간대 조회 — 데이터 반출 의심 (DML_SELECT 감사 ON 후)
resource "azurerm_log_analytics_saved_search" "hunt_db_mass_select" {
  name                       = "team4-hunt-db-mass-select"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  category                   = "Hunting Queries"
  display_name               = "[team4-hunt] DB 대량 SELECT/비정상 조회"
  query                      = <<-KQL
    MySqlAuditLogs
    | where TimeGenerated > ago(1d)
    | where SqlText startswith "SELECT"
    | extend Hour = datetime_part("Hour", TimeGenerated)
    | summarize Selects = count(), Tables = dcount(Table), OffHours = countif(Hour < 7 or Hour >= 22), Sample = make_set(SqlText, 3) by User, Ip
    | where Selects >= 50 or OffHours > 0
    | order by Selects desc
  KQL
}

# ⑨ 희귀 관리평면 작업 (7일간 3회 이하) — 평소 안 하던 ARM 작업
resource "azurerm_log_analytics_saved_search" "hunt_rare_arm_ops" {
  name                       = "team4-hunt-rare-arm-ops"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  category                   = "Hunting Queries"
  display_name               = "[team4-hunt] 희귀 관리평면 작업"
  query                      = <<-KQL
    AzureActivity
    | where TimeGenerated > ago(7d)
    | where ActivityStatusValue in ("Success", "Succeeded")
    | summarize Count = count(), Callers = make_set(Caller, 5), Last = max(TimeGenerated) by OperationNameValue
    | where Count <= 3
    | order by Last desc
  KQL
}