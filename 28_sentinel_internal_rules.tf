# ── Phase 1: 내부 행위 기반 탐지 룰 (기존 23_sentinel_rules.tf 의 7개 위에 추가) ──
# local.sentinel_ws_id, time_sleep.wait_sentinel_ready 는 23_sentinel_rules.tf 에 정의됨.
# KQL 컬럼은 영문만. 테이블명은 team4-law2 에서 실측 확인함.

# ① 권한·역할 변경/상승 (관리평면) — 차단 않고 탐지로 대응(설계)
resource "azurerm_sentinel_alert_rule_scheduled" "priv_role_change" {
  name                       = "team4-priv-role-change"
  log_analytics_workspace_id = local.sentinel_ws_id
  display_name               = "[team4] 권한·역할 변경/상승 (관리평면)"
  description                = "구독/리소스에 역할 할당·삭제 발생 — 공용구독 특성상 차단이 아닌 탐지로 대응"
  severity                   = "High"
  query_frequency            = "PT15M"
  query_period               = "PT15M"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["PrivilegeEscalation", "Persistence"]
  techniques                 = ["T1098"]

  query = <<-KQL
    AzureActivity
    | where OperationNameValue has "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/"
    | where ActivityStatusValue in ("Success", "Succeeded")
    | project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, _ResourceId
  KQL

  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "Caller"
    }
  }
  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "CallerIpAddress"
    }
  }
  depends_on = [time_sleep.wait_sentinel_ready]
}

# ② NSG·방화벽 보안정책 변경 (WAF 정책은 자동차단 Logic App이 수정하므로 제외)
resource "azurerm_sentinel_alert_rule_scheduled" "net_policy_change" {
  name                       = "team4-net-policy-change"
  log_analytics_workspace_id = local.sentinel_ws_id
  display_name               = "[team4] NSG·방화벽 보안정책 변경"
  description                = "NSG 규칙 또는 Azure Firewall 정책이 변경됨 — 네트워크 통제 무력화 시도"
  severity                   = "Medium"
  query_frequency            = "PT15M"
  query_period               = "PT15M"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562"]

  query = <<-KQL
    AzureActivity
    | where OperationNameValue has_any (
        "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/WRITE",
        "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/DELETE",
        "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE",
        "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/DELETE",
        "MICROSOFT.NETWORK/AZUREFIREWALLS/WRITE",
        "MICROSOFT.NETWORK/FIREWALLPOLICIES/WRITE",
        "MICROSOFT.NETWORK/FIREWALLPOLICIES/RULECOLLECTIONGROUPS/WRITE")
    | where ActivityStatusValue in ("Success", "Succeeded")
    | project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, _ResourceId
  KQL

  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "Caller"
    }
  }
  depends_on = [time_sleep.wait_sentinel_ready]
}

# ③ Key Vault 비인가/거부 접근 (4xx) — 데이터평면 거부 탐지
resource "azurerm_sentinel_alert_rule_scheduled" "kv_forbidden" {
  name                       = "team4-kv-forbidden"
  log_analytics_workspace_id = local.sentinel_ws_id
  display_name               = "[team4] Key Vault 비인가/거부 접근 (4xx)"
  description                = "KV 데이터평면 접근이 4xx(403 Forbidden/401 등)로 거부됨 — 권한 없는 계정의 비밀 열람 시도"
  severity                   = "High"
  query_frequency            = "PT15M"
  query_period               = "PT15M"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1552"]

  query = <<-KQL
    AZKVAuditLogs
    | where toint(Properties.httpStatusCode) >= 400
    | summarize Denied = count(), Ops = make_set(OperationName, 10), Uris = make_set(tostring(Properties.requestUri), 10) by CallerIpAddress
    | where Denied >= 1
  KQL

  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "CallerIpAddress"
    }
  }
  depends_on = [time_sleep.wait_sentinel_ready]
}

# ④ DB 사용자 생성·권한 변경 (DDL/DCL) — DB 계정 권한상승 탐지
resource "azurerm_sentinel_alert_rule_scheduled" "db_user_change" {
  name                       = "team4-db-user-grant"
  log_analytics_workspace_id = local.sentinel_ws_id
  display_name               = "[team4] DB 사용자 생성·권한 변경 (DDL/DCL)"
  description                = "MySQL에서 사용자 생성/삭제 또는 GRANT/REVOKE 발생 — DB 계정 권한상승·백도어 계정 탐지"
  severity                   = "Medium"
  query_frequency            = "PT15M"
  query_period               = "PT15M"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["Persistence", "PrivilegeEscalation"]
  techniques                 = ["T1136", "T1098"]

  query = <<-KQL
    MySqlAuditLogs
    | where SqlText has_any ("CREATE USER", "CREATE AADUSER", "DROP USER", "ALTER USER", "GRANT ", "REVOKE")
    | project TimeGenerated, User, Ip, Db, SqlText
  KQL

  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "User"
    }
  }
  depends_on = [time_sleep.wait_sentinel_ready]
}

# ⑤ Storage 대량 다운로드/삭제 — 로그·데이터 반출/변조 탐지
resource "azurerm_sentinel_alert_rule_scheduled" "storage_mass" {
  name                       = "team4-storage-mass-access"
  log_analytics_workspace_id = local.sentinel_ws_id
  display_name               = "[team4] Storage 대량 다운로드/삭제 시도"
  description                = "같은 출발지에서 Blob을 대량 읽기 또는 삭제 시도 — 데이터 반출 또는 로그 변조 의심"
  severity                   = "High"
  query_frequency            = "PT15M"
  query_period               = "PT15M"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["Exfiltration", "Collection"]
  techniques                 = ["T1530"]

  query = <<-KQL
    StorageBlobLogs
    | where OperationName in ("GetBlob", "DeleteBlob")
    | summarize Ops = count(), Deletes = countif(OperationName == "DeleteBlob"), Objects = dcount(Uri) by CallerIpAddress, AuthenticationType
    | where Ops >= 50 or Deletes >= 1
  KQL

  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "CallerIpAddress"
    }
  }
  depends_on = [time_sleep.wait_sentinel_ready]
}

# ⑥ 미허용 아웃바운드(Egress) 차단 탐지 — 내부 VM이 허용목록 밖으로 나가려다 Firewall Deny
#   SignInLogs(비활성 계정 로그인, 원설계 ⑥)는 테넌트 Entra 진단권한 제약으로 대체.
#   베이스라인(OS·에이전트·패키지 텔레메트리)은 noise 목록으로 제외 → 반출 시도만 탐지.
resource "azurerm_sentinel_alert_rule_scheduled" "egress_deny" {
  name                       = "team4-egress-deny"
  log_analytics_workspace_id = local.sentinel_ws_id
  display_name               = "[team4] 미허용 아웃바운드 차단 (Egress Deny)"
  description                = "내부 VM(web/was)이 허용목록 밖 목적지로 나가려다 Azure Firewall이 차단 — 데이터 반출(Exfiltration) 시도. OS·에이전트·패키지 텔레메트리는 제외."
  severity                   = "High"
  query_frequency            = "PT15M"
  query_period               = "PT15M"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["Exfiltration"]
  techniques                 = ["T1048"]

  query = <<-KQL
    let noise = dynamic(["ubuntu.com","snapcraft.io","canonical.com","githubusercontent.com","microsoft.com","microsoft.us","office.com","skype.com","google.com"]);
    let vms = dynamic(["10.20.1.4","10.20.3.10"]);
    AZFWApplicationRule
    | where Action == "Deny"
    | where SourceIp in (vms)
    | where isnotempty(Fqdn) and not(Fqdn has_any (noise))
    | summarize Attempts=count(), Targets=make_set(Fqdn, 15), FirstSeen=min(TimeGenerated) by SourceIp
    | where Attempts >= 1
  KQL

  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "SourceIp"
    }
  }
  depends_on = [time_sleep.wait_sentinel_ready]
}

# ⑦ VM 파일 변조·권한상승 (auditd FIM, Syslog local6)
resource "azurerm_sentinel_alert_rule_scheduled" "vm_fim" {
  name                       = "team4-vm-fim-privesc"
  log_analytics_workspace_id = local.sentinel_ws_id
  display_name               = "[team4] VM 파일 변조·권한상승 (auditd FIM)"
  description                = "web/was VM에서 계정·sudoers·SSH키 변조 또는 권한상승 명령 실행이 auditd에 탐지됨"
  severity                   = "High"
  query_frequency            = "PT15M"
  query_period               = "PT15M"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["PrivilegeEscalation", "DefenseEvasion"]
  techniques                 = ["T1548", "T1098"]

  query = <<-KQL
    Syslog
    | where Facility == "local6"
    | where SyslogMessage has_any ('key="identity"', 'key="priv_esc"', 'key="priv_esc_exec"', 'key="user_mgmt"', 'key="ssh_keys"', 'key="ssh_config"')
    | project TimeGenerated, Computer, SyslogMessage
  KQL

  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "Computer"
    }
  }
  depends_on = [time_sleep.wait_sentinel_ready]
}