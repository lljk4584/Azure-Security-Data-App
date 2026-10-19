# ─────────────────────────────────────────────────────────────
# Phase 2 SOAR: 내부 인시던트용 "수동 실행" 대응 Playbook (사람 판단 후 실행)
# 설계의도: RBAC 제약상 내부 탐지(①~⑦)는 자동차단하지 않고, 분석가가 인시던트를
#           확인한 뒤 아래 Playbook을 "수동 실행"해 대응한다. (HTTP 트리거)
#   1) VM 격리        : 대상 VM NSG에 deny-all(in/out, priority 100) 규칙 추가
#                       (기존 allow 중 100번 쓰던 규칙은 06_nsg.tf에서 105로 양보)
#   2) 격리 해제       : 위 규칙 제거
#   3) Storage 긴급봉쇄 : team4storage publicNetworkAccess=Disabled (반출 경로 즉시 차단)
#   4) 증거 보전 스냅샷 : 대상 VM OS 디스크 스냅샷 생성(포렌식)
# 대상 VM은 트리거 본문 {"target":"web"|"was"} 로 지정(미지정 시 web).
# data.azurerm_subscription.current 는 27_activity_diag.tf 에 정의됨.
# ─────────────────────────────────────────────────────────────

# ========== 1) VM 격리 Playbook ==========
resource "azurerm_logic_app_workflow" "isolate_vm" {
  name                = "${var.project_prefix}-pb-isolate-vm"
  resource_group_name = azurerm_resource_group.security.name
  location            = azurerm_resource_group.security.location
  identity { type = "SystemAssigned" }
}

resource "azurerm_role_assignment" "isolate_web_nsg" {
  scope                = azurerm_network_security_group.web.id
  role_definition_name = "Network Contributor"
  principal_id         = azurerm_logic_app_workflow.isolate_vm.identity[0].principal_id
}

resource "azurerm_role_assignment" "isolate_was_nsg" {
  scope                = azurerm_network_security_group.was.id
  role_definition_name = "Network Contributor"
  principal_id         = azurerm_logic_app_workflow.isolate_vm.identity[0].principal_id
}

resource "azurerm_logic_app_trigger_http_request" "isolate_trigger" {
  name         = "run-isolate"
  logic_app_id = azurerm_logic_app_workflow.isolate_vm.id
  schema       = jsonencode({ type = "object", properties = { target = { type = "string" } } })
}

# 대상 NSG 결정 (was면 nsg-was, 아니면 nsg-web)
resource "azurerm_logic_app_action_custom" "isolate_pick_nsg" {
  name         = "Pick_nsg"
  logic_app_id = azurerm_logic_app_workflow.isolate_vm.id
  body = jsonencode({
    type     = "Compose"
    inputs   = "@{if(equals(triggerBody()?['target'],'was'),'${azurerm_network_security_group.was.id}','${azurerm_network_security_group.web.id}')}"
    runAfter = {}
  })
}

# 인바운드 전체 차단 (priority 100 = 가장 높은 우선순위 → 모든 allow를 누름)
resource "azurerm_logic_app_action_custom" "isolate_deny_in" {
  name         = "Deny_inbound"
  logic_app_id = azurerm_logic_app_workflow.isolate_vm.id
  body = jsonencode({
    type = "Http"
    inputs = {
      method = "PUT"
      uri    = "https://management.azure.com@{outputs('Pick_nsg')}/securityRules/team4-ISOLATE-IN?api-version=2023-09-01"
      body = {
        properties = {
          priority                   = 100
          direction                  = "Inbound"
          access                     = "Deny"
          protocol                   = "*"
          sourceAddressPrefix        = "*"
          sourcePortRange            = "*"
          destinationAddressPrefix   = "*"
          destinationPortRange       = "*"
          description                = "team4 SOAR 수동 격리(인바운드 전체 차단)"
        }
      }
      authentication = { type = "ManagedServiceIdentity", audience = "https://management.azure.com/" }
    }
    runAfter = { Pick_nsg = ["Succeeded"] }
  })
  depends_on = [azurerm_logic_app_action_custom.isolate_pick_nsg]
}

# 아웃바운드 전체 차단 (반출 경로 포함 차단)
resource "azurerm_logic_app_action_custom" "isolate_deny_out" {
  name         = "Deny_outbound"
  logic_app_id = azurerm_logic_app_workflow.isolate_vm.id
  body = jsonencode({
    type = "Http"
    inputs = {
      method = "PUT"
      uri    = "https://management.azure.com@{outputs('Pick_nsg')}/securityRules/team4-ISOLATE-OUT?api-version=2023-09-01"
      body = {
        properties = {
          priority                   = 100
          direction                  = "Outbound"
          access                     = "Deny"
          protocol                   = "*"
          sourceAddressPrefix        = "*"
          sourcePortRange            = "*"
          destinationAddressPrefix   = "*"
          destinationPortRange       = "*"
          description                = "team4 SOAR 수동 격리(아웃바운드 전체 차단)"
        }
      }
      authentication = { type = "ManagedServiceIdentity", audience = "https://management.azure.com/" }
    }
    runAfter = { Deny_inbound = ["Succeeded"] }
  })
  depends_on = [azurerm_logic_app_action_custom.isolate_deny_in]
}

# ========== 2) 격리 해제 Playbook ==========
resource "azurerm_logic_app_workflow" "release_vm" {
  name                = "${var.project_prefix}-pb-release-vm"
  resource_group_name = azurerm_resource_group.security.name
  location            = azurerm_resource_group.security.location
  identity { type = "SystemAssigned" }
}

resource "azurerm_role_assignment" "release_web_nsg" {
  scope                = azurerm_network_security_group.web.id
  role_definition_name = "Network Contributor"
  principal_id         = azurerm_logic_app_workflow.release_vm.identity[0].principal_id
}

resource "azurerm_role_assignment" "release_was_nsg" {
  scope                = azurerm_network_security_group.was.id
  role_definition_name = "Network Contributor"
  principal_id         = azurerm_logic_app_workflow.release_vm.identity[0].principal_id
}

resource "azurerm_logic_app_trigger_http_request" "release_trigger" {
  name         = "run-release"
  logic_app_id = azurerm_logic_app_workflow.release_vm.id
  schema       = jsonencode({ type = "object", properties = { target = { type = "string" } } })
}

resource "azurerm_logic_app_action_custom" "release_pick_nsg" {
  name         = "Pick_nsg"
  logic_app_id = azurerm_logic_app_workflow.release_vm.id
  body = jsonencode({
    type     = "Compose"
    inputs   = "@{if(equals(triggerBody()?['target'],'was'),'${azurerm_network_security_group.was.id}','${azurerm_network_security_group.web.id}')}"
    runAfter = {}
  })
}

resource "azurerm_logic_app_action_custom" "release_del_in" {
  name         = "Delete_inbound"
  logic_app_id = azurerm_logic_app_workflow.release_vm.id
  body = jsonencode({
    type = "Http"
    inputs = {
      method         = "DELETE"
      uri            = "https://management.azure.com@{outputs('Pick_nsg')}/securityRules/team4-ISOLATE-IN?api-version=2023-09-01"
      authentication = { type = "ManagedServiceIdentity", audience = "https://management.azure.com/" }
    }
    runAfter = { Pick_nsg = ["Succeeded"] }
  })
  depends_on = [azurerm_logic_app_action_custom.release_pick_nsg]
}

resource "azurerm_logic_app_action_custom" "release_del_out" {
  name         = "Delete_outbound"
  logic_app_id = azurerm_logic_app_workflow.release_vm.id
  body = jsonencode({
    type = "Http"
    inputs = {
      method         = "DELETE"
      uri            = "https://management.azure.com@{outputs('Pick_nsg')}/securityRules/team4-ISOLATE-OUT?api-version=2023-09-01"
      authentication = { type = "ManagedServiceIdentity", audience = "https://management.azure.com/" }
    }
    runAfter = { Delete_inbound = ["Succeeded", "Failed"] }
  })
  depends_on = [azurerm_logic_app_action_custom.release_del_in]
}

# ========== 3) Storage 긴급 봉쇄 Playbook ==========
resource "azurerm_logic_app_workflow" "lockdown_storage" {
  name                = "${var.project_prefix}-pb-lockdown-storage"
  resource_group_name = azurerm_resource_group.security.name
  location            = azurerm_resource_group.security.location
  identity { type = "SystemAssigned" }
}

resource "azurerm_role_assignment" "lockdown_storage_role" {
  scope                = azurerm_storage_account.security.id
  role_definition_name = "Storage Account Contributor"
  principal_id         = azurerm_logic_app_workflow.lockdown_storage.identity[0].principal_id
}

resource "azurerm_logic_app_trigger_http_request" "lockdown_trigger" {
  name         = "run-lockdown"
  logic_app_id = azurerm_logic_app_workflow.lockdown_storage.id
  schema       = "{}"
}

# publicNetworkAccess=Disabled 로 PATCH → 공용/서비스엔드포인트 접근 전면 차단
resource "azurerm_logic_app_action_custom" "lockdown_patch" {
  name         = "Disable_public_access"
  logic_app_id = azurerm_logic_app_workflow.lockdown_storage.id
  body = jsonencode({
    type = "Http"
    inputs = {
      method = "PATCH"
      uri    = "https://management.azure.com${azurerm_storage_account.security.id}?api-version=2023-01-01"
      body = {
        properties = {
          publicNetworkAccess = "Disabled"
        }
      }
      authentication = { type = "ManagedServiceIdentity", audience = "https://management.azure.com/" }
    }
    runAfter = {}
  })
}

# ========== 4) 증거 보전 스냅샷 Playbook ==========
resource "azurerm_logic_app_workflow" "snapshot_vm" {
  name                = "${var.project_prefix}-pb-snapshot-vm"
  resource_group_name = azurerm_resource_group.security.name
  location            = azurerm_resource_group.security.location
  identity { type = "SystemAssigned" }
}

# VM 조회 + 디스크 읽기 + 스냅샷 생성 → infra RG 범위 Contributor
resource "azurerm_role_assignment" "snapshot_infra" {
  scope                = azurerm_resource_group.infra.id
  role_definition_name = "Contributor"
  principal_id         = azurerm_logic_app_workflow.snapshot_vm.identity[0].principal_id
}

resource "azurerm_logic_app_trigger_http_request" "snapshot_trigger" {
  name         = "run-snapshot"
  logic_app_id = azurerm_logic_app_workflow.snapshot_vm.id
  schema       = jsonencode({ type = "object", properties = { target = { type = "string" } } })
}

# 대상 VM 결정
resource "azurerm_logic_app_action_custom" "snapshot_pick_vm" {
  name         = "Pick_vm"
  logic_app_id = azurerm_logic_app_workflow.snapshot_vm.id
  body = jsonencode({
    type     = "Compose"
    inputs   = "@{if(equals(triggerBody()?['target'],'was'),'${azurerm_linux_virtual_machine.was.id}','${azurerm_linux_virtual_machine.web.id}')}"
    runAfter = {}
  })
}

# VM 정보 GET → OS 디스크 managed disk id 추출
resource "azurerm_logic_app_action_custom" "snapshot_get_vm" {
  name         = "Get_vm"
  logic_app_id = azurerm_logic_app_workflow.snapshot_vm.id
  body = jsonencode({
    type = "Http"
    inputs = {
      method         = "GET"
      uri            = "https://management.azure.com@{outputs('Pick_vm')}?api-version=2023-09-01"
      authentication = { type = "ManagedServiceIdentity", audience = "https://management.azure.com/" }
    }
    runAfter = { Pick_vm = ["Succeeded"] }
  })
  depends_on = [azurerm_logic_app_action_custom.snapshot_pick_vm]
}

# OS 디스크 스냅샷 생성 (Copy) — infra RG 에 team4-ev-<target>-<timestamp>
resource "azurerm_logic_app_action_custom" "snapshot_create" {
  name         = "Create_snapshot"
  logic_app_id = azurerm_logic_app_workflow.snapshot_vm.id
  body = jsonencode({
    type = "Http"
    inputs = {
      method = "PUT"
      uri    = "https://management.azure.com/subscriptions/${data.azurerm_subscription.current.subscription_id}/resourceGroups/${azurerm_resource_group.infra.name}/providers/Microsoft.Compute/snapshots/team4-ev-@{coalesce(triggerBody()?['target'],'web')}-@{formatDateTime(utcNow(),'yyyyMMddHHmmss')}?api-version=2023-04-02"
      body = {
        location = azurerm_resource_group.infra.location
        properties = {
          creationData = {
            createOption     = "Copy"
            sourceResourceId = "@{body('Get_vm')?['properties']?['storageProfile']?['osDisk']?['managedDisk']?['id']}"
          }
        }
      }
      authentication = { type = "ManagedServiceIdentity", audience = "https://management.azure.com/" }
    }
    runAfter = { Get_vm = ["Succeeded"] }
  })
  depends_on = [azurerm_logic_app_action_custom.snapshot_get_vm]
}
