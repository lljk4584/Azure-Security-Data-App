# ── 구독 활동 로그(AzureActivity) → LAW (+ Storage 장기보관) ──
# 관리평면 권한변경/상승·NSG·WAF·정책 변경 탐지의 "전제". 이게 있어야 AzureActivity 테이블이 채워지고
# Phase 1 규칙 1·2가 동작한다. 보안 로그라 LAW(분석) + 보안 Storage(WORM 보관) 양쪽에 남긴다.
data "azurerm_subscription" "current" {}

resource "azurerm_monitor_diagnostic_setting" "activity_to_law" {
  name               = "activity-law"
  target_resource_id = data.azurerm_subscription.current.id

  # ⚠️ 공유키 비활성 스토리지로는 구독 Activity 전송이 실패해 설정 전체가 막힐 수 있어 LAW 전용으로 둔다.
  #    (Activity의 WORM 스토리지 보관은 공유키 off 제약 → 운영 전환 과제)
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log { category = "Administrative" }
  enabled_log { category = "Security" }
  enabled_log { category = "Policy" }
  enabled_log { category = "Alert" }
  enabled_log { category = "ServiceHealth" }
  enabled_log { category = "ResourceHealth" }
  enabled_log { category = "Autoscale" }
  enabled_log { category = "Recommendation" }
}
