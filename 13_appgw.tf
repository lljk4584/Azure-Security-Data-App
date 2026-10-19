resource "azurerm_web_application_firewall_policy" "main" {
  name                = "waf-policy"
  resource_group_name = azurerm_resource_group.infra.name
  location            = azurerm_resource_group.infra.location

  # 자동 차단 목록: Logic App이 공격 IP를 추가함
  # 빈 목록은 허용되지 않아서 문서용 예약 IP(192.0.2.1)를 기본값으로 둠
  custom_rules {
    name      = "AutoBlockedIP"
    priority  = 1
    rule_type = "MatchRule"
    action    = "Block"

    match_conditions {
      match_variables {
        variable_name = "RemoteAddr"
      }
      operator     = "IPMatch"
      match_values = ["192.0.2.1"]
    }
  }

  policy_settings {
    enabled = true
    mode    = "Prevention"
  }

  managed_rules {
    managed_rule_set {
      type    = "OWASP"
      version = "3.2"
    }
  }

    # IP당 요청 속도 제한: 1분에 300건을 넘으면 그 IP를 차단
  # (모든 IP에 적용하려고 "예약 IP가 아니면"이라는 부정 조건을 사용)
  custom_rules {
    name                 = "RateLimitPerIP"
    priority             = 2
    rule_type            = "RateLimitRule"
    action               = "Block"
    rate_limit_duration  = "OneMin"
    rate_limit_threshold = 300
    group_rate_limit_by  = "ClientAddr"

    match_conditions {
      match_variables {
        variable_name = "RemoteAddr"
      }
      operator           = "IPMatch"
      negation_condition = true
      match_values       = ["255.255.255.255/32"]
    }
  }

  # Logic App이 추가한 IP를 Terraform이 되돌리지 않도록
  lifecycle {
    ignore_changes = [custom_rules]
  }
}

resource "azurerm_application_gateway" "main" {
  name                = "app-gw"
  resource_group_name = azurerm_resource_group.infra.name
  location            = azurerm_resource_group.infra.location
  firewall_policy_id  = azurerm_web_application_firewall_policy.main.id

  sku {
    name = "WAF_v2"
    tier = "WAF_v2"
  }

  autoscale_configuration {
    min_capacity = 0
    max_capacity = 2
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.appgw.id]
  }

  gateway_ip_configuration {
    name      = "appgw-ipconf"
    subnet_id = azurerm_subnet.appgw.id
  }

  frontend_ip_configuration {
    name                 = "frontend-public"
    public_ip_address_id = azurerm_public_ip.appgw.id
  }

  frontend_port {
    name = "http-80"
    port = 80
  }

  frontend_port {
    name = "https-443"
    port = 443
  }

  ssl_certificate {
    name                = var.certificate_name
    key_vault_secret_id = azurerm_key_vault_certificate.appgw.versionless_secret_id
  }

  ssl_policy {
    policy_type = "Predefined"
    policy_name = "AppGwSslPolicy20220101S"
  }

  backend_address_pool {
    name = "web-backend-pool"
  }

   # 백엔드가 HTTPS(443). 프로브/백엔드 host 를 인증서 도메인과 동일하게 지정
  # (web nginx가 KV의 그 도메인 인증서를 그대로 서빙 → 공인 CA라 신뢰 루트 불필요)
  probe {
    name                = "web-health-probe"
    protocol            = "Https"
    host                = var.domain_name
    path                = "/health.html"
    interval            = 30
    timeout             = 30
    unhealthy_threshold = 3
  }

  backend_http_settings {
    name                  = "web-https-settings"
    cookie_based_affinity = "Disabled"
    port                  = 443
    protocol              = "Https"
    request_timeout       = 60
    probe_name            = "web-health-probe"
    host_name             = var.domain_name
  }

  http_listener {
    name                           = "https-listener"
    frontend_ip_configuration_name = "frontend-public"
    frontend_port_name             = "https-443"
    protocol                       = "Https"
    host_name                      = var.domain_name
    ssl_certificate_name           = var.certificate_name
  }

  http_listener {
    name                           = "http-listener"
    frontend_ip_configuration_name = "frontend-public"
    frontend_port_name             = "http-80"
    protocol                       = "Http"
    host_name                      = var.domain_name
  }

  redirect_configuration {
    name                 = "http-to-https"
    redirect_type        = "Permanent"
    target_listener_name = "https-listener"
    include_path         = true
    include_query_string = true
  }

  request_routing_rule {
    name                       = "https-rule"
    rule_type                  = "Basic"
    priority                   = 100
    http_listener_name         = "https-listener"
    backend_address_pool_name  = "web-backend-pool"
    backend_http_settings_name = "web-https-settings"
  }

  request_routing_rule {
    name                        = "http-redirect"
    rule_type                   = "Basic"
    priority                    = 200
    http_listener_name          = "http-listener"
    redirect_configuration_name = "http-to-https"
  }

  depends_on = [time_sleep.wait_appgw_kv_rbac]
}