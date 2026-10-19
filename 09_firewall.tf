# Spoke의 외부 통신 경로가 될 Azure Firewall과 Firewall Policy를 생성하는 파일입니다.
resource "azurerm_firewall_policy" "main" {
  name                     = "firewall-policy"
  resource_group_name      = azurerm_resource_group.infra.name
  location                 = azurerm_resource_group.infra.location
  sku                      = "Standard"
  threat_intelligence_mode = "Deny"   # 알려진 악성 IP·도메인 자동 차단

  dns {proxy_enabled = true}
}

resource "azurerm_firewall" "main" {
  name                = "hub-firewall"
  resource_group_name = azurerm_resource_group.infra.name
  location            = azurerm_resource_group.infra.location
  sku_name            = "AZFW_VNet"
  sku_tier            = "Standard"
  firewall_policy_id  = azurerm_firewall_policy.main.id

  ip_configuration {
    name                 = "firewall-ipconf"
    subnet_id            = azurerm_subnet.firewall.id
    public_ip_address_id = azurerm_public_ip.firewall.id
  }
}
