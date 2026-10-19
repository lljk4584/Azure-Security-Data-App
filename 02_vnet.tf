# Hub VNet과 Web/DB가 들어갈 Spoke VNet을 생성하는 파일입니다.
resource "azurerm_virtual_network" "hub" {
  name                = "hub-vnet"
  resource_group_name = azurerm_resource_group.infra.name
  location            = azurerm_resource_group.infra.location
  address_space       = [var.hubcidr]
}

resource "azurerm_virtual_network" "spoke" {
  name                = "spoke-vnet"
  resource_group_name = azurerm_resource_group.infra.name
  location            = azurerm_resource_group.infra.location
  address_space       = [var.spokecidr]
  dns_servers = [azurerm_firewall.main.ip_configuration[0].private_ip_address]
}
