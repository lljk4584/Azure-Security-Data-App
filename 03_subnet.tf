# Firewall, App Gateway, Bastion, Web, WAS, DB용 Subnet을 생성하는 파일입니다.
resource "azurerm_subnet" "firewall" {
  name                 = "AzureFirewallSubnet"
  resource_group_name  = azurerm_resource_group.infra.name
  virtual_network_name = azurerm_virtual_network.hub.name
  address_prefixes     = [var.fwsub]
}

resource "azurerm_subnet" "appgw" {
  name                 = "appgw-sub"
  resource_group_name  = azurerm_resource_group.infra.name
  virtual_network_name = azurerm_virtual_network.hub.name
  address_prefixes     = [var.appgwsub]
  depends_on = [azurerm_subnet.firewall]
}

resource "azurerm_subnet" "bastion" {
  name                 = "AzureBastionSubnet"
  resource_group_name  = azurerm_resource_group.infra.name
  virtual_network_name = azurerm_virtual_network.hub.name
  address_prefixes     = [var.batsub]
  depends_on = [azurerm_subnet.appgw]

}

resource "azurerm_subnet" "web" {
  name                            = "web-sub"
  resource_group_name             = azurerm_resource_group.infra.name
  virtual_network_name            = azurerm_virtual_network.spoke.name
  address_prefixes                = [var.websub]
  default_outbound_access_enabled = false
  service_endpoints = ["Microsoft.Storage", "Microsoft.KeyVault"]

}

resource "azurerm_subnet" "was" {
  name                            = "was-sub"
  resource_group_name             = azurerm_resource_group.infra.name
  virtual_network_name            = azurerm_virtual_network.spoke.name
  address_prefixes                = [var.wassub]
  default_outbound_access_enabled = false
  depends_on                      = [azurerm_subnet.web]
  service_endpoints = ["Microsoft.Storage", "Microsoft.KeyVault"]

}

resource "azurerm_subnet" "db" {
  name                            = "db-sub"
  resource_group_name             = azurerm_resource_group.infra.name
  virtual_network_name            = azurerm_virtual_network.spoke.name
  address_prefixes                = [var.dbsub]
  default_outbound_access_enabled = false

  delegation {
    name = "mysql-flexible"
    service_delegation {
      name    = "Microsoft.DBforMySQL/flexibleServers"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
  depends_on = [azurerm_subnet.was]
}