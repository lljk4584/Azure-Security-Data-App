resource "azurerm_private_dns_zone" "mysql" {
  name                = "${var.mysql_server_name}.private.mysql.database.azure.com"
  resource_group_name = azurerm_resource_group.infra.name
}


resource "azurerm_private_dns_zone_virtual_network_link" "mysql_spoke" {
  name                  = "mysql-dns-spoke-link"
  resource_group_name   = azurerm_resource_group.infra.name
  private_dns_zone_name = azurerm_private_dns_zone.mysql.name
  virtual_network_id    = azurerm_virtual_network.spoke.id
  registration_enabled  = false
}

resource "azurerm_private_dns_zone_virtual_network_link" "mysql_hub" {
  name                  = "mysql-hub-link"
  resource_group_name   = azurerm_resource_group.infra.name
  private_dns_zone_name  = azurerm_private_dns_zone.mysql.name
  virtual_network_id    = azurerm_virtual_network.hub.id
  registration_enabled  = false
}