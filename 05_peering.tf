resource "azurerm_virtual_network_peering" "hub_to_spoke" {
  name                         = "hub-to-spoke"
  resource_group_name          = azurerm_resource_group.infra.name
  virtual_network_name         = azurerm_virtual_network.hub.name
  remote_virtual_network_id    = azurerm_virtual_network.spoke.id
  allow_virtual_network_access = true
  allow_forwarded_traffic      = true

  depends_on = [
    azurerm_subnet.firewall, azurerm_subnet.appgw, azurerm_subnet.bastion,
    azurerm_subnet.web, azurerm_subnet.db
  ]
}

resource "azurerm_virtual_network_peering" "spoke_to_hub" {
  name                         = "spoke-to-hub"
  resource_group_name          = azurerm_resource_group.infra.name
  virtual_network_name         = azurerm_virtual_network.spoke.name
  remote_virtual_network_id    = azurerm_virtual_network.hub.id
  allow_virtual_network_access = true
  allow_forwarded_traffic      = true

  depends_on = [
    azurerm_subnet.firewall, azurerm_subnet.appgw, azurerm_subnet.bastion,
    azurerm_subnet.web, azurerm_subnet.db,
    azurerm_virtual_network_peering.hub_to_spoke
  ]
}