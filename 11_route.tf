# Web/WAS Subnet의 기본 Outbound 경로를 Azure Firewall로 보내는 UDR을 생성하는 파일입니다.
resource "azurerm_route_table" "web" {
  name                = "route-table"
  resource_group_name = azurerm_resource_group.infra.name
  location            = azurerm_resource_group.infra.location
}

resource "azurerm_route" "default_to_firewall" {
  name                   = "default-to-firewall"
  resource_group_name    = azurerm_resource_group.infra.name
  route_table_name       = azurerm_route_table.web.name
  address_prefix         = "0.0.0.0/0"
  next_hop_type          = "VirtualAppliance"
  next_hop_in_ip_address = azurerm_firewall.main.ip_configuration[0].private_ip_address
}

resource "azurerm_subnet_route_table_association" "web" {
  subnet_id      = azurerm_subnet.web.id
  route_table_id = azurerm_route_table.web.id
}

resource "azurerm_subnet_route_table_association" "was" {
  subnet_id      = azurerm_subnet.was.id
  route_table_id = azurerm_route_table.web.id
}