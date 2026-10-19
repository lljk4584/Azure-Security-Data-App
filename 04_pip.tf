# Application Gateway, Azure Firewall, Bastion이 사용할 Public IP를 생성하는 파일입니다.
resource "azurerm_public_ip" "appgw" {
  name                = "appgw-pip"
  resource_group_name = azurerm_resource_group.infra.name
  location            = azurerm_resource_group.infra.location
  allocation_method   = "Static"
  sku                 = "Standard"
  domain_name_label   = var.appgw_dns_label
}

resource "azurerm_public_ip" "firewall" {
  name                = "firewall-pip"
  resource_group_name = azurerm_resource_group.infra.name
  location            = azurerm_resource_group.infra.location
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_public_ip" "bastion" {
  name                = "bastion-pip"
  resource_group_name = azurerm_resource_group.infra.name
  location            = azurerm_resource_group.infra.location
  allocation_method   = "Static"
  sku                 = "Standard"
}
