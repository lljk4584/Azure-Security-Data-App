# App Gateway와 Web/WAS/DB VM에 필요한 최소 NSG 규칙을 생성하는 파일입니다.
resource "azurerm_network_security_group" "appgw" {
  name                = "nsg-appgw"
  resource_group_name = azurerm_resource_group.infra.name
  location            = azurerm_resource_group.infra.location
}

resource "azurerm_network_security_rule" "appgw_http" {
  name                        = "allow-http"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "80"
  source_address_prefix       = "Internet"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.infra.name
  network_security_group_name = azurerm_network_security_group.appgw.name
}

resource "azurerm_network_security_rule" "appgw_https" {
  name                        = "allow-https"
  priority                    = 105
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "443"
  source_address_prefix       = "Internet"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.infra.name
  network_security_group_name = azurerm_network_security_group.appgw.name
}

resource "azurerm_network_security_rule" "appgw_manager" {
  name                        = "allow-gatewaymanager"
  priority                    = 110
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "65200-65535"
  source_address_prefix       = "GatewayManager"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.infra.name
  network_security_group_name = azurerm_network_security_group.appgw.name
}

resource "azurerm_network_security_rule" "appgw_lb" {
  name                        = "allow-loadbalancer"
  priority                    = 120
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "AzureLoadBalancer"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.infra.name
  network_security_group_name = azurerm_network_security_group.appgw.name
}

resource "azurerm_network_security_group" "web" {
  name                = "nsg-web"
  resource_group_name = azurerm_resource_group.infra.name
  location            = azurerm_resource_group.infra.location
}

resource "azurerm_network_security_rule" "web_http_appgw" {
  name                        = "allow-https-from-appgw"
  priority                    = 105
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "443"
  source_address_prefix       = var.appgwsub
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.infra.name
  network_security_group_name = azurerm_network_security_group.web.name
}

resource "azurerm_network_security_rule" "web_ssh_bastion" {
  name                        = "allow-ssh-from-bastion"
  priority                    = 110
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = var.batsub
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.infra.name
  network_security_group_name = azurerm_network_security_group.web.name
}

resource "azurerm_network_security_rule" "web_to_was" {
  name                        = "allow-was-outbound"
  priority                    = 120
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "8080"
  source_address_prefix       = "*"
  destination_address_prefix  = var.wassub
  resource_group_name         = azurerm_resource_group.infra.name
  network_security_group_name = azurerm_network_security_group.web.name
}

# ── WAS 계층 NSG: Web에서 8080, Bastion에서 22만 허용 ──
resource "azurerm_network_security_group" "was" {
  name                = "nsg-was"
  resource_group_name = azurerm_resource_group.infra.name
  location            = azurerm_resource_group.infra.location
}

resource "azurerm_network_security_rule" "was_app_from_web" {
  name                        = "allow-app-from-web"
  priority                    = 105
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "8080"
  source_address_prefix       = var.websub
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.infra.name
  network_security_group_name = azurerm_network_security_group.was.name
}

resource "azurerm_network_security_rule" "was_ssh_bastion" {
  name                        = "allow-ssh-from-bastion"
  priority                    = 110
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = var.batsub
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.infra.name
  network_security_group_name = azurerm_network_security_group.was.name
}

resource "azurerm_network_security_rule" "was_mysql_to_db" {
  name                        = "allow-mysql-to-db"
  priority                    = 105
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "3306"
  source_address_prefix       = "*"
  destination_address_prefix  = var.dbsub
  resource_group_name         = azurerm_resource_group.infra.name
  network_security_group_name = azurerm_network_security_group.was.name
}

resource "azurerm_network_security_rule" "was_deny_vnet" {
  name                        = "deny-vnet-inbound"
  priority                    = 4000
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "VirtualNetwork"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.infra.name
  network_security_group_name = azurerm_network_security_group.was.name
}

resource "azurerm_network_security_group" "db" {
  name                = "nsg-db"
  resource_group_name = azurerm_resource_group.infra.name
  location            = azurerm_resource_group.infra.location
}

resource "azurerm_network_security_rule" "db_mysql_from_was" {
  name                        = "allow-mysql-from-was"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "3306"
  source_address_prefix       = var.wassub
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.infra.name
  network_security_group_name = azurerm_network_security_group.db.name
}

# 기본 규칙(VNet 내부 전체 허용)보다 먼저 적용되도록 나머지 VNet 내부 트래픽 차단
resource "azurerm_network_security_rule" "db_deny_vnet" {
  name                        = "deny-vnet-inbound"
  priority                    = 4000
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "VirtualNetwork"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.infra.name
  network_security_group_name = azurerm_network_security_group.db.name
}