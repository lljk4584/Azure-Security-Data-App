# Web VM을 Public IP 없이 관리하기 위한 Azure Bastion을 생성하는 파일입니다.
resource "azurerm_bastion_host" "bastion" {
  name                = "bastion"
  resource_group_name = azurerm_resource_group.infra.name
  location            = azurerm_resource_group.infra.location
  sku                 = "Standard"
  tunneling_enabled   = true
  copy_paste_enabled = true # false로 바꿔야함
  file_copy_enabled = true #false로 바꿔야함

  ip_configuration {
    name                 = "bastion-ipconf"
    subnet_id            = azurerm_subnet.bastion.id
    public_ip_address_id = azurerm_public_ip.bastion.id
  }
}
