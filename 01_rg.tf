# 인프라용 INFRA-RG와 보안용 Security-RG를 생성하는 파일입니다.
resource "azurerm_resource_group" "infra" {
  name     = var.rgname
  location = var.loca
}

resource "azurerm_resource_group" "security" {
  name     = var.security_rg_name
  location = var.loca
}
