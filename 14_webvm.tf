# Spoke Web Subnet에 Nginx 리버스 프록시를 제공하는 Linux Web VM을 생성하는 파일입니다.
resource "azurerm_network_interface" "web" {
  name                = "web-vm-nic"
  resource_group_name = azurerm_resource_group.infra.name
  location            = azurerm_resource_group.infra.location

  ip_configuration {
    name                          = "web-ipconf"
    subnet_id                     = azurerm_subnet.web.id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_network_interface_application_gateway_backend_address_pool_association" "web" {
  network_interface_id    = azurerm_network_interface.web.id
  ip_configuration_name   = "web-ipconf"
  backend_address_pool_id = one(azurerm_application_gateway.main.backend_address_pool[*].id)
}

resource "azurerm_linux_virtual_machine" "web" {
  name                = "web-vm"
  resource_group_name = azurerm_resource_group.infra.name
  location            = azurerm_resource_group.infra.location
  size                = var.web_vm_size
  admin_username      = var.web_admin_username

  network_interface_ids = [azurerm_network_interface.web.id]

  disable_password_authentication = true

  admin_ssh_key {
    username   = var.web_admin_username
    public_key = trimspace(file(var.web_admin_ssh_public_key_path))
  }

  identity {
    type = "SystemAssigned"
  }

  custom_data = base64encode(templatefile("${path.module}/web_cloudinit.yaml", {
  was_ip    = var.was_private_ip
  kv_uri    = azurerm_key_vault.main.vault_uri
  cert_name = azurerm_key_vault_certificate.appgw.name
  }))

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }

  boot_diagnostics {}

  depends_on = [
    azurerm_firewall.main,
    azurerm_firewall_policy_rule_collection_group.main,
    azurerm_subnet_route_table_association.web
  ]
}

resource "azurerm_virtual_machine_extension" "aad_ssh" {
  name                       = "AADSSHLoginForLinux"
  virtual_machine_id         = azurerm_linux_virtual_machine.web.id
  publisher                  = "Microsoft.Azure.ActiveDirectory"
  type                       = "AADSSHLoginForLinux"
  type_handler_version       = "1.0"
  auto_upgrade_minor_version = true

  # Firewall에서 Entra 도메인이 허용된 뒤 설치
  depends_on = [azurerm_firewall_policy_rule_collection_group.main]
}

# ── Web VM 관리 ID → Key Vault 비밀 사용자 (DB 접속 정보 등 앱 시크릿 조회용) ──
resource "azurerm_role_assignment" "webvm_kv_secrets_user" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_linux_virtual_machine.web.identity[0].principal_id
}