# WAS Subnet에 Flask 애플리케이션(gunicorn:8080)을 올리는 WAS VM을 생성하는 파일입니다.
# web-vm(nginx) → was-vm(8080) → MySQL(3306) 흐름의 중간 계층(WAS)입니다.
# DB 접속은 비밀번호 없이, id-was-app 관리 ID의 Entra 토큰으로 수행한다.

resource "azurerm_network_interface" "was" {
  name                = "was-vm-nic"
  resource_group_name = azurerm_resource_group.infra.name
  location            = azurerm_resource_group.infra.location

  ip_configuration {
    name                          = "was-ipconf"
    subnet_id                     = azurerm_subnet.was.id
    private_ip_address_allocation = "Static"
    private_ip_address            = var.was_private_ip
  }
}

resource "azurerm_linux_virtual_machine" "was" {
  name                = "was-vm"
  resource_group_name = azurerm_resource_group.infra.name
  location            = azurerm_resource_group.infra.location
  size                = var.web_vm_size
  admin_username      = var.web_admin_username

  network_interface_ids = [azurerm_network_interface.was.id]

  disable_password_authentication = true

  admin_ssh_key {
    username   = var.web_admin_username
    public_key = trimspace(file(var.web_admin_ssh_public_key_path))
  }

  # 관리 ID 2개: id-mysql(부팅 시 앱 유저 생성용 DB 관리자) + id-was-app(앱 런타임 DB 접속, 최소권한)
  identity {
    type = "SystemAssigned, UserAssigned"
    identity_ids = [
      azurerm_user_assigned_identity.mysql.id,
      azurerm_user_assigned_identity.was_app.id,
    ]
  }

  custom_data = base64encode(templatefile("${path.module}/was_cloudinit.yaml", {
    mysql_fqdn      = azurerm_mysql_flexible_server.main.fqdn
    db_name         = var.app_db_name
    admin_login     = "id-mysql"
    admin_client_id = azurerm_user_assigned_identity.mysql.client_id
    app_login       = "was_app"
    app_client_id   = azurerm_user_assigned_identity.was_app.client_id
    app_object_id   = azurerm_user_assigned_identity.was_app.principal_id
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

  # cloud-init이 첫 부팅에서 네트워크(방화벽 허용·피어링)·DB·Entra 관리자에
  # 모두 접근할 수 있도록, 아래가 모두 준비된 뒤 VM을 만든다.
  depends_on = [
    azurerm_firewall.main,
    azurerm_firewall_policy_rule_collection_group.main,
    azurerm_subnet_route_table_association.was,
    azurerm_virtual_network_peering.hub_to_spoke,
    azurerm_virtual_network_peering.spoke_to_hub,
    azurerm_mysql_flexible_database.app,
    azurerm_mysql_flexible_server_configuration.audit_events,
    azurerm_mysql_flexible_server_active_directory_administrator.main,
  ]
}

resource "azurerm_virtual_machine_extension" "was_aad_ssh" {
  name                       = "AADSSHLoginForLinux"
  virtual_machine_id         = azurerm_linux_virtual_machine.was.id
  publisher                  = "Microsoft.Azure.ActiveDirectory"
  type                       = "AADSSHLoginForLinux"
  type_handler_version       = "1.0"
  auto_upgrade_minor_version = true

  depends_on = [azurerm_firewall_policy_rule_collection_group.main]
}

# 참고: 앱이 더 이상 Key Vault에서 DB 비밀번호를 읽지 않으므로
# WAS의 Key Vault Secrets User 역할 할당은 제거(최소권한).
# KV의 mysql-admin-password 비밀 자체는 break-glass 용도로 그대로 보관한다.
