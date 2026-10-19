output "https_url" {
  value = "https://${var.domain_name}"
}

output "appgw_public_ip" {
  description = "호스팅케이알 A 레코드에 넣을 IP"
  value       = azurerm_public_ip.appgw.ip_address
}

output "firewall_public_ip" {
  value = azurerm_public_ip.firewall.ip_address
}

output "web_private_ip" {
  value = azurerm_network_interface.web.private_ip_address
}

output "mysql_fqdn" {
  value = azurerm_mysql_flexible_server.main.fqdn
}

output "key_vault_name" {
  value = azurerm_key_vault.main.name
}

output "storage_account_name" {
  value = azurerm_storage_account.security.name
}

output "certificate_expires" {
  value = azurerm_key_vault_certificate.appgw.certificate_attribute[0].expires
}