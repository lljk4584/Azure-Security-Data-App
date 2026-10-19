resource "azurerm_firewall_policy_rule_collection_group" "main" {
  name               = "web-rules"
  firewall_policy_id = azurerm_firewall_policy.main.id
  priority           = 100

  application_rule_collection {
    name     = "allow-web-required"
    priority = 100
    action   = "Allow"

    # Ubuntu 패키지 저장소 (cloud-init의 nginx 설치, 보안 업데이트)
    rule {
      name              = "ubuntu-repos"
      source_addresses  = [var.websub, var.wassub]
      destination_fqdns = [
        "azure.archive.ubuntu.com",
        "archive.ubuntu.com",
        "security.ubuntu.com",
      ]
      protocols {
        type = "Http"
        port = 80
      }
      protocols {
        type = "Https"
        port = 443
      }
    }

    # Entra ID SSH 로그인 확장
    rule {
      name              = "entra-ssh-login"
      source_addresses  = [var.websub, var.wassub]
      destination_fqdns = [
        "packages.microsoft.com",
        "login.microsoftonline.com",
        "pas.windows.net",
      ]
      protocols {
        type = "Https"
        port = 443
      }
    }
        # Azure Monitor Agent (VM Syslog → Log Analytics)
    rule {
      name              = "azure-monitor-agent"
      source_addresses  = [var.websub, var.wassub]
      destination_fqdns = [
        "global.handler.control.monitor.azure.com",
        "${var.loca}.handler.control.monitor.azure.com",
        "${azurerm_log_analytics_workspace.main.workspace_id}.ods.opinsights.azure.com",
        "management.azure.com",
      ]
      protocols {
        type = "Https"
        port = 443
      }
    }
        # Key Vault (Web/WAS VM 관리 ID로 비밀 조회)
    rule {
      name              = "key-vault"
      source_addresses  = [var.websub, var.wassub]
      destination_fqdns = ["${var.key_vault_name}.vault.azure.net"]
      protocols {
        type = "Https"
        port = 443
      }
    }
  }
}