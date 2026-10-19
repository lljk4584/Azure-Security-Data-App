variable "subid" {
  type = string
}

variable "appgw_dns_label" {
  type    = string
  default = "team4-appgw"
}

variable "web_admin_ssh_public_key_path" {
  type    = string
  default = "./id_rsa.pub" # "C:/01_team4_project/id_rsa.pub"
}

variable "web_admin_ssh_private_key_path" {
  type    = string
  default = "./id_rsa" # "C:/01_team4_project/id_rsa"
}

variable "mysql_server_name" {
  type    = string
  default = "team4-mysql"
}

variable "mysql_entra_admin_object_id" {
  type = string
}

variable "key_vault_name" {
  type    = string
  default = "team4-kv"
}

variable "storage_account_name" {
  type    = string
  default = "team4storage"
}

variable "loca" {
  type    = string
  default = "koreacentral"
}

variable "project_prefix" {
  type    = string
  default = "team4"
}

variable "rgname" {
  type    = string
  default = "team4-INFRA-RG"
}

variable "security_rg_name" {
  type    = string
  default = "team4-Security-RG"
}

# 네트워크
variable "hubcidr" {
  type    = string
  default = "10.10.0.0/16"
}

variable "fwsub" {
  type    = string
  default = "10.10.1.0/26"
}

variable "appgwsub" {
  type    = string
  default = "10.10.2.0/24"
}

variable "batsub" {
  type    = string
  default = "10.10.3.0/26"
}

variable "spokecidr" {
  type    = string
  default = "10.20.0.0/16"
}

variable "websub" {
  type    = string
  default = "10.20.1.0/24"
}

variable "dbsub" {
  type    = string
  default = "10.20.2.0/24"
}

variable "wassub" {
  type    = string
  default = "10.20.3.0/24"
}

variable "was_private_ip" {
  type    = string
  default = "10.20.3.10"
}

variable "domain_name" {
  type    = string
  default = "example.com"
}

variable "certificate_name" {
  type    = string
  default = "team4-cloud"
}

variable "pfx_path" {
  type    = string
  default = "./team4-fullchain.pfx"
}

variable "pfx_password" {
  type      = string
  sensitive = true
}

# Web VM
variable "web_vm_size" {
  type    = string
  default = "Standard_B2s"
}

variable "web_admin_username" {
  type    = string
  default = "team4"
}

variable "mysql_admin_username" {
  type    = string
  default = "team4"
}

variable "mysql_sku" {
  type    = string
  default = "B_Standard_B1ms"
}

variable "app_db_name" {
  type    = string
  default = "emp_db"
}

# 관리자 (Entra ID 사용자 Object ID 목록)

variable "security_admins" {
  type    = list(string)
  default = []   # 보안 관리자 Object ID
}
# Contributor/Key Vault Administrator/Microsoft Sentinel Contributor


variable "infra_admins" {
  type    = list(string)
  default = []   # 인프라 관리자 Object ID
}
# Contributor/Virtual Machine Administrator Login

variable "service_admins" {
  type    = list(string)
  default = []   # 서비스 관리자 Object ID
}
# Virtual Machine Contributor/Virtual Machine User Login

variable "cso" {
  type = list(string)
  default = []   # 보안 최고관리자(CSO) Object ID
}

variable "mysql_entra_admin_login" {
  type    = string
  default = "team4-entra"
}

variable "alert_email" {
  type = string
}

variable "alert_email_backup" {
  type = string
}

# Key Vault / Storage 방화벽에서 허용할 관리자 공인 IP (예: 203.0.113.10)
variable "admin_public_ip" {
  type = string
}

# 자동 차단에서 제외할 IP (비워두면 호스트 PC도 차단 대상)
variable "waf_autoblock_exclude" {
  type    = list(string)
  default = []
}