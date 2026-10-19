# 보안 & 데이터 및 App 보안 구축

## 목적
현재 V8은 공격/차단 시나리오보다 **Azure 서비스 뼈대를 먼저 생성하는 단계**입니다. GitHub 자동배포는 사용하지 않으며 Web VM에는 Nginx 기본 확인 페이지만 설치합니다.

## 생성 구조
- INFRA-RG: Hub/Spoke VNet, Peering, NSG, Bastion, Azure Firewall, UDR, Application Gateway + WAF, Web VM, Azure SQL, Private Endpoint, Private DNS, Log Analytics
- Security-RG: Key Vault, Storage Account, Private Blob Container
- Entra ID: Object ID를 입력한 경우에만 보안 관리자 / 인프라 관리자 / 서비스 관리자 역할 할당

## 현재 단계의 통신 구조
Internet → Application Gateway(WAF_v2, Detection, HTTP 80) → Web VM(Nginx HTTP 80)
Web VM → UDR → Azure Firewall → Internet
Web VM → Azure SQL Private Endpoint(1433)
Bastion → Web VM(SSH 22)

## V8에서 의도적으로 제외한 것
- GitHub 소스 자동배포
- 실제 PHP/애플리케이션 소스
- SQL 테이블/초기 데이터
- Sentinel Onboarding 및 분석 규칙
- Defender for Cloud 설정
- Entra 로그인 탐지
- WAF Prevention 차단 테스트
- Key Vault Secret 실제 연동
- HTTPS 인증서 적용

위 기능은 서비스 뼈대가 정상 배포된 후 보안 단계에서 추가합니다.

## 파일 연결표
| 파일 | 생성 내용 |
|---|---|
| 00_init.tf | Terraform / Azure Provider |
| 01_rg.tf | INFRA-RG / Security-RG |
| 02_vnet.tf | Hub / Spoke VNet |
| 03_subnet.tf | Firewall / AppGW / Bastion / Web / DB Subnet |
| 04_pip.tf | AppGW / Firewall / Bastion Public IP |
| 05_peering.tf | Hub ↔ Spoke Peering |
| 06_nsg.tf | AppGW / Web NSG |
| 07_nsg_association.tf | NSG와 Subnet 연결 |
| 08_bastion.tf | Azure Bastion |
| 09_firewall.tf | Azure Firewall / Firewall Policy |
| 10_firewall_rule.tf | 초기 Web Outbound HTTP/HTTPS 허용 |
| 11_route.tf | Web → Firewall UDR |
| 12_keyvault.tf | Key Vault |
| 13_appgw.tf | Application Gateway + WAF |
| 14_webvm.tf | Web VM / NIC / AppGW Backend 연결 |
| 15_private_dns.tf | Azure SQL Private DNS |
| 16_sqldb.tf | Azure SQL DB / Private Endpoint |
| 17_storage.tf | Storage Account / Private Container |
| 18_log_analytics.tf | Log Analytics Workspace |
| 19_rbac.tf | 선택형 관리자 RBAC |
| 99_outputs.tf | 배포 결과 출력 |
| 100_var.tf | 변수 정의 |
| web_cloudinit.yaml | Nginx 기본 페이지 설치 |

## 실행 순서
```bash
cp terraform.tfvars.example terraform.tfvars
# terraform.tfvars에서 전역 고유 이름, 구독 ID, Tenant ID, SSH 공개키 수정

# SQL 비밀번호는 환경변수로 입력
export TF_VAR_sql_admin_password='Strong-Password!123'

terraform init
terraform fmt
terraform validate
terraform plan
terraform apply
```

PowerShell에서는 다음과 같이 입력합니다.
```powershell
$env:TF_VAR_sql_admin_password = "Strong-Password!123"
terraform init
terraform fmt
terraform validate
terraform plan
terraform apply
```

## 배포 후 확인
`terraform output appgw_url`에 출력되는 주소로 접속했을 때 `Team 4·5 Azure Service` 페이지가 보이면 1차 서비스 뼈대가 정상입니다.

## 다음 단계
1. Application Gateway HTTPS 443 적용
2. 실제 Web/PHP 서비스 배포
3. Web → Key Vault → SQL Credential 연동
4. WAF Prevention 전환 후 공격 차단 테스트
5. Log Analytics 진단 로그 연결
6. Sentinel / Defender for Cloud / 내부 유출 탐지 추가
