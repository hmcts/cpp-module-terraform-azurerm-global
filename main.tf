locals {
  tags = {
    domain      = "cpp.nonlive"
    platform    = var.platform
    environment = var.environment
    tier        = var.tier
    project     = ""
  }
  global_tags = {
    creator         = "SPT/terraform"
    expiration_date = "none"
    owner           = "HMCTS-SP"
    timestamp       = formatdate("DDMMYY", timestamp())
  }
  locations = {
    uks = "uksouth"
    ukw = "ukwest"
    eas = "eastasia"
    sea = "southeastasia"
    cus = "centralus"
  }
  prefixes = {
    api_connection          = "apic"
    api_management_services = "apim"
    app_registration        = "spn"
    app_service_plan        = "plan"
    application_gateway     = "agw"
  }
  global_azure_location                  = "uksouth"
  global_azure_read_replication_location = "ukwest"
  prefix_default_route                   = "0.0.0.0/0"
  env = {
    environment_short_name_lower          = "mdv"
    environment_mgmt_lower                = "mdv"
    environment_dns_third_octet           = "88"
    environment_realm                     = "CPP.NONLIVE"
    environment_domain                    = "cpp.nonlive"
    environment_platform                  = "nlv"
    environment_adds_account              = "domainjoin"
    environment_jenkins_app_id            = "1a0172bd-5e9d-4017-aab3-0756c7dbd7cf"
    environment_admin_group_id            = "c1c0dad5-6923-4ab4-a5c4-360e5e2a7971"
    environment_oms_rg                    = "RG-MDV-INT-01"
    environment_oms_name                  = "oms-cpp-nonlive"
    environment_storage_account_repl_type = "GRS"
    tier_short_name_lower                 = "int"
    environment_dns_resolvers             = []
  }
  azure = {
    resource_group_name       = "RG-${upper(local.env.environment_short_name_lower)}-${upper(local.env.tier_short_name_lower)}-01"
    app_backup_rg             = "RG-${upper(local.env.environment_short_name_lower)}-BACKUP-${upper(local.env.tier_short_name_lower)}"
    default_vm_size           = "Standard_DS1_v2"
    default_kali_vm_size      = "Standard_DS2_v2"
    standard_vm_size          = "Standard_D4s_v3"
    latest_cimaster_vm_size   = "Standard_E4as_v4"
    cimaster_vm_size          = "Standard_E8s_v3"
    default_db_vm_size        = "Standard_E8s_v3"
    premium_disk              = "Premium_LRS"
    standard_disk             = "Standard_LRS"
    storage_account           = "sa${local.env.environment_short_name_lower}${local.env.tier_short_name_lower}01"
    storage_account_repl_type = "${local.env.environment_storage_account_repl_type}"
    storage_container         = "sa${local.env.environment_short_name_lower}${local.env.tier_short_name_lower}01-container"
    storage_container_images  = "sa${local.env.environment_short_name_lower}${local.env.tier_short_name_lower}01-container-images"
    storage_container_NFS     = "sa${local.env.environment_short_name_lower}${local.env.tier_short_name_lower}01-nfs"
    tfstate_storage_account   = "sa${local.env.environment_mgmt_lower}shared01"
    tfstate_storage_container = "sa${local.env.environment_mgmt_lower}shared01-container-tfstates"
    scripts_storage_account   = "sa${local.env.environment_mgmt_lower}shared01"
    scripts_storage_container = "sa${local.env.environment_mgmt_lower}shared01-container-scripts"
    domainjoin_user           = "${local.env.environment_adds_account}"
    realm                     = "${local.env.environment_realm}"
    redis_cache_elk_name      = "${local.identifiers.redis_cache}-${upper(local.env.environment_short_name_lower)}-${upper(local.env.tier_short_name_lower)}-ELK"
    domain                    = "${local.env.environment_domain}"
    mgmt_tier                 = "${local.env.environment_mgmt_lower}"
    patching_tag              = "${var.environment_patching_tag}"
  }
  identifiers = {
    application_gateway        = "GW"
    application_security_group = "AG"
    availability_set           = "AS"
    encryption_key             = "EK"
    eventhub                   = "EH"
    eventhub_auth_rule         = "ER"
    eventhub_namespace         = "EN"
    key_vault                  = "KV"
    load_balancer              = "LB"
    nic                        = "NI"
    postgresql                 = "PS"
    redis_cache                = "RC"
    resource_group             = "RG"
    resource_lock              = "RL"
    subnet                     = "SN"
    udr                        = "UR"
    vip                        = "IP"
    virtual_machine            = "VM"
    vnet                       = "VN"
    vnet_gateway               = "VG"
    local_net_gateway          = "LNG"
  }
  environments = {
    dmo                    = "DMO"
    ste                    = "STE"
    dev                    = "DEV"
    management_development = "MDV"
    management_production  = "MPD"
    nft                    = "NFT"
    nle                    = "NLE"
    lve                    = "LVE"
    prd                    = "PRD"
    prp                    = "PRP"
    prx                    = "PRX"
    sit                    = "SIT"
  }
  external_ntp_sources = {
    npl_source_1 = "139.143.5.30"
    npl_source_2 = "139.143.5.31"
    leo_source_1 = "188.39.213.7"
    leo_source_2 = "85.199.214.102"
  }
  sh_office_ips = {
    range_1 = "167.98.162.96/28"
    range_2 = "62.6.59.98"
    range_3 = "5.148.40.98"
    # range_4 = "167.98.162.96/28"
  }
  dom1_ips = {
    range_1 = "157.203.177.19"
    range_2 = "157.203.177.190"
    range_3 = "195.59.75.0/24"
    range_4 = "194.33.192.0/25"
    range_5 = "194.33.196.0/25"
    range_6 = "194.33.193.0/25"
    range_7 = "194.33.197.0/25"
  }
  cgi_aem_ips = {
    range_1 = "163.164.232.146"
    range_2 = "163.164.232.147"
    range_3 = "185.157.224.136/29"
    range_4 = "185.157.225.136/29"
  }
  lv-vnet-scheme = {
    address_space_vnet                   = "10.200.0.0/16"
    address_prefix-subnet-ci             = "10.200.48.0/27"
    address_prefix-subnet-prp-cislave    = "10.201.64.0/24"
    address_prefix-subnet-prd-cislave    = "10.202.64.0/24"
    address_prefix-subnet-yumrepo        = "10.200.48.64/27"
    address_prefix-subnet-artrepo        = "10.200.48.192/27"
    address_prefix-subnet-prpbae-cislave = "10.203.62.0/24"
  }
  nlv-vnet-scheme = {
    address_space_vnet = "10.88.0.0/14"
  }
  nle-ccp-vnet-scheme = {
    address_space_vnet = "10.93.0.0/20"
  }
  mdv-dmz-vnet-scheme = {
    address_space_vnet               = "10.88.112.0/20"
    address_prefix-subnet-adminvpn   = "10.88.112.0/27"
    address_prefix-subnet-dmzjumpl   = "10.88.112.32/27"
    address_prefix-subnet-publishing = "10.88.112.64/27"
    address_prefix-subnet-ngf        = "10.88.112.96/27"
    address_prefix-subnet-dmzntp     = "10.88.112.128/27"
    address_prefix-subnet-vpnusers   = "10.88.124.0/22"
    address_prefix-subnet-vpnusers1  = "10.88.120.0/22"
    address_prefix-subnet-vpnusers2  = "10.88.116.0/22"
  }
  mdv-int-vnet-scheme = {
    address_space_vnet                 = "10.88.128.0/20"
    address_prefix-subnet-ci           = "10.88.128.0/27"
    address_prefix-subnet-jumpl        = "10.88.128.32/27"
    address_prefix-subnet-yumrepo      = "10.88.128.64/27"
    address_prefix-subnet-secret       = "10.88.128.96/27"
    address_prefix-subnet-crev         = "10.88.128.192/27"
    address_prefix-subnet-artrepo      = "10.88.129.0/27"
    address_prefix-subnet-adds-gateway = "10.88.129.32/27"
    address_prefix-subnet-secretbe     = "10.88.129.64/27"
    address_prefix-subnet-sonarqube    = "10.88.129.96/27"
    address_prefix-subnet-ntp          = "10.88.129.128/27"
    address_prefix-subnet-monitoring   = "10.88.129.160/27"
    address_prefix-subnet-clamavmir    = "10.88.129.224/27"
    address_prefix-subnet-wafcc        = "10.88.130.0/27"
    address_prefix-subnet-vul-scan-cc  = "10.88.130.32/28"
    address_prefix-subnet-secretbe2    = "10.88.128.128/28"
    address_prefix-subnet-appgw2       = "10.88.132.0/27"
    address_prefix-subnet-pg-pem       = "10.88.132.32/28"
    address_prefix-subnet-appgw0       = "10.88.132.64/27"
    address_prefix-subnet-zabbix       = "10.88.133.0/27"
    address_prefix-subnet-elk          = "10.88.133.32/27"
    address_prefix-subnet-rc-elk       = "10.88.133.64/29"
    address_prefix_subnet_dynatrace    = "10.88.133.96/28"
    address_prefix-subnet-ngf-cc       = "10.88.135.0/29"
    address_prefix-subnet-appgw1       = "10.88.132.96/27"
    address_prefix-subnet-mgtprx       = "10.88.130.128/27"
  }
  mdv-imz-vnet-scheme = {
    address_space_vnet               = "10.88.144.0/20"
    address_prefix-subnet-ftps-inner = "10.88.144.32/29"
    address_prefix-subnet-ngf        = "10.88.156.0/28"

    address_prefix-subnet-cgi-darts = "10.72.1.0/24"

    address_prefix-subnet-cms-proxy = "10.88.145.0/29"
    address_prefix-subnet-darts-waf = "10.88.145.8/29"
    address_prefix-subnet-libra-ftp = "10.88.145.16/29"
    address_prefix-subnet-xhbit-ftp = "10.88.145.32/29"
    address_prefix-subnet-psnp-ftp  = "10.88.145.40/29"

    address_prefix-subnet-outbound-proxy = "10.88.155.24/29"

    address_prefix-imz-waf = "10.88.145.12"

    address_prefix-subnet-azure-vpn-gateways = "10.88.155.32/29"
    address_prefix-subnet-azure-vpn-cgi      = "172.28.165.0/24"
    address_prefix-subnet-azure-vpn-psn      = "10.25.255.66/32"
    address_prefix-azure-vpn-cgi_gateway     = "163.164.232.146"
    address_prefix-azure-vpn-psn_gateway     = "51.231.160.172"
    address_prefix-azure-leg-cgi_gateway     = "185.230.152.73"
    address_prefix-subnet-azure-leg-cgi      = "169.254.1.0/30"
    address_prefix-azure-leg-cgi_gateway-dr  = "185.230.154.73"
    address_prefix-subnet-azure-leg-cgi-dr   = "169.254.4.0/30"
    address_prefix-leg-cgi-bgp-peering       = "198.51.100.1"
    address_prefix-leg-cgi-dr-bgp-peering    = "198.51.100.2"

    address_prefix-azure-vpn-gateway-ark-c = "185.157.225.131"
    address_prefix-subnet-azure-vpn-ark-c  = "10.2.80.64/28"

    address_prefix-azure-vpn-gateway-ark-f = "185.157.224.131"
    address_prefix-subnet-azure-vpn-ark-f  = "10.3.80.64/28"
  }
  mdv-sbz-vnet-scheme = {
    address_space_vnet               = "10.88.160.0/20"
    address_prefix-subnet-cislave    = "10.88.160.0/27"
    address_prefix-subnet-alfresco   = "10.88.160.32/27"
    address_prefix-subnet-alfrescodb = "10.88.160.64/27"
    address_prefix-subnet-owasp      = "10.88.160.96/27"
  }
  mdv-sbz2-vnet-scheme = {
    address_space_vnet           = "10.88.176.0/24"
    address_prefix-subnet-bld-vm = "10.88.176.0/29"
    address_prefix-subnet-kau    = "10.88.176.8/29"
  }
  mdv-ste-vnet-scheme = {
    address_space_vnet               = "10.88.176.0/24"
    address_prefix-subnet-webserver  = "10.88.176.0/27"
    address_prefix-subnet-alfresco   = "10.88.176.32/27"
    address_prefix-subnet-wildfly    = "10.88.176.64/27"
    address_prefix-subnet-artemis    = "10.88.176.96/27"
    address_prefix-subnet-alfrescodb = "10.88.176.160/27"
    address_prefix-subnet-contextdb  = "10.88.176.192/27"
    address_prefix-subnet-docmosis   = "10.88.176.224/27"
  }
  ste-vnet-scheme = {
    address_space_vnet               = "10.87.0.0/16"
    address_prefix-subnet-ops        = "10.87.0.0/24"
    address_prefix-subnet-ccm-web    = "10.87.10.0/23"
    address_prefix-subnet-ccm-app    = "10.87.12.0/23"
    address_prefix-subnet-ccm-dat    = "10.87.14.0/23"
    address_prefix-subnet-wfm-gtw-01 = "10.87.20.0/27"
    address_prefix-subnet-wfm-app-01 = "10.87.20.32/27"

    # PAAS stuff
    address_prefix-subnet-rc-laa1    = "10.87.127.240/28"
    address_prefix-subnet-rc-common  = "10.87.127.224/28"
    address_prefix-subnet-laa1       = "10.87.127.208/28"
    address_prefix-subnet-sd-common  = "10.87.127.192/28"
    address_prefix-subnet-csfl       = "10.87.127.160/28"
    address_prefix-subnet-blks       = "10.87.127.144/28"
    address_prefix-subnet-laa        = "10.87.127.128/28"
    address_prefix-subnet-scsl       = "10.87.127.112/28"
    address_prefix-subnet-sa-common  = "10.87.127.104/29"
    address_prefix-subnet-kv-common  = "10.87.127.96/29"
    address_prefix-subnet-blks-1     = "10.87.127.88/29"
    address_prefix-subnet-notifyatt  = "10.87.127.64/28"
    address_prefix-subnet-rc-common1 = "10.87.127.0/28" # temp fix to provision the correct common RC
  }
  dev-ccm-vnet-scheme = {
    address_space_vnet        = "10.89.64.0/18"
    address_space_vnet_w      = "10.150.0.0/16"
    address_prefix-subnet-ops = "10.89.64.0/24"

    address_prefix-subnet-web-01     = "10.89.65.0/27"
    address_prefix-subnet-app-01     = "10.89.65.32/27"
    address_prefix-subnet-data-01    = "10.89.65.64/27"
    address_prefix-subnet-wfm-gtw-01 = "10.89.65.96/27"
    address_prefix-subnet-wfm-app-01 = "10.89.65.128/27"

    address_prefix-subnet-web-02  = "10.89.66.0/26"
    address_prefix-subnet-app-02  = "10.89.66.64/26"
    address_prefix-subnet-data-02 = "10.89.66.128/26"

    address_prefix-subnet-web-03  = "10.89.67.0/26"
    address_prefix-subnet-app-03  = "10.89.67.64/26"
    address_prefix-subnet-data-03 = "10.89.67.128/26"

    address_prefix-subnet-web-04  = "10.89.68.0/26"
    address_prefix-subnet-app-04  = "10.89.68.64/26"
    address_prefix-subnet-data-04 = "10.89.68.128/26"

    address_prefix-subnet-web-05  = "10.89.69.0/26"
    address_prefix-subnet-app-05  = "10.89.69.64/26"
    address_prefix-subnet-data-05 = "10.89.69.128/26"

    address_prefix-subnet-web-06  = "10.89.71.0/26"
    address_prefix-subnet-app-06  = "10.89.71.64/26"
    address_prefix-subnet-data-06 = "10.89.71.128/26"

    address_prefix-subnet-web-07  = "10.89.72.0/26"
    address_prefix-subnet-app-07  = "10.89.72.64/26"
    address_prefix-subnet-data-07 = "10.89.72.128/26"

    address_prefix-subnet-web-08  = "10.89.73.0/26"
    address_prefix-subnet-app-08  = "10.89.73.64/26"
    address_prefix-subnet-data-08 = "10.89.73.128/26"

    address_prefix-subnet-web-09  = "10.89.74.0/26"
    address_prefix-subnet-app-09  = "10.89.74.64/26"
    address_prefix-subnet-data-09 = "10.89.74.128/26"

    address_prefix-subnet-web-10  = "10.89.80.0/24"
    address_prefix-subnet-app-10  = "10.89.81.0/24"
    address_prefix-subnet-data-10 = "10.89.82.0/24"

    address_prefix-subnet-web-11  = "10.89.83.0/24"
    address_prefix-subnet-app-11  = "10.89.84.0/24"
    address_prefix-subnet-data-11 = "10.89.85.0/24"

    address_prefix-subnet-web-12  = "10.89.86.0/24"
    address_prefix-subnet-app-12  = "10.89.87.0/24"
    address_prefix-subnet-data-12 = "10.89.88.0/24"

    address_prefix-subnet-web-13  = "10.89.89.0/24"
    address_prefix-subnet-app-13  = "10.89.90.0/24"
    address_prefix-subnet-data-13 = "10.89.91.0/24"

    address_prefix-subnet-web-14  = "10.89.92.0/24"
    address_prefix-subnet-app-14  = "10.89.93.0/24"
    address_prefix-subnet-data-14 = "10.89.94.0/24"

    address_prefix-subnet-web-15  = "10.89.95.0/24"
    address_prefix-subnet-app-15  = "10.89.96.0/24"
    address_prefix-subnet-data-15 = "10.89.97.0/24"

    address_prefix-subnet-web-16  = "10.89.98.0/24"
    address_prefix-subnet-app-16  = "10.89.99.0/24"
    address_prefix-subnet-data-16 = "10.89.100.0/24"

    address_prefix-subnet-web-17  = "10.89.101.0/24"
    address_prefix-subnet-app-17  = "10.89.102.0/24"
    address_prefix-subnet-data-17 = "10.89.103.0/24"

    address_prefix-subnet-web-18  = "10.89.104.0/24"
    address_prefix-subnet-app-18  = "10.89.105.0/24"
    address_prefix-subnet-data-18 = "10.89.106.0/24"

    address_prefix-subnet-web-19  = "10.89.107.0/24"
    address_prefix-subnet-app-19  = "10.89.108.0/24"
    address_prefix-subnet-data-19 = "10.89.109.0/24"

    address_prefix-subnet-web-20  = "10.89.110.0/24"
    address_prefix-subnet-app-20  = "10.89.111.0/24"
    address_prefix-subnet-data-20 = "10.89.112.0/24"

    address_prefix-subnet-web-21  = "10.89.113.0/24"
    address_prefix-subnet-app-21  = "10.89.114.0/24"
    address_prefix-subnet-data-21 = "10.89.115.0/24"



    #   This Subnet is never used so commented out and overlapping with DEV10
    #   address_prefix-subnet-int-kali = "10.89.80.64/27"

    address_prefix-subnet-rc-common = "10.89.127.224/28"

    address_prefix-subnet-apim-appgw = "10.89.127.248/29"
    address_prefix-subnet-apim-app   = "10.89.127.240/29"

    address_space_vnet_dmz         = "10.89.192.0/19"
    address_prefix-subnet-waf      = "10.89.192.0/27"
    address_prefix-subnet-dmz-kali = "10.89.192.32/29"
  }
  dev-ccm-app-subnets = [
    local.dev-ccm-vnet-scheme.address_prefix-subnet-app-01,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-app-02,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-app-03,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-app-04,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-app-05,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-app-06,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-app-07,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-app-08,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-app-09,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-app-10,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-app-11,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-app-12,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-app-13,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-app-14,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-app-15,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-app-16,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-app-17,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-app-18,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-app-19,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-app-20,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-app-21,
  ]
  dev-ccm-web-subnets = [
    local.dev-ccm-vnet-scheme.address_prefix-subnet-web-01,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-web-02,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-web-03,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-web-04,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-web-05,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-web-06,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-web-07,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-web-08,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-web-09,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-web-10,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-web-11,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-web-12,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-web-13,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-web-14,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-web-15,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-web-16,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-web-17,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-web-18,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-web-19,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-web-20,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-web-21,
  ]
  dev-ccm-data-subnets = [
    local.dev-ccm-vnet-scheme.address_prefix-subnet-data-01,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-data-02,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-data-03,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-data-04,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-data-05,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-data-06,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-data-07,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-data-08,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-data-09,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-data-10,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-data-11,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-data-12,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-data-13,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-data-14,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-data-15,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-data-16,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-data-17,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-data-18,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-data-19,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-data-20,
    local.dev-ccm-vnet-scheme.address_prefix-subnet-data-21,
  ]
  sit-ccm-vnet-scheme = {
    address_space_vnet        = "10.90.64.0/18"
    address_prefix-subnet-ops = "10.90.64.0/24"

    address_prefix-subnet-web-01       = "10.90.65.0/27"
    address_prefix-subnet-app-01       = "10.90.65.32/27"
    address_prefix-subnet-app-audit-01 = "10.90.65.96/27"
    address_prefix-subnet-data-01      = "10.90.65.64/27"

    address_prefix-subnet-web-02  = "10.90.66.0/27"
    address_prefix-subnet-app-02  = "10.90.66.32/27"
    address_prefix-subnet-data-02 = "10.90.66.64/27"

    address_prefix-subnet-int-kali = "10.90.80.64/29"

    address_prefix-subnet-rc-common = "10.90.127.224/28"

    address_prefix-subnet-apim-appgw = "10.90.127.248/29"
    address_prefix-subnet-apim-app   = "10.90.127.240/29"

    address_space_vnet_dmz         = "10.90.192.0/19"
    address_prefix-subnet-waf      = "10.90.192.0/27"
    address_prefix-subnet-dmz-kali = "10.90.192.32/29"
  }
  sit-ccm-app-subnets = [
    local.sit-ccm-vnet-scheme.address_prefix-subnet-app-01,
    local.sit-ccm-vnet-scheme.address_prefix-subnet-app-02,
  ]
  sit-ccm-web-subnets = [
    local.sit-ccm-vnet-scheme.address_prefix-subnet-web-01,
    local.sit-ccm-vnet-scheme.address_prefix-subnet-web-02,
  ]
  sit-ccm-data-subnets = [
    local.sit-ccm-vnet-scheme.address_prefix-subnet-data-01,
    local.sit-ccm-vnet-scheme.address_prefix-subnet-data-02,
  ]
  nft-ccm-vnet-scheme = {
    address_space_vnet        = "10.91.64.0/18"
    address_prefix-subnet-ops = "10.91.64.0/24"

    #   Second app tier "address_prefix-subnet-app-ext-01" is created due to app tier is run out of ip address
    address_prefix-subnet-web-01       = "10.91.65.0/27"
    address_prefix-subnet-app-01       = "10.91.65.32/27"
    address_prefix-subnet-app-audit-01 = "10.91.65.96/27"
    address_prefix-subnet-data-01      = "10.91.65.64/27"
    address_prefix-subnet-app-ext-01   = "10.91.67.0/24"

    # address_prefix-subnet-web-02  = "10.91.66.0/27"
    # address_prefix-subnet-app-02  = "10.91.66.32/27"
    # address_prefix-subnet-data-02 = "10.91.66.64/27"

    address_prefix-subnet-rc-common = "10.91.127.224/28"
    address_prefix-subnet-sd-common = "10.91.127.192/28"


    address_prefix-subnet-apim-appgw = "10.91.127.248/29"
    address_prefix-subnet-apim-app   = "10.91.127.240/29"

    address_space_vnet_dmz    = "10.91.192.0/19"
    address_prefix-subnet-waf = "10.91.192.0/27"

    address_prefix-subnet-csfl      = "10.91.127.160/28"
    address_prefix-subnet-notifyatt = "10.91.127.112/28"
  }
  nft-ccm-app-subnets = [
    local.nft-ccm-vnet-scheme.address_prefix-subnet-app-01,
  ]
  nft-ccm-web-subnets = [
    local.nft-ccm-vnet-scheme.address_prefix-subnet-web-01,
  ]
  nft-ccm-data-subnets = [
    local.nft-ccm-vnet-scheme.address_prefix-subnet-data-01,
  ]
  dev-rota-vnet-scheme = {
    address_space_vnet        = "10.89.64.0/18"
    address_prefix-subnet-ops = "10.89.64.0/24"

    address_prefix-subnet-web-01  = "10.89.70.0/27"
    address_prefix-subnet-app-01  = "10.89.70.32/27"
    address_prefix-subnet-data-01 = "10.89.70.64/27"

    address_space_vnet_dmz         = "10.89.192.0/19"
    address_prefix-subnet-waf      = "10.89.192.0/27"
    address_prefix-subnet-dmz-kali = "10.89.192.32/29"
  }
  sit-rota-vnet-scheme = {
    address_space_vnet        = "10.90.64.0/18"
    address_prefix-subnet-ops = "10.90.64.0/24"

    address_prefix-subnet-web-01  = "10.90.70.0/27"
    address_prefix-subnet-app-01  = "10.90.70.32/27"
    address_prefix-subnet-data-01 = "10.90.70.64/27"

    address_space_vnet_dmz         = "10.90.192.0/19"
    address_prefix-subnet-waf      = "10.90.192.0/27"
    address_prefix-subnet-dmz-kali = "10.90.192.32/29"
  }
  nft-rota-vnet-scheme = {
    address_space_vnet        = "10.91.64.0/18"
    address_prefix-subnet-ops = "10.91.64.0/24"

    address_prefix-subnet-web-01  = "10.91.70.0/27"
    address_prefix-subnet-app-01  = "10.91.70.64/26"
    address_prefix-subnet-data-01 = "10.91.70.128/27"

    address_space_vnet_dmz    = "10.91.192.0/19"
    address_prefix-subnet-waf = "10.91.192.0/27"
  }
  nle-atl-vnet-scheme = {
    address_space_vnet        = "10.254.0.0/20"
    address_prefix-subnet-ops = "10.254.10.0/24"

    address_prefix-subnet-app-01  = "10.254.2.0/24"
    address_prefix-subnet-data-01 = "10.254.3.0/24"

    address_space_dmz_vnet = "10.254.20.0/24"

    address_space_subnet_dmz  = "10.254.1.0/24"
    address_prefix-subnet-waf = "10.254.20.0/29"
  }
  idam-dev-vnet-scheme = {
    address_space_vnet                = "10.10.0.0/16"
    address_prefix_subnet_dmz         = "10.89.192.0/27"
    address_prefix_subnet_web_idm1_01 = "10.10.2.0/24"
    address_prefix_subnet_web_idm1_02 = "10.10.3.0/24"
    address_prefix_subnet_web_idm1_03 = "10.10.255.0/24"
    address_prefix_subnet_app_idm1_01 = "10.10.4.0/24"
    address_prefix_subnet_app_idm1_02 = "10.10.5.0/24"
    address_prefix_subnet_dat_idm1_01 = "10.10.6.0/24"
    address_prefix_subnet_dat_idm1_02 = "10.10.7.0/24"
    address_prefix_subnet_ops_01      = "10.10.1.0/24"
    address_prefix_subnet_ops_02      = "10.10.0.0/29"
    cpstub_proxy_static_ip            = "10.10.255.5"
    rotastub_proxy_static_ip          = "10.10.255.8"
  }
  idam-sit-vnet-scheme = {
    address_space_vnet                = "10.15.0.0/16"
    address_prefix_subnet_dmz         = "10.90.192.0/19"
    address_prefix_subnet_web_idm1_01 = "10.15.2.0/24"
    address_prefix_subnet_web_idm1_02 = "10.15.3.0/24"
    address_prefix_subnet_web_idm1_03 = "10.15.255.0/24"
    address_prefix_subnet_app_idm1_01 = "10.15.4.0/24"
    address_prefix_subnet_app_idm1_02 = "10.15.5.0/24"
    address_prefix_subnet_dat_idm1_01 = "10.15.6.0/24"
    address_prefix_subnet_dat_idm1_02 = "10.15.7.0/24"
    address_prefix_subnet_ops_01      = "10.15.1.0/24"
    address_prefix_subnet_ops_02      = "10.15.0.0/29"
    cpstub_proxy_static_ip            = "10.15.255.5"
    rotastub_proxy_static_ip          = "10.15.255.8"
  }
  idam-nft-vnet-scheme = {
    address_space_vnet                = "10.20.0.0/16"
    address_prefix_subnet_dmz         = "10.91.192.0/27"
    address_prefix_subnet_web_idm1_01 = "10.20.2.0/24"
    address_prefix_subnet_web_idm1_02 = "10.20.3.0/24"
    address_prefix_subnet_web_idm1_03 = "10.20.255.0/24"
    address_prefix_subnet_app_idm1_01 = "10.20.4.0/24"
    address_prefix_subnet_app_idm1_02 = "10.20.5.0/24"
    address_prefix_subnet_dat_idm1_01 = "10.20.6.0/24"
    address_prefix_subnet_dat_idm1_02 = "10.20.7.0/24"
    address_prefix_subnet_ops_01      = "10.20.1.0/24"
    address_prefix_subnet_ops_02      = "10.20.0.0/29"
    cpstub_proxy_static_ip            = "10.20.255.5"
    rotastub_proxy_static_ip          = "10.20.255.8"
  }
}