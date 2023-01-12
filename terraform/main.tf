###################################
#            General
###################################
terraform {
  required_providers {
    nutanix = {
      source = "nutanix/nutanix"
      version = ">=1.2.0"
    }
  }
}

# provider and authentication
provider "nutanix" {
  username = var.pc_user
  password = var.pc_secret
  endpoint = var.pc_endpoint
  port     = var.pc_port
  insecure = true
}

###################################
#            Data sources
###################################
# get PE cluster uuid and assigned to local variable
data "nutanix_clusters" "clusters" {}
locals {
  cluster = data.nutanix_clusters.clusters.entities[0].metadata.uuid
}

# get category key
data "nutanix_category_key" "key" {
    name = var.pc_category_name
}

# ###################################
# #            Categories
# ###################################
# create categories values
resource "nutanix_category_value" "value" {
    for_each = toset(var.pc_category_values)
    name = data.nutanix_category_key.key.id
    value = each.key
}

###################################
#            Address group
###################################
# address_group outbound1
resource "nutanix_address_group" "outbound_1" {
  name = "PROD-SUP"

  ip_address_block_list {
    ip = "10.1.0.0"
    prefix_length = 24
  }

    ip_address_block_list {
    ip = "10.2.0.0"
    prefix_length = 24
  }
}

# address_group inbound1
resource "nutanix_address_group" "inbound_1" {
  name = "ECN"
  ip_address_block_list {
    ip = "10.0.0.49"
    prefix_length = 32
  }
}

# address_group inbound2
resource "nutanix_address_group" "inbound_2" {
  name = "PAVirtuel"
  ip_address_block_list {
    ip = "10.0.0.50"
    prefix_length = 32
  }
}

# address_group inbound3
resource "nutanix_address_group" "inbound_3" {
  name = "PU"
  ip_address_block_list {
    ip = "10.1.0.201"
    prefix_length = 32
  }

   ip_address_block_list {
    ip = "10.1.0.202"
    prefix_length = 32
  }
}


###################################
#           Security Rule  
###################################
resource "nutanix_network_security_rule" "RAD" {
  name            = var.pc_security_rule_name              
  description     = var.pc_security_rule_description
  app_rule_action = var.pc_security_rule_mode
 
  app_rule_target_group_peer_specification_type = "FILTER"
  app_rule_target_group_default_internal_policy = "ALLOW_ALL"
  app_rule_target_group_filter_type = "CATEGORIES_MATCH_ALL"
  app_rule_target_group_filter_kind_list = ["vm"]

  app_rule_target_group_filter_params {
    name = "AppType"
    values = [
      var.pc_security_rule_apptype
    ]
  }

    app_rule_inbound_allow_list {
    peer_specification_type = "IP_SUBNET"
    protocol                = "TCP"
    tcp_port_range_list {
        start_port = 5986
        end_port = 5986
    }
    address_group_inclusion_list {
        kind = "address_group"
        uuid = nutanix_address_group.inbound_1.id
      }
    }

  app_rule_inbound_allow_list {
    peer_specification_type = "IP_SUBNET"
    protocol                = "TCP"
    tcp_port_range_list {
        start_port = 3389
        end_port = 3389
    }
    address_group_inclusion_list {
        kind = "address_group"
        uuid = nutanix_address_group.inbound_2.id
      }
    }

   app_rule_inbound_allow_list {
    peer_specification_type = "IP_SUBNET"
    protocol                = "TCP"
    tcp_port_range_list {
        start_port = 3389
        end_port = 3389
    }
    address_group_inclusion_list {
        kind = "address_group"
        uuid = nutanix_address_group.inbound_3.id
      }
    }

  app_rule_outbound_allow_list {
    peer_specification_type = "IP_SUBNET"
    protocol                = "TCP"
    tcp_port_range_list {
        start_port = 22
        end_port = 22
    }
    tcp_port_range_list {
        start_port = 3389
        end_port = 3389
    }
    tcp_port_range_list {
        start_port = 5986
        end_port = 5986
    }
    tcp_port_range_list {
        start_port = 135
        end_port = 135
    }
    tcp_port_range_list {
        start_port = 443
        end_port = 443
    }
    tcp_port_range_list {
        start_port = 139
        end_port = 139
    }
    tcp_port_range_list {
        start_port = 445
        end_port = 445
    }
     tcp_port_range_list {
        start_port = 49152
        end_port = 65535
    }
    address_group_inclusion_list {
        kind = "address_group"
        uuid = nutanix_address_group.outbound_1.id
      }
    }

    depends_on = [nutanix_category_value.value]
}