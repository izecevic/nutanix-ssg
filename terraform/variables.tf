# region authentication
variable "pc_user" {
  type = string
}

variable "pc_secret" {
    type = string
}

variable "pc_endpoint" {
    type = string
}

variable "pc_port" {
    type = string
}
# endregion

# region categories
variable "pc_category_name" {
      type = string
}

variable "pc_category_values" {
  type = list(string)
}
# endregion

# region address_group
# endregion

# region security_rule
variable "pc_security_rule_name" {
  type = string
}

variable "pc_security_rule_description" {
  type = string
}

variable "pc_security_rule_mode" {
  type = string
}

variable "pc_security_rule_apptype" {
  type = string
}
# endregion