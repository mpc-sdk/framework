provider "aws" {
  region  = var.region
  profile = "mfa-devops"
}

module "relay-server" {
  source         = "./relay-server"
  # region         = var.region
  # default_vpc_id = var.default_vpc_id
  # zone_id        = var.zone_id
  # domain         = var.domain
}
