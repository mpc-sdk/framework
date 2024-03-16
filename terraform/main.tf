provider "aws" {
  region  = var.region
  profile = "mfa-devops"
}

data "external" "env" {
  program = ["${path.module}/env.sh"]
}

provider "cloudflare" {
  api_token = data.external.env.result.cloudflare_api
}

module "relay-server" {
  source = "./relay-server"
  # region         = var.region
  # default_vpc_id = var.default_vpc_id
  # zone_id        = var.zone_id
  # domain         = var.domain
}
