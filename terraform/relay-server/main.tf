terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
  }
}

resource "aws_security_group" "relay_server_security_group" {
  name        = "relay-server-security-group"
  description = "Relay server security group"
  vpc_id      = var.default_vpc_id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "relay-server-group"
  }
}

resource "aws_instance" "relay_server" {
  ami                    = "ami-004c37117ce961527"
  instance_type          = "t3.medium"
  key_name               = "ec2-ssh"
  user_data              = file("${path.module}/../scripts/relay-server.sh")
  vpc_security_group_ids = [aws_security_group.relay_server_security_group.id]

  tags = {
    Name = "relay-server"
  }
}

resource "cloudflare_record" "relay_server_dns_record" {
  zone_id = var.zone_id
  name    = "relay"
  type    = "A"
  ttl     = 1
  value   = aws_instance.relay_server.public_ip
  proxied = true
}
