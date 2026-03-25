# ──────────────────────────────────────────────────────────────────────────────
# MILNET SSO — AWS GovCloud EC2 Module
# ──────────────────────────────────────────────────────────────────────────────
# EC2 instances for MILNET services in GovCloud.
# No public IPs. IMDSv2 required. EBS encrypted with CMEK.
# Nitro-based instances for enhanced security and performance.
# ──────────────────────────────────────────────────────────────────────────────

variable "primary_region" { type = string }
variable "environment" { type = string }
variable "subnet_ids" { type = list(string) }
variable "service_names" { type = list(string) }
variable "kms_key_arn" { type = string }

locals {
  name_prefix  = "milnet-govcloud-${var.environment}"
  is_prod      = var.environment == "production"
  instance_type = local.is_prod ? "m6i.large" : "t3.small"

  # Spread services across subnets (round-robin)
  service_subnets = {
    for idx, svc in var.service_names :
    svc => var.subnet_ids[idx % length(var.subnet_ids)]
  }
}

# ── AMI: Amazon Linux 2023 (FIPS-enabled) ──
# AL2023 supports FIPS mode via fips=1 kernel parameter.

data "aws_ami" "al2023_fips" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "state"
    values = ["available"]
  }
}

# ── Launch Template ──

resource "aws_launch_template" "milnet_service" {
  name_prefix = "${local.name_prefix}-svc-tmpl-"
  description = "MILNET GovCloud service launch template"

  image_id      = data.aws_ami.al2023_fips.id
  instance_type = local.instance_type

  # IMDSv2 required — prevents SSRF-based credential theft
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"  # IMDSv2 only
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  # EBS encryption with CMEK
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = 50
      volume_type           = "gp3"
      encrypted             = true
      kms_key_id            = var.kms_key_arn
      delete_on_termination = true
    }
  }

  # No public IP
  network_interfaces {
    associate_public_ip_address = false
    delete_on_termination       = true
  }

  # Enable FIPS kernel mode via user data
  user_data = base64encode(<<-EOF
    #!/bin/bash
    # Enable FIPS 140-3 mode
    fips-mode-setup --enable
    # Disable unnecessary services
    systemctl disable --now avahi-daemon 2>/dev/null || true
    systemctl disable --now bluetooth 2>/dev/null || true
    # Harden SSH
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl restart sshd
  EOF
  )

  tag_specifications {
    resource_type = "instance"
    tags = {
      ManagedBy  = "terraform"
      FipsMode   = "true"
      PublicIP   = "false"
    }
  }

  tag_specifications {
    resource_type = "volume"
    tags = {
      Encrypted  = "cmek"
      ManagedBy  = "terraform"
    }
  }
}

# ── Per-Service EC2 Instances ──

resource "aws_instance" "milnet_services" {
  for_each = toset(var.service_names)

  launch_template {
    id      = aws_launch_template.milnet_service.id
    version = "$Latest"
  }

  subnet_id = local.service_subnets[each.value]

  # Spot instances for dev, on-demand for production
  instance_market_options {
    market_type = local.is_prod ? null : "spot"

    dynamic "spot_options" {
      for_each = local.is_prod ? [] : [1]
      content {
        spot_instance_type             = "persistent"
        instance_interruption_behavior = "stop"
      }
    }
  }

  tags = {
    Name        = "${local.name_prefix}-${each.value}"
    Service     = each.value
    Environment = var.environment
  }
}

# ── Outputs ──

output "instance_ids" {
  description = "Map of service name to EC2 instance ID"
  value       = { for svc, inst in aws_instance.milnet_services : svc => inst.id }
}

output "private_ips" {
  description = "Map of service name to private IP"
  value       = { for svc, inst in aws_instance.milnet_services : svc => inst.private_ip }
  sensitive   = true
}
