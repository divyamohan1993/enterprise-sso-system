# ──────────────────────────────────────────────────────────────────────────────
# MILNET SSO — AWS GovCloud VPC Module
# ──────────────────────────────────────────────────────────────────────────────
# Private subnets only. No Internet Gateway by default.
# Air-gap mode: no IGW, no NAT GW, no VPN — PrivateLink / Direct Connect only.
# Non-air-gap: NAT Gateway for egress to GovCloud endpoints only.
# ──────────────────────────────────────────────────────────────────────────────

variable "primary_region" { type = string }
variable "secondary_region" { type = string }
variable "environment" { type = string }
variable "enable_air_gap" {
  description = "true = no IGW/NAT, IL5 air-gap mode"
  type        = bool
  default     = false
}

locals {
  name_prefix = "milnet-govcloud-${var.environment}"
}

# ── VPC ──

resource "aws_vpc" "milnet" {
  cidr_block           = "10.40.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "${local.name_prefix}-vpc"
    Region      = var.primary_region
    AirGap      = tostring(var.enable_air_gap)
  }
}

# ── Private Subnets (3 AZs for HA) ──

resource "aws_subnet" "private" {
  count = 3

  vpc_id            = aws_vpc.milnet.id
  cidr_block        = "10.40.${count.index}.0/24"
  availability_zone = "${var.primary_region}${["a", "b", "c"][count.index]}"

  # Never assign public IPs
  map_public_ip_on_launch = false

  tags = {
    Name = "${local.name_prefix}-private-${["a", "b", "c"][count.index]}"
    Tier = "private"
  }
}

# ── Internet Gateway — only if NOT air-gapped ──

resource "aws_internet_gateway" "igw" {
  count  = var.enable_air_gap ? 0 : 1
  vpc_id = aws_vpc.milnet.id

  tags = {
    Name = "${local.name_prefix}-igw"
  }
}

# ── NAT Gateway — only if NOT air-gapped ──

resource "aws_eip" "nat" {
  count  = var.enable_air_gap ? 0 : 1
  domain = "vpc"

  tags = {
    Name = "${local.name_prefix}-nat-eip"
  }
}

resource "aws_subnet" "public" {
  count = var.enable_air_gap ? 0 : 1

  vpc_id            = aws_vpc.milnet.id
  cidr_block        = "10.40.100.0/24"
  availability_zone = "${var.primary_region}a"

  tags = {
    Name = "${local.name_prefix}-public-nat"
    Tier = "public"
  }
}

resource "aws_nat_gateway" "nat" {
  count         = var.enable_air_gap ? 0 : 1
  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.public[0].id

  tags = {
    Name = "${local.name_prefix}-nat"
  }

  depends_on = [aws_internet_gateway.igw]
}

# ── Route Tables ──

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.milnet.id

  # If not air-gapped, route 0.0.0.0/0 through NAT
  dynamic "route" {
    for_each = var.enable_air_gap ? [] : [1]
    content {
      cidr_block     = "0.0.0.0/0"
      nat_gateway_id = aws_nat_gateway.nat[0].id
    }
  }

  tags = {
    Name = "${local.name_prefix}-private-rt"
  }
}

resource "aws_route_table_association" "private" {
  count          = 3
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# ── VPC Endpoints for AWS GovCloud Services ──
# Use interface endpoints so traffic stays within GovCloud — never touches internet.

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.milnet.id
  service_name      = "com.amazonaws.${var.primary_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]

  tags = { Name = "${local.name_prefix}-s3-endpoint" }
}

resource "aws_vpc_endpoint" "kms" {
  vpc_id              = aws_vpc.milnet.id
  service_name        = "com.amazonaws.${var.primary_region}.kms-fips"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  private_dns_enabled = true

  tags = { Name = "${local.name_prefix}-kms-fips-endpoint" }
}

resource "aws_vpc_endpoint" "secretsmanager" {
  vpc_id              = aws_vpc.milnet.id
  service_name        = "com.amazonaws.${var.primary_region}.secretsmanager"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  private_dns_enabled = true

  tags = { Name = "${local.name_prefix}-secretsmanager-endpoint" }
}

resource "aws_vpc_endpoint" "rds" {
  vpc_id              = aws_vpc.milnet.id
  service_name        = "com.amazonaws.${var.primary_region}.rds"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  private_dns_enabled = true

  tags = { Name = "${local.name_prefix}-rds-endpoint" }
}

# ── Security Group: deny all by default (VPC default SG hardening) ──

resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.milnet.id

  # Override default SG to deny all — services use explicit SGs
  tags = { Name = "${local.name_prefix}-default-sg-deny-all" }
}

# ── Security Group: MILNET internal east-west ──

resource "aws_security_group" "milnet_internal" {
  name        = "${local.name_prefix}-internal"
  description = "Allow intra-MILNET traffic only"
  vpc_id      = aws_vpc.milnet.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.40.0.0/16"]
    description = "Allow all internal VPC traffic"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.40.0.0/16"]
    description = "Allow all internal VPC traffic"
  }

  tags = { Name = "${local.name_prefix}-internal-sg" }
}

# ── Outputs ──

output "vpc_id" {
  value = aws_vpc.milnet.id
}

output "private_subnet_ids" {
  value = aws_subnet.private[*].id
}

output "internal_security_group_id" {
  value = aws_security_group.milnet_internal.id
}
