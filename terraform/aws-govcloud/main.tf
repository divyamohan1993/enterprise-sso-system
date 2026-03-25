# ──────────────────────────────────────────────────────────────────────────────
# MILNET SSO — AWS GovCloud Infrastructure
# ──────────────────────────────────────────────────────────────────────────────
# All resources are constrained to GovCloud regions:
#   us-gov-west-1  — primary (Oregon)
#   us-gov-east-1  — secondary (Virginia)
#
# Compliance: FedRAMP High, IL4/IL5, ITAR, FIPS 140-2/140-3
# CloudHSM: FIPS 140-3 Level 3 certified
# All API calls use FIPS endpoints (*.us-gov-west-1.amazonaws.com)
# ──────────────────────────────────────────────────────────────────────────────

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    bucket         = "milnet-tf-state-govcloud"
    key            = "aws-govcloud/terraform.tfstate"
    region         = "us-gov-west-1"
    encrypt        = true
    use_fips_endpoint = true
    # kms_key_id set via environment variable TF_VAR_state_kms_key
  }
}

provider "aws" {
  region = var.primary_region

  # FIPS endpoints for all services — required for FedRAMP High / IL5
  use_fips_endpoint = true

  default_tags {
    tags = var.tags
  }
}

# Secondary region provider for cross-region replication
provider "aws" {
  alias  = "secondary"
  region = var.secondary_region

  use_fips_endpoint = true

  default_tags {
    tags = var.tags
  }
}

# ── Modules ──

module "vpc" {
  source = "./modules/vpc"

  primary_region   = var.primary_region
  secondary_region = var.secondary_region
  environment      = var.environment
  enable_air_gap   = var.enable_air_gap
}

module "kms" {
  source = "./modules/kms"

  primary_region   = var.primary_region
  secondary_region = var.secondary_region
  environment      = var.environment
  service_names    = var.service_names

  providers = {
    aws           = aws
    aws.secondary = aws.secondary
  }
}

module "cloudhsm" {
  source = "./modules/cloudhsm"

  primary_region = var.primary_region
  environment    = var.environment
  subnet_ids     = module.vpc.private_subnet_ids

  depends_on = [module.vpc]
}

module "rds" {
  source = "./modules/rds"

  primary_region   = var.primary_region
  secondary_region = var.secondary_region
  environment      = var.environment
  vpc_id           = module.vpc.vpc_id
  subnet_ids       = module.vpc.private_subnet_ids
  kms_key_arn      = module.kms.rds_kms_key_arn

  depends_on = [module.vpc, module.kms]
}

module "ec2" {
  source = "./modules/ec2"

  primary_region = var.primary_region
  environment    = var.environment
  subnet_ids     = module.vpc.private_subnet_ids
  service_names  = var.service_names
  kms_key_arn    = module.kms.ebs_kms_key_arn

  depends_on = [module.vpc, module.kms, module.iam]
}

module "iam" {
  source = "./modules/iam"

  environment   = var.environment
  service_names = var.service_names
  kms_key_arns  = module.kms.all_key_arns

  depends_on = [module.kms]
}

module "secretsmanager" {
  source = "./modules/secretsmanager"

  primary_region = var.primary_region
  environment    = var.environment
  service_names  = var.service_names
  kms_key_arn    = module.kms.secrets_kms_key_arn

  depends_on = [module.kms]
}
