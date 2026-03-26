###############################################################################
# cloud-armor.tf — Enterprise SSO Gateway Cloud Armor Security Policy
###############################################################################
# Protects the gateway load balancer with:
#   - Adaptive DDoS protection
#   - Geo-blocking (default: India only)
#   - Rate limiting (100 req/min per IP)
#   - WAF rules (SQLi, XSS, protocol attacks)
#   - Bot management via reCAPTCHA Enterprise (optional)
#   - Request body size restriction (4KB max)
###############################################################################

###############################################################################
# Security Policy
###############################################################################

resource "google_compute_security_policy" "gateway_armor" {
  name        = "${local.name_prefix}-gateway-armor"
  project     = var.project_id
  description = "Cloud Armor policy for SSO gateway — military-grade edge protection"

  type = "CLOUD_ARMOR"

  # --------------------------------------------------------------------------
  # Adaptive Protection — ML-based DDoS detection
  # --------------------------------------------------------------------------
  adaptive_protection_config {
    layer_7_ddos_defense_config {
      enable          = true
      rule_visibility = "STANDARD"
    }
  }

  # --------------------------------------------------------------------------
  # Advanced Options
  # --------------------------------------------------------------------------
  advanced_options_config {
    json_parsing = "STANDARD"
    log_level    = "VERBOSE"
  }

  # --------------------------------------------------------------------------
  # Rule 0: reCAPTCHA Enterprise bot management (optional)
  # --------------------------------------------------------------------------
  dynamic "rule" {
    for_each = var.recaptcha_site_key != "" ? [1] : []
    content {
      action   = "rate_based_ban"
      priority = 100
      match {
        expr {
          expression = "!token.recaptcha_session.valid && has(request.headers['x-recaptcha-token'])"
        }
      }
      description = "Block requests failing reCAPTCHA session validation"
      rate_limit_options {
        conform_action = "allow"
        exceed_action  = "deny(403)"
        enforce_on_key = "IP"
        rate_limit_threshold {
          count        = 10
          interval_sec = 60
        }
        ban_duration_sec = 300
      }
    }
  }

  # --------------------------------------------------------------------------
  # Rule 1: Geo-blocking — only allow configured countries
  # --------------------------------------------------------------------------
  rule {
    action   = "deny(403)"
    priority = 200
    match {
      expr {
        expression = "!('[${join("','", var.allowed_countries)}]'.contains(origin.region_code))"
      }
    }
    description = "Geo-block: deny traffic from outside allowed countries (default: IN only)"
  }

  # --------------------------------------------------------------------------
  # Rule 2: Rate limiting — 100 requests/min per IP
  # --------------------------------------------------------------------------
  rule {
    action   = "throttle"
    priority = 300
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "Rate limit: ${var.cloud_armor_rate_limit} req/min per IP"
    rate_limit_options {
      conform_action = "allow"
      exceed_action  = "deny(429)"
      enforce_on_key = "IP"
      rate_limit_threshold {
        count        = var.cloud_armor_rate_limit
        interval_sec = 60
      }
    }
  }

  # --------------------------------------------------------------------------
  # Rule 3: Block oversized request bodies (> 4KB)
  # Auth requests are small; large bodies indicate abuse.
  # --------------------------------------------------------------------------
  rule {
    action   = "deny(413)"
    priority = 400
    match {
      expr {
        expression = "int(request.headers['content-length']) > ${var.max_request_body_bytes}"
      }
    }
    description = "Block requests with body > ${var.max_request_body_bytes} bytes"
  }

  # --------------------------------------------------------------------------
  # Rule 4: WAF — SQL Injection protection
  # --------------------------------------------------------------------------
  rule {
    action   = "deny(403)"
    priority = 1000
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('sqli-v33-stable', {'sensitivity': 1})"
      }
    }
    description = "WAF: Block SQL injection attacks (sensitivity level 1)"
  }

  # --------------------------------------------------------------------------
  # Rule 5: WAF — Cross-Site Scripting (XSS) protection
  # --------------------------------------------------------------------------
  rule {
    action   = "deny(403)"
    priority = 1100
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('xss-v33-stable', {'sensitivity': 1})"
      }
    }
    description = "WAF: Block XSS attacks (sensitivity level 1)"
  }

  # --------------------------------------------------------------------------
  # Rule 6: WAF — Remote Code Execution (RCE) protection
  # --------------------------------------------------------------------------
  rule {
    action   = "deny(403)"
    priority = 1200
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('rce-v33-stable', {'sensitivity': 1})"
      }
    }
    description = "WAF: Block remote code execution attacks"
  }

  # --------------------------------------------------------------------------
  # Rule 7: WAF — Local File Inclusion (LFI) protection
  # --------------------------------------------------------------------------
  rule {
    action   = "deny(403)"
    priority = 1300
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('lfi-v33-stable', {'sensitivity': 1})"
      }
    }
    description = "WAF: Block local file inclusion attacks"
  }

  # --------------------------------------------------------------------------
  # Rule 8: WAF — Remote File Inclusion (RFI) protection
  # --------------------------------------------------------------------------
  rule {
    action   = "deny(403)"
    priority = 1400
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('rfi-v33-stable', {'sensitivity': 1})"
      }
    }
    description = "WAF: Block remote file inclusion attacks"
  }

  # --------------------------------------------------------------------------
  # Rule 9: WAF — Protocol attack protection (HTTP splitting, smuggling)
  # --------------------------------------------------------------------------
  rule {
    action   = "deny(403)"
    priority = 1500
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('protocolattack-v33-stable', {'sensitivity': 1})"
      }
    }
    description = "WAF: Block protocol attacks (HTTP splitting/smuggling)"
  }

  # --------------------------------------------------------------------------
  # Rule 10: WAF — Scanner/probe detection
  # --------------------------------------------------------------------------
  rule {
    action   = "deny(403)"
    priority = 1600
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('scannerdetection-v33-stable', {'sensitivity': 1})"
      }
    }
    description = "WAF: Block automated scanners and probes"
  }

  # --------------------------------------------------------------------------
  # Rule 11: WAF — Session fixation protection
  # --------------------------------------------------------------------------
  rule {
    action   = "deny(403)"
    priority = 1700
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('sessionfixation-v33-stable', {'sensitivity': 1})"
      }
    }
    description = "WAF: Block session fixation attacks"
  }

  # --------------------------------------------------------------------------
  # Rule 12: Block known bad user agents
  # --------------------------------------------------------------------------
  rule {
    action   = "deny(403)"
    priority = 1800
    match {
      expr {
        expression = "request.headers['user-agent'].matches('(?i)(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|wpscan|hydra)')"
      }
    }
    description = "Block requests from known offensive security tools"
  }

  # --------------------------------------------------------------------------
  # Rule 13: Enforce valid HTTP methods for auth endpoints
  # --------------------------------------------------------------------------
  rule {
    action   = "deny(405)"
    priority = 1900
    match {
      expr {
        expression = "!request.method.matches('^(GET|POST|OPTIONS)$')"
      }
    }
    description = "Only allow GET, POST, OPTIONS methods for auth endpoints"
  }

  # --------------------------------------------------------------------------
  # Default rule: Allow remaining traffic (that passed all checks)
  # --------------------------------------------------------------------------
  rule {
    action   = "allow"
    priority = 2147483647
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "Default allow — traffic that survived all security checks"
  }
}

###############################################################################
# reCAPTCHA Enterprise Site Key (conditional)
###############################################################################

resource "google_recaptcha_enterprise_key" "gateway_recaptcha" {
  count        = var.recaptcha_site_key != "" ? 0 : (var.enable_recaptcha ? 1 : 0)
  display_name = "${local.name_prefix}-gateway-recaptcha"
  project      = var.project_id

  web_settings {
    integration_type  = "INVISIBLE"
    allowed_domains   = var.gateway_domains
    allow_amp_traffic = false
  }

  labels = var.labels
}

###############################################################################
# Backend Security Policy attachment
###############################################################################
# This links the Cloud Armor policy to the gateway backend service.
# The backend service itself is defined in the compute/LB configuration;
# this output provides the policy self_link for that attachment.

###############################################################################
# Additional variables for Cloud Armor
###############################################################################

variable "enable_recaptcha" {
  description = "Enable reCAPTCHA Enterprise key creation for bot management"
  type        = bool
  default     = false
}

variable "gateway_domains" {
  description = "Allowed domains for reCAPTCHA Enterprise"
  type        = list(string)
  default     = ["sso.mil.in"]
}

###############################################################################
# Outputs
###############################################################################

output "cloud_armor_policy_id" {
  description = "Cloud Armor security policy ID for gateway backend service attachment"
  value       = google_compute_security_policy.gateway_armor.id
}

output "cloud_armor_policy_self_link" {
  description = "Cloud Armor security policy self_link"
  value       = google_compute_security_policy.gateway_armor.self_link
}

output "vpc_id" {
  description = "VPC network ID"
  value       = google_compute_network.sso_vpc.id
}

output "public_subnet_id" {
  description = "Public subnet ID (gateway)"
  value       = google_compute_subnetwork.public.id
}

output "private_subnet_id" {
  description = "Private subnet ID (services)"
  value       = google_compute_subnetwork.private.id
}

output "private_secondary_subnet_id" {
  description = "Private secondary subnet ID (cross-region nodes)"
  value       = google_compute_subnetwork.private_secondary.id
}
