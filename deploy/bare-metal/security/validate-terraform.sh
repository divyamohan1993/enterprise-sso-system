#!/usr/bin/env bash
# ==============================================================================
# MILNET SSO — Terraform Compliance Validation Script
# ==============================================================================
# Validates Terraform configurations without running `terraform init`
# (no cloud credentials required in CI).
#
# Checks performed:
#   1. HCL syntax: all .tf files have balanced braces/brackets/parens
#   2. India region compliance: gcp-india only uses asia-south1 / asia-south2
#   3. GovCloud compliance: aws-govcloud only uses us-gov-* regions
#   4. No public IPs in GCP India config
#   5. No non-GovCloud regions in AWS config
#   6. HSM protection enforced in GCP India KMS
#   7. FIPS endpoints enforced in AWS GovCloud
#   8. No hardcoded secrets or credentials
#
# Usage:
#   validate-terraform.sh [--terraform-dir /path/to/terraform] [--verbose] [--strict]
#
# Exit codes:
#   0 — All checks passed
#   1 — One or more checks failed
# ==============================================================================

set -euo pipefail

readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Defaults ──────────────────────────────────────────────────────────────────

# Default: terraform dir is 4 levels up from this script
# (deploy/bare-metal/security/ -> repo root -> terraform/)
TERRAFORM_DIR="${TERRAFORM_DIR:-${SCRIPT_DIR}/../../../terraform}"
VERBOSE=false
STRICT=false

# ── Counters ──────────────────────────────────────────────────────────────────

PASS=0
FAIL=0
WARN=0

# ── Logging ───────────────────────────────────────────────────────────────────

log_pass()    { echo "  [PASS] $*"; PASS=$((PASS + 1)); }
log_fail()    { echo "  [FAIL] $*" >&2; FAIL=$((FAIL + 1)); }
log_warn()    { echo "  [WARN] $*" >&2; WARN=$((WARN + 1)); }
log_info()    { echo "[VALIDATE] $*"; }
log_verbose() { [[ "$VERBOSE" == "true" ]] && echo "  [DBG]  $*" || true; }
log_section() { echo ""; echo "=== $* ==="; }

# ── Argument Parsing ──────────────────────────────────────────────────────────

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --terraform-dir=*) TERRAFORM_DIR="${1#--terraform-dir=}"; shift ;;
            --terraform-dir)   TERRAFORM_DIR="$2"; shift 2 ;;
            --verbose|-v)      VERBOSE=true; shift ;;
            --strict)          STRICT=true; shift ;;
            -h|--help)         usage; exit 0 ;;
            *)                 echo "Unknown argument: $1" >&2; exit 1 ;;
        esac
    done
}

usage() {
    cat <<EOF
Usage: $SCRIPT_NAME [options]

Options:
  --terraform-dir=DIR   Path to terraform directory (default: auto-detected)
  --verbose, -v         Print extra diagnostic output
  --strict              Treat warnings as failures (non-zero exit on WARN)
  -h, --help            Show this help

Environment:
  TERRAFORM_DIR         Override terraform directory path
EOF
}

# ── Check 1: HCL Syntax (Balanced Braces) ────────────────────────────────────
# Without terraform binary, we validate structural integrity by counting
# delimiters. This catches truncated files and unclosed blocks.

check_hcl_syntax() {
    log_section "Check 1: HCL syntax (balanced braces/brackets/parens)"

    local tf_files=()
    while IFS= read -r -d $'\0' f; do
        tf_files+=("$f")
    done < <(find "$TERRAFORM_DIR" -name "*.tf" -print0 2>/dev/null)

    if [[ ${#tf_files[@]} -eq 0 ]]; then
        log_fail "No .tf files found under $TERRAFORM_DIR"
        return
    fi

    log_info "Found ${#tf_files[@]} .tf files"

    local syntax_errors=0

    for tf_file in "${tf_files[@]}"; do
        local rel_path="${tf_file#"${TERRAFORM_DIR}/"}"

        # Count opening and closing delimiters.
        # Strip comments and strings to avoid false positives.
        local content
        content="$(
            # Remove single-line comments (# and //)
            # Remove heredoc content is complex — skip for now
            grep -v '^\s*#' "$tf_file" | grep -v '^\s*//'
        )"

        local open_braces close_braces
        local open_brackets close_brackets
        local open_parens close_parens

        open_braces=$(echo "$content"   | tr -cd '{' | wc -c)
        close_braces=$(echo "$content"  | tr -cd '}' | wc -c)
        open_brackets=$(echo "$content" | tr -cd '[' | wc -c)
        close_brackets=$(echo "$content"| tr -cd ']' | wc -c)
        open_parens=$(echo "$content"   | tr -cd '(' | wc -c)
        close_parens=$(echo "$content"  | tr -cd ')' | wc -c)

        local file_ok=true

        if [[ "$open_braces" -ne "$close_braces" ]]; then
            log_fail "${rel_path}: unbalanced braces ({=$open_braces, }=$close_braces)"
            file_ok=false
            syntax_errors=$((syntax_errors + 1))
        fi

        if [[ "$open_brackets" -ne "$close_brackets" ]]; then
            log_fail "${rel_path}: unbalanced brackets ([=$open_brackets, ]=$close_brackets)"
            file_ok=false
            syntax_errors=$((syntax_errors + 1))
        fi

        if [[ "$open_parens" -ne "$close_parens" ]]; then
            log_fail "${rel_path}: unbalanced parentheses ((=$open_parens, )=$close_parens)"
            file_ok=false
            syntax_errors=$((syntax_errors + 1))
        fi

        if [[ "$file_ok" == "true" ]]; then
            log_verbose "OK: $rel_path"
        fi
    done

    if [[ "$syntax_errors" -eq 0 ]]; then
        log_pass "All ${#tf_files[@]} .tf files have balanced delimiters"
    fi
}

# ── Check 2: GCP India — India-Only Regions ───────────────────────────────────

check_gcp_india_regions() {
    log_section "Check 2: GCP India region compliance (asia-south1/asia-south2 only)"

    local india_dir="${TERRAFORM_DIR}/gcp-india"

    if [[ ! -d "$india_dir" ]]; then
        log_warn "GCP India directory not found: $india_dir"
        return
    fi

    # Find all region string values that are NOT India regions
    # Look for: = "us-", = "europe-", = "asia-east", = "asia-northeast", = "asia-southeast", = "australia-"
    local bad_regions
    bad_regions="$(
        grep -r --include="*.tf" \
            -E '=\s*"(us-[a-z]|europe-[a-z]|asia-east[0-9]|asia-northeast[0-9]|asia-southeast[0-9]|australia-[a-z]|northamerica-|southamerica-)' \
            "$india_dir" 2>/dev/null || true
    )"

    if [[ -n "$bad_regions" ]]; then
        log_fail "Non-India regions found in gcp-india config:"
        echo "$bad_regions" | while IFS= read -r line; do
            log_fail "  $line"
        done
    else
        log_pass "No non-India regions in gcp-india config"
    fi

    # Verify India regions ARE present
    local india_regions
    india_regions="$(
        grep -r --include="*.tf" \
            -E '"(asia-south1|asia-south2)"' \
            "$india_dir" 2>/dev/null | wc -l
    )"

    if [[ "$india_regions" -gt 0 ]]; then
        log_pass "India regions (asia-south1/asia-south2) referenced $india_regions times"
    else
        log_fail "No India regions found in gcp-india config — config may be misconfigured"
    fi

    # Check variable validation blocks enforce India regions
    local has_validation
    has_validation="$(
        grep -r --include="*.tf" \
            'asia-south' \
            "${india_dir}/variables.tf" 2>/dev/null | wc -l
    )"

    if [[ "$has_validation" -gt 0 ]]; then
        log_pass "variables.tf contains india region validation constraints"
    else
        log_warn "variables.tf may be missing india region validation blocks"
    fi
}

# ── Check 3: No Public IPs in GCP India ──────────────────────────────────────

check_gcp_no_public_ips() {
    log_section "Check 3: No public IPs in GCP India config"

    local india_dir="${TERRAFORM_DIR}/gcp-india"

    if [[ ! -d "$india_dir" ]]; then
        log_warn "GCP India directory not found: $india_dir"
        return
    fi

    local issues=0

    # Check for access_config blocks (which assign ephemeral external IPs).
    # Exclude comment lines (lines where the first non-whitespace char is #).
    local access_configs
    access_configs="$(
        grep -r --include="*.tf" \
            -n 'access_config' \
            "$india_dir" 2>/dev/null \
            | grep -v '^\s*#' \
            | grep -v ':[[:space:]]*#' \
            || true
    )"
    if [[ -n "$access_configs" ]]; then
        log_fail "access_config block found (assigns public IP to GCE instance):"
        echo "$access_configs" | while IFS= read -r line; do
            log_fail "  $line"
        done
        issues=$((issues + 1))
    fi

    # Check for ipv4_enabled = true (Cloud SQL public IP)
    local ipv4_true
    ipv4_true="$(
        grep -r --include="*.tf" \
            -n 'ipv4_enabled\s*=\s*true' \
            "$india_dir" 2>/dev/null || true
    )"
    if [[ -n "$ipv4_true" ]]; then
        log_fail "ipv4_enabled = true found (Cloud SQL public IP enabled):"
        echo "$ipv4_true" | while IFS= read -r line; do
            log_fail "  $line"
        done
        issues=$((issues + 1))
    fi

    # Check for nat_ip blocks without NO_EXTERNAL_IP or similar
    local nat_ips
    nat_ips="$(
        grep -r --include="*.tf" \
            -n 'nat_ip\s*=' \
            "$india_dir" 2>/dev/null | grep -v '#' | grep -v 'nat_ip_allocate' || true
    )"
    if [[ -n "$nat_ips" ]]; then
        log_warn "Possible static NAT IP assignment found — verify it's Cloud NAT, not public IP:"
        echo "$nat_ips" | while IFS= read -r line; do
            log_warn "  $line"
        done
    fi

    # Verify explicit "No public IP" markers
    local no_public_ip_markers
    no_public_ip_markers="$(
        grep -r --include="*.tf" \
            -c 'No public IP\|no-public-ip\|ipv4_enabled.*false\|associate_public_ip_address.*false' \
            "$india_dir" 2>/dev/null | awk -F: '$2>0' | wc -l
    )"

    if [[ "$issues" -eq 0 ]]; then
        log_pass "No public IP configurations detected in gcp-india"
    fi

    if [[ "$no_public_ip_markers" -gt 0 ]]; then
        log_pass "Explicit no-public-IP markers found in $no_public_ip_markers files"
    fi
}

# ── Check 4: AWS GovCloud — GovCloud-Only Regions ────────────────────────────

check_aws_govcloud_regions() {
    log_section "Check 4: AWS GovCloud region compliance (us-gov-* only)"

    local govcloud_dir="${TERRAFORM_DIR}/aws-govcloud"

    if [[ ! -d "$govcloud_dir" ]]; then
        log_warn "AWS GovCloud directory not found: $govcloud_dir"
        return
    fi

    # Find all AWS region strings that are NOT GovCloud
    # Pattern: "us-east-1", "us-west-2", "eu-west-1", etc.
    local bad_regions
    bad_regions="$(
        grep -r --include="*.tf" \
            -E '"(us-east-[0-9]|us-west-[0-9]|eu-[a-z]|ap-[a-z]|ca-[a-z]|sa-[a-z]|af-[a-z]|me-[a-z])"' \
            "$govcloud_dir" 2>/dev/null || true
    )"

    if [[ -n "$bad_regions" ]]; then
        log_fail "Non-GovCloud regions found in aws-govcloud config:"
        echo "$bad_regions" | while IFS= read -r line; do
            log_fail "  $line"
        done
    else
        log_pass "No non-GovCloud regions in aws-govcloud config"
    fi

    # Verify GovCloud regions ARE present
    local govcloud_regions
    govcloud_regions="$(
        grep -r --include="*.tf" \
            -E '"us-gov-(west|east)-[0-9]"' \
            "$govcloud_dir" 2>/dev/null | wc -l
    )"

    if [[ "$govcloud_regions" -gt 0 ]]; then
        log_pass "GovCloud regions (us-gov-*) referenced $govcloud_regions times"
    else
        log_fail "No GovCloud regions found in aws-govcloud config — config may be misconfigured"
    fi

    # Check variable validation blocks enforce GovCloud regions
    local has_validation
    has_validation="$(
        grep -r --include="*.tf" \
            'us-gov-west\|us-gov-east' \
            "${govcloud_dir}/variables.tf" 2>/dev/null | wc -l
    )"

    if [[ "$has_validation" -gt 0 ]]; then
        log_pass "variables.tf contains GovCloud region validation constraints"
    else
        log_warn "variables.tf may be missing GovCloud region validation blocks"
    fi
}

# ── Check 5: AWS GovCloud — FIPS Endpoints ────────────────────────────────────

check_aws_fips_endpoints() {
    log_section "Check 5: AWS GovCloud FIPS endpoint enforcement"

    local govcloud_dir="${TERRAFORM_DIR}/aws-govcloud"

    if [[ ! -d "$govcloud_dir" ]]; then
        log_warn "AWS GovCloud directory not found: $govcloud_dir"
        return
    fi

    # Check provider block has use_fips_endpoint = true
    local fips_provider
    fips_provider="$(
        grep -r --include="*.tf" \
            -n 'use_fips_endpoint\s*=\s*true' \
            "$govcloud_dir" 2>/dev/null || true
    )"

    if [[ -n "$fips_provider" ]]; then
        log_pass "FIPS endpoint enabled in provider config"
        log_verbose "$fips_provider"
    else
        log_fail "use_fips_endpoint = true not found in aws-govcloud provider config"
    fi

    # Check for kms-fips VPC endpoint
    local kms_fips
    kms_fips="$(
        grep -r --include="*.tf" \
            -n 'kms-fips\|kms_fips\|fips' \
            "$govcloud_dir" 2>/dev/null | grep -v '#' || true
    )"

    if [[ -n "$kms_fips" ]]; then
        log_pass "FIPS KMS references found in aws-govcloud config"
    else
        log_warn "No FIPS KMS VPC endpoint found — verify KMS traffic uses FIPS endpoint"
    fi

    # Verify state backend has use_fips_endpoint
    local backend_fips
    backend_fips="$(
        grep -r --include="*.tf" \
            'use_fips_endpoint' \
            "${govcloud_dir}/main.tf" 2>/dev/null | wc -l
    )"

    if [[ "$backend_fips" -gt 0 ]]; then
        log_pass "FIPS endpoint configured in state backend (main.tf)"
    else
        log_warn "State backend in main.tf may not have FIPS endpoint — verify S3 backend config"
    fi
}

# ── Check 6: GCP HSM Protection Level ─────────────────────────────────────────

check_gcp_hsm_protection() {
    log_section "Check 6: GCP India HSM protection level enforcement"

    local india_dir="${TERRAFORM_DIR}/gcp-india"

    if [[ ! -d "$india_dir" ]]; then
        log_warn "GCP India directory not found: $india_dir"
        return
    fi

    # Check KMS keys use HSM protection level
    local hsm_keys
    hsm_keys="$(
        grep -r --include="*.tf" \
            -n 'protection_level\s*=\s*"HSM"' \
            "$india_dir" 2>/dev/null || true
    )"

    if [[ -n "$hsm_keys" ]]; then
        local hsm_count
        hsm_count="$(echo "$hsm_keys" | wc -l)"
        log_pass "HSM protection level set on $hsm_count KMS key(s)"
    else
        log_fail "No KMS keys with protection_level = \"HSM\" found in gcp-india"
    fi

    # Check for SOFTWARE protection level (should not be present in India config)
    local software_keys
    software_keys="$(
        grep -r --include="*.tf" \
            -n 'protection_level\s*=\s*"SOFTWARE"' \
            "$india_dir" 2>/dev/null || true
    )"

    if [[ -n "$software_keys" ]]; then
        log_fail "SOFTWARE protection level found in gcp-india KMS (should be HSM):"
        echo "$software_keys" | while IFS= read -r line; do
            log_fail "  $line"
        done
    else
        log_pass "No SOFTWARE protection level keys in gcp-india"
    fi
}

# ── Check 7: No Hardcoded Secrets ────────────────────────────────────────────

check_no_hardcoded_secrets() {
    log_section "Check 7: No hardcoded secrets or credentials"

    local issues=0

    # Patterns that suggest hardcoded credentials
    local secret_patterns=(
        'password\s*=\s*"[^${}][^"]{6,}"'   # password = "literal..." (not a variable)
        'secret\s*=\s*"[A-Za-z0-9+/]{20,}"'  # secret = "base64-like-string"
        'AKIA[0-9A-Z]{16}'                     # AWS access key pattern
        'private_key\s*=\s*"-----BEGIN'        # Inline private key
        'aws_secret_access_key\s*='            # AWS secret key assignment
    )

    for pattern in "${secret_patterns[@]}"; do
        local matches
        matches="$(
            grep -r --include="*.tf" \
                -n -E "$pattern" \
                "$TERRAFORM_DIR" 2>/dev/null \
                | grep -v '^\s*#' \
                | grep -v 'var\.' \
                | grep -v 'local\.' \
                | grep -v 'module\.' \
                | grep -v 'data\.' \
                | grep -v '"\${' \
                || true
        )"

        if [[ -n "$matches" ]]; then
            log_fail "Potential hardcoded secret (pattern: $pattern):"
            echo "$matches" | head -5 | while IFS= read -r line; do
                log_fail "  $line"
            done
            issues=$((issues + 1))
        fi
    done

    if [[ "$issues" -eq 0 ]]; then
        log_pass "No obvious hardcoded secrets found"
    fi
}

# ── Check 8: Required Files Present ──────────────────────────────────────────

check_required_files() {
    log_section "Check 8: Required Terraform files present"

    local required_files=(
        "gcp-india/main.tf"
        "gcp-india/variables.tf"
        "gcp-india/outputs.tf"
        "gcp-india/modules/vpc/main.tf"
        "gcp-india/modules/kms/main.tf"
        "gcp-india/modules/cloud-hsm/main.tf"
        "gcp-india/modules/cloud-sql/main.tf"
        "gcp-india/modules/compute/main.tf"
        "gcp-india/modules/iam/main.tf"
        "gcp-india/modules/gcs/main.tf"
        "aws-govcloud/main.tf"
        "aws-govcloud/variables.tf"
        "aws-govcloud/outputs.tf"
        "aws-govcloud/modules/vpc/main.tf"
        "aws-govcloud/modules/cloudhsm/main.tf"
        "aws-govcloud/modules/rds/main.tf"
        "aws-govcloud/modules/ec2/main.tf"
        "aws-govcloud/modules/iam/main.tf"
        "aws-govcloud/modules/kms/main.tf"
        "aws-govcloud/modules/secretsmanager/main.tf"
    )

    local missing=0
    for f in "${required_files[@]}"; do
        local full_path="${TERRAFORM_DIR}/${f}"
        if [[ -f "$full_path" ]]; then
            log_verbose "Found: $f"
        else
            log_fail "Missing required file: $f"
            missing=$((missing + 1))
        fi
    done

    if [[ "$missing" -eq 0 ]]; then
        log_pass "All ${#required_files[@]} required Terraform files present"
    fi
}

# ── Check 9: GCP India — lifecycle prevent_destroy on keys ───────────────────

check_gcp_key_lifecycle() {
    log_section "Check 9: GCP KMS keys have lifecycle prevent_destroy"

    local india_dir="${TERRAFORM_DIR}/gcp-india"

    if [[ ! -d "$india_dir" ]]; then
        log_warn "GCP India directory not found: $india_dir"
        return
    fi

    local kms_files
    kms_files="$(
        grep -r --include="*.tf" \
            -l 'google_kms_crypto_key' \
            "$india_dir" 2>/dev/null || true
    )"

    if [[ -z "$kms_files" ]]; then
        log_warn "No google_kms_crypto_key resources found in gcp-india"
        return
    fi

    local prevent_destroy_count
    prevent_destroy_count="$(
        grep -r --include="*.tf" \
            -c 'prevent_destroy\s*=\s*true' \
            "$india_dir" 2>/dev/null | awk -F: '$2>0' | wc -l
    )"

    if [[ "$prevent_destroy_count" -gt 0 ]]; then
        log_pass "prevent_destroy = true found in $prevent_destroy_count KMS files"
    else
        log_fail "No prevent_destroy = true found on KMS keys in gcp-india — accidental deletion risk"
    fi
}

# ── Summary ───────────────────────────────────────────────────────────────────

print_summary() {
    echo ""
    echo "============================================================"
    echo "  MILNET Terraform Validation Summary"
    echo "============================================================"
    echo "  PASS : $PASS"
    echo "  WARN : $WARN"
    echo "  FAIL : $FAIL"
    echo "============================================================"

    if [[ "$FAIL" -gt 0 ]]; then
        echo "  Result: FAILED ($FAIL check(s) failed)"
        return 1
    elif [[ "$WARN" -gt 0 && "$STRICT" == "true" ]]; then
        echo "  Result: FAILED (--strict mode: $WARN warning(s) treated as failures)"
        return 1
    else
        echo "  Result: PASSED"
        return 0
    fi
}

# ── Main ──────────────────────────────────────────────────────────────────────

main() {
    parse_args "$@"

    # Resolve absolute path
    TERRAFORM_DIR="$(realpath "$TERRAFORM_DIR" 2>/dev/null || echo "$TERRAFORM_DIR")"

    echo "============================================================"
    echo "  MILNET SSO — Terraform Compliance Validator"
    echo "============================================================"
    echo "  Terraform dir: $TERRAFORM_DIR"
    echo "  Strict mode  : $STRICT"
    echo ""

    if [[ ! -d "$TERRAFORM_DIR" ]]; then
        echo "ERROR: Terraform directory not found: $TERRAFORM_DIR" >&2
        exit 1
    fi

    check_required_files
    check_hcl_syntax
    check_gcp_india_regions
    check_gcp_no_public_ips
    check_gcp_hsm_protection
    check_gcp_key_lifecycle
    check_aws_govcloud_regions
    check_aws_fips_endpoints
    check_no_hardcoded_secrets

    print_summary
}

main "$@"
