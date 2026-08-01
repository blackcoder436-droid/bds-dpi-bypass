#!/usr/bin/env bash
# ==============================================================================
# Master 1-Click Deployment Script for Anti-DPI 3x-ui Infrastructure
# Run on fresh Ubuntu / Debian Linux VPS
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=================================================================="
echo "🚀 Starting Burmese Digital Store Anti-DPI VPN Deployment"
echo "=================================================================="

# 1. BBR Setup
bash "${SCRIPT_DIR}/scripts/01_setup_bbr.sh"

# 2. Nginx Setup
bash "${SCRIPT_DIR}/scripts/02_setup_nginx.sh"

# 3. WARP Setup
python3 "${SCRIPT_DIR}/scripts/03_setup_warp.py"

# 4. 3x-ui Database Configuration
python3 "${SCRIPT_DIR}/scripts/04_configure_3xui_db.py"

echo "=================================================================="
echo "✅ Anti-DPI VPN Infrastructure Deployment Completed Successfully!"
echo "=================================================================="
