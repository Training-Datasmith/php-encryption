#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

USE_SUDO_DOCKER="${USE_SUDO_DOCKER:-0}"
IMAGE_TEST="php-encryption-system-test:remote-test-2026-11-09"
IMAGE_FLOOR="php-encryption-floor-lint:remote-test-2026-11-09"
COMPOSER_GATE_PATTERN='^Composer version 2\.8\.10 2025-07-10 [0-9]{2}:[0-9]{2}:[0-9]{2}$'
AUDIT_GATE='^No security vulnerability advisories found\.$'
BIG_FILE="${ROOT_DIR}/test/unit/File/big-generated-file"
BIG_BYTES=209715200

if [[ "${USE_SUDO_DOCKER}" == "1" ]]; then
  DOCKER=(sudo docker)
else
  DOCKER=(docker)
fi

log() { printf '%s\n' "$*"; }

ensure_big_file() {
  if [[ ! -f "${BIG_FILE}" ]] || [[ "$(wc -c < "${BIG_FILE}")" -ne "${BIG_BYTES}" ]]; then
    log "Creating ${BIG_BYTES}-byte test fixture..."
    dd if=/dev/urandom "of=${BIG_FILE}" bs=1M count=200 status=none
  fi
}

gate_line() {
  local pattern="$1"
  local file="$2"
  local label="$3"
  local stripped
  stripped="$(sed -r 's/\x1b\[[0-9;]*m//g' "${file}")"
  if echo "${stripped}" | grep -Eq '^(PHP )?(Warning|Deprecated|Notice):'; then
    log "FAIL: ${label} output contains PHP noise"
    return 1
  fi
  if ! echo "${stripped}" | grep -Eq "${pattern}"; then
    log "FAIL: ${label} missing gate line matching ${pattern}"
    return 1
  fi
  echo "${stripped}" | grep -E "${pattern}" | tail -n 1
  return 0
}

ensure_big_file

log "Building images"
"${DOCKER[@]}" build -f "${ROOT_DIR}/docker/system-test/Dockerfile" -t "${IMAGE_TEST}" "${ROOT_DIR}/docker/system-test"
"${DOCKER[@]}" build -f "${ROOT_DIR}/docker/floor-lint/Dockerfile" -t "${IMAGE_FLOOR}" "${ROOT_DIR}/docker/floor-lint"

mkdir -p "${ROOT_DIR}/.system-test"

log "Floor lint (PHP 5.6)"
"${DOCKER[@]}" run --rm -v "${ROOT_DIR}:/app" -w /app "${IMAGE_FLOOR}" \
  php scripts/run-floor-lint.php 2>&1 | tee "${ROOT_DIR}/.system-test/floor-lint.out"
gate_line '^OK lint \([0-9]+ files\)$' "${ROOT_DIR}/.system-test/floor-lint.out" "floor lint"

log "Composer update + audit + checks + PHPUnit"
"${DOCKER[@]}" run --rm \
  -v "${ROOT_DIR}:/app" \
  -w /app \
  -e COMPOSER_ALLOW_SUPERUSER=1 \
  "${IMAGE_TEST}" \
  bash -lc '
    set -euo pipefail
    git config --global --add safe.directory /app
    composer --version | tee /app/.system-test/composer-version.out
    composer update --no-interaction --prefer-stable --no-progress 2>&1 | tee /app/.system-test/composer-update.out
    composer audit --no-interaction --abandoned=report 2>&1 | tee /app/.system-test/composer-audit.out
    php scripts/check-cluster-pins.php 2>&1 | tee /app/.system-test/check-pins.out
    php scripts/check-rename.php 2>&1 | tee /app/.system-test/check-rename.out
    php -r "require \"vendor/autoload.php\";" 2>&1 | tee /app/.system-test/bootstrap-load.out
    vendor/bin/phpunit --colors=never --log-junit /app/.system-test/phpunit.junit.xml \
      -c test/phpunit-8.xml --bootstrap vendor/autoload.php \
      2>&1 | tee /app/.system-test/phpunit.out
  '

gate_line "${COMPOSER_GATE_PATTERN}" "${ROOT_DIR}/.system-test/composer-version.out" "composer version"
gate_line "${AUDIT_GATE}" "${ROOT_DIR}/.system-test/composer-audit.out" "composer audit"
gate_line '^check-cluster-pins: all cluster packages match expected SHAs and aliases \([0-9]+ packages\)\.$' \
  "${ROOT_DIR}/.system-test/check-pins.out" "cluster pins"
gate_line '^OK rename-check$' "${ROOT_DIR}/.system-test/check-rename.out" "rename check"

PHPUNIT_STRIPPED="$(sed -r 's/\x1b\[[0-9;]*m//g' "${ROOT_DIR}/.system-test/phpunit.out")"
if echo "${PHPUNIT_STRIPPED}" | grep -Eq '^(PHP )?(Warning|Deprecated|Notice):'; then
  log "FAIL: PHPUnit output contains PHP noise"
  echo "${PHPUNIT_STRIPPED}" | grep -E '^(PHP )?(Warning|Deprecated|Notice):' | head -5
  exit 1
fi
OK_LINE="$(echo "${PHPUNIT_STRIPPED}" | grep -E '^OK \([0-9]+ tests?, [0-9]+ assertions?\)$' | tail -n 1)"
if [[ -z "${OK_LINE}" ]]; then
  log "FAIL: PHPUnit missing OK line"
  exit 1
fi
log "Captured PHPUnit line: ${OK_LINE}"
echo "${OK_LINE}" > "${ROOT_DIR}/scripts/phpunit-expected-line.txt"

"${DOCKER[@]}" run --rm -v "${ROOT_DIR}:/app" -w /app "${IMAGE_TEST}" \
  php scripts/check-phpunit-gate.php /app/.system-test/phpunit.out /app/.system-test/phpunit.junit.xml \
  2>&1 | tee "${ROOT_DIR}/.system-test/phpunit-gate.out"
gate_line '^PHPUnit gate passed: OK \([0-9]+ tests?, [0-9]+ assertions?\)$' \
  "${ROOT_DIR}/.system-test/phpunit-gate.out" "phpunit gate"

log "System test passed."
