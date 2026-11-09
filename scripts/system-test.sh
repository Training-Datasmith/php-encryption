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

gate_exact_committed() {
  local logfile="$1"
  local expected_file="$2"
  local label="$3"
  local expected
  expected="$(tr -d '\n\r' < "${expected_file}")"
  local stripped
  stripped="$(sed -r 's/\x1b\[[0-9;]*m//g' "${logfile}")"
  if echo "${stripped}" | grep -Eq '^(PHP )?(Warning|Deprecated|Notice):'; then
    log "FAIL: ${label} output contains PHP noise"
    return 1
  fi
  if ! grep -Fxq "${expected}" <<< "${stripped}"; then
    log "FAIL: ${label} missing exact line: ${expected}"
    return 1
  fi
  log "${label}: ${expected}"
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

log "Composer update + audit + checks + PHPUnit (split gates)"
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

    vendor/bin/phpunit --colors=never --log-junit /app/.system-test/phpunit-baseline.junit.xml \
      -c test/phpunit-8.xml --testsuite baseline --bootstrap vendor/autoload.php \
      2>&1 | tee /app/.system-test/phpunit-baseline.out

    vendor/bin/phpunit --colors=never \
      -c test/phpunit-8.xml --testsuite added --bootstrap vendor/autoload.php \
      2>&1 | tee /app/.system-test/phpunit-added.out

    vendor/bin/phpunit --colors=never \
      -c test/phpunit-8.xml --testsuite all --bootstrap vendor/autoload.php \
      2>&1 | tee /app/.system-test/phpunit-full.out
  '

gate_line "${COMPOSER_GATE_PATTERN}" "${ROOT_DIR}/.system-test/composer-version.out" "composer version"
gate_line "${AUDIT_GATE}" "${ROOT_DIR}/.system-test/composer-audit.out" "composer audit"
gate_line '^check-cluster-pins: all cluster packages match expected SHAs and aliases \([0-9]+ packages\)\.$' \
  "${ROOT_DIR}/.system-test/check-pins.out" "cluster pins"
gate_line '^OK rename-check$' "${ROOT_DIR}/.system-test/check-rename.out" "rename check"

gate_exact_committed "${ROOT_DIR}/.system-test/phpunit-baseline.out" \
  "${ROOT_DIR}/scripts/phpunit-baseline-line.txt" "PHPUnit baseline"
"${DOCKER[@]}" run --rm -v "${ROOT_DIR}:/app" -w /app "${IMAGE_TEST}" \
  php scripts/check-phpunit-gate.php baseline /app/.system-test/phpunit-baseline.out /app/.system-test/phpunit-baseline.junit.xml \
  2>&1 | tee "${ROOT_DIR}/.system-test/phpunit-baseline-gate.out"
gate_line "^PHPUnit gate passed \\(baseline\\): OK \\(1374 tests, 207554 assertions\\)$" \
  "${ROOT_DIR}/.system-test/phpunit-baseline-gate.out" "phpunit baseline gate"

gate_exact_committed "${ROOT_DIR}/.system-test/phpunit-added.out" \
  "${ROOT_DIR}/scripts/phpunit-added-line.txt" "PHPUnit added"
"${DOCKER[@]}" run --rm -v "${ROOT_DIR}:/app" -w /app "${IMAGE_TEST}" \
  php scripts/check-phpunit-gate.php added /app/.system-test/phpunit-added.out \
  2>&1 | tee "${ROOT_DIR}/.system-test/phpunit-added-gate.out"
ADDED_GATE_EXPECTED="PHPUnit gate passed (added): $(tr -d '\n\r' < "${ROOT_DIR}/scripts/phpunit-added-line.txt")"
if ! grep -Fxq "${ADDED_GATE_EXPECTED}" "${ROOT_DIR}/.system-test/phpunit-added-gate.out"; then
  log "FAIL: phpunit added gate missing: ${ADDED_GATE_EXPECTED}"
  exit 1
fi
log "phpunit added gate: ${ADDED_GATE_EXPECTED}"

gate_exact_committed "${ROOT_DIR}/.system-test/phpunit-full.out" \
  "${ROOT_DIR}/scripts/phpunit-full-line.txt" "PHPUnit full"
"${DOCKER[@]}" run --rm -v "${ROOT_DIR}:/app" -w /app "${IMAGE_TEST}" \
  php scripts/check-phpunit-gate.php full /app/.system-test/phpunit-full.out \
  2>&1 | tee "${ROOT_DIR}/.system-test/phpunit-full-gate.out"
FULL_GATE_EXPECTED="PHPUnit gate passed (full): $(tr -d '\n\r' < "${ROOT_DIR}/scripts/phpunit-full-line.txt")"
if ! grep -Fxq "${FULL_GATE_EXPECTED}" "${ROOT_DIR}/.system-test/phpunit-full-gate.out"; then
  log "FAIL: phpunit full gate missing: ${FULL_GATE_EXPECTED}"
  exit 1
fi
log "phpunit full gate: ${FULL_GATE_EXPECTED}"

log "HKDF null-salt floor test (PHP 5.6 fallback)"
"${DOCKER[@]}" run --rm -v "${ROOT_DIR}:/app" -w /app "${IMAGE_FLOOR}" \
  php scripts/hkdf-null-salt-floor-test.php 2>&1 | tee "${ROOT_DIR}/.system-test/hkdf-floor.out"
gate_line '^OK hkdf-null-salt floor test$' "${ROOT_DIR}/.system-test/hkdf-floor.out" "hkdf null-salt floor"

log "System test passed."
