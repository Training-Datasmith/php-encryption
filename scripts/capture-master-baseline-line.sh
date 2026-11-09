#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WT="${ROOT}/.master-baseline-worktree"
IMAGE="php-encryption-system-test:remote-test-2026-11-09"
OUT="${ROOT}/scripts/phpunit-baseline-line.txt"

USE_SUDO_DOCKER="${USE_SUDO_DOCKER:-0}"
if [[ "${USE_SUDO_DOCKER}" == "1" ]]; then
  DOCKER=(sudo docker)
else
  DOCKER=(docker)
fi

if [[ ! -d "${WT}" ]]; then
  git worktree add --detach "${WT}" origin/master
fi

BIG="${WT}/test/unit/File/big-generated-file"
if [[ ! -f "${BIG}" ]] || [[ "$(wc -c < "${BIG}")" -ne 209715200 ]]; then
  dd if=/dev/urandom "of=${BIG}" bs=1M count=200 status=none
fi

mkdir -p "${ROOT}/.system-test"

"${DOCKER[@]}" build -f "${ROOT}/docker/system-test/Dockerfile" -t "${IMAGE}" "${ROOT}/docker/system-test" >/dev/null

"${DOCKER[@]}" run --rm -v "${WT}:/app" -w /app -e COMPOSER_ALLOW_SUPERUSER=1 "${IMAGE}" bash -lc '
  set -euo pipefail
  composer update --no-interaction --prefer-stable --no-progress >/dev/null
  vendor/bin/phpunit --colors=never -c test/phpunit-8.xml --bootstrap vendor/autoload.php test/unit
' 2>&1 | tee "${ROOT}/.system-test/master-baseline-phpunit.out"

LINE="$(sed -r 's/\x1b\[[0-9;]*m//g' "${ROOT}/.system-test/master-baseline-phpunit.out" | grep -E '^OK \([0-9]+ tests?, [0-9]+ assertions?\)$' | tail -n 1)"
if [[ -z "${LINE}" ]]; then
  echo "Failed to capture baseline PHPUnit line from master" >&2
  exit 1
fi
echo "${LINE}" > "${OUT}"
echo "Wrote ${OUT}: ${LINE}"
