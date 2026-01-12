#!/usr/bin/env bash
set -euo pipefail

NO_BUILD=0
NO_RESTORE=0

for arg in "$@"; do
  case "$arg" in
    --no-build) NO_BUILD=1 ;;
    --no-restore) NO_RESTORE=1 ;;
    *) echo "Unknown arg: $arg"; exit 2 ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACTS_ROOT="$REPO_ROOT/artifacts"
RESULTS_DIR="$ARTIFACTS_ROOT/test-results"
COVERAGE_DIR="$ARTIFACTS_ROOT/coverage"
RUNSETTINGS="$REPO_ROOT/build/coverage.runsettings"

mkdir -p "$RESULTS_DIR" "$COVERAGE_DIR"

echo "Repo: $REPO_ROOT"
echo "Results: $RESULTS_DIR"
echo "Coverage: $COVERAGE_DIR"

cd "$REPO_ROOT"

if [[ "$NO_RESTORE" -eq 0 ]]; then
  dotnet restore
fi

dotnet tool restore

DOTNET_TEST_ARGS=(
  test
  ./Security.sln
  -c Release
  --collect:"XPlat Code Coverage"
  --settings "$RUNSETTINGS"
  --results-directory "$RESULTS_DIR"
)

if [[ "$NO_BUILD" -eq 1 ]]; then
  DOTNET_TEST_ARGS+=(--no-build)
fi

echo "Running: dotnet ${DOTNET_TEST_ARGS[*]}"
dotnet "${DOTNET_TEST_ARGS[@]}"

REPORTS_GLOB="$RESULTS_DIR/**/coverage.cobertura.xml"

dotnet tool run reportgenerator \
  "-reports:$REPORTS_GLOB" \
  "-targetdir:$COVERAGE_DIR" \
  "-reporttypes:Html;HtmlSummary;TextSummary"

echo "Coverage report: $COVERAGE_DIR/index.html"
