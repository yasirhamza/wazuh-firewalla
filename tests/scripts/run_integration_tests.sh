#!/bin/bash
# Integration Test Runner for Wazuh-Firewalla Stack
# Based on integration-testing skill patterns

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== Wazuh-Firewalla Integration Tests ===${NC}"
echo ""

# Check prerequisites
echo -e "${YELLOW}Checking prerequisites...${NC}"

if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed${NC}"
    exit 1
fi

if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python3 is not installed${NC}"
    exit 1
fi

# Check if containers are running
echo -e "${YELLOW}Checking container status...${NC}"
CONTAINERS=("single-node-wazuh.manager-1" "single-node-wazuh.indexer-1" "single-node-msp-poller" "single-node-threat-intel")
MISSING=0

for container in "${CONTAINERS[@]}"; do
    if docker ps --format '{{.Names}}' | grep -q "^${container}$"; then
        echo -e "  ${GREEN}✓${NC} $container running"
    else
        echo -e "  ${RED}✗${NC} $container NOT running"
        MISSING=1
    fi
done

if [ $MISSING -eq 1 ]; then
    echo ""
    echo -e "${RED}Some containers are not running. Start the stack first:${NC}"
    echo "  cd $PROJECT_ROOT && docker compose up -d"
    exit 1
fi

# Setup virtual environment and install dependencies
echo ""
echo -e "${YELLOW}Setting up test environment...${NC}"
VENV_DIR="$PROJECT_ROOT/tests/.venv"

if [ ! -d "$VENV_DIR" ]; then
    echo -e "${YELLOW}Creating virtual environment...${NC}"
    python3 -m venv "$VENV_DIR"
fi

echo -e "${YELLOW}Installing test dependencies...${NC}"
"$VENV_DIR/bin/pip" install -q pytest requests

# Load environment variables from deployment .env
DEPLOY_ENV="/opt/wazuh-docker/single-node/.env"
if [ -f "$DEPLOY_ENV" ]; then
    echo -e "${YELLOW}Loading credentials from deployment .env...${NC}"
    export INDEXER_PASSWORD=$(grep -E "^INDEXER_PASSWORD=" "$DEPLOY_ENV" | cut -d= -f2)
elif [ -f "$PROJECT_ROOT/.env" ]; then
    echo -e "${YELLOW}Loading environment from project .env...${NC}"
    export $(grep -v '^#' "$PROJECT_ROOT/.env" | xargs)
fi

if [ -z "$INDEXER_PASSWORD" ]; then
    echo -e "${RED}Warning: INDEXER_PASSWORD not set. OpenSearch tests may fail.${NC}"
fi

# Run the tests
echo ""
echo -e "${YELLOW}Running integration tests...${NC}"
echo ""

cd "$PROJECT_ROOT/tests"
"$VENV_DIR/bin/python" -m pytest integration/ -v --tb=short "$@"

TEST_RESULT=$?

echo ""
if [ $TEST_RESULT -eq 0 ]; then
    echo -e "${GREEN}=== All tests passed! ===${NC}"
else
    echo -e "${RED}=== Some tests failed ===${NC}"
fi

exit $TEST_RESULT
