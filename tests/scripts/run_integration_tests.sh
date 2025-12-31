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

# Install test dependencies if needed
echo ""
echo -e "${YELLOW}Checking test dependencies...${NC}"
pip3 install -q pytest requests 2>/dev/null || {
    echo -e "${YELLOW}Installing pytest and requests...${NC}"
    pip3 install pytest requests
}

# Load environment variables
if [ -f "$PROJECT_ROOT/.env" ]; then
    echo -e "${YELLOW}Loading environment from .env...${NC}"
    export $(grep -v '^#' "$PROJECT_ROOT/.env" | xargs)
fi

# Run the tests
echo ""
echo -e "${YELLOW}Running integration tests...${NC}"
echo ""

cd "$PROJECT_ROOT/tests"
python3 -m pytest integration/ -v --tb=short "$@"

TEST_RESULT=$?

echo ""
if [ $TEST_RESULT -eq 0 ]; then
    echo -e "${GREEN}=== All tests passed! ===${NC}"
else
    echo -e "${RED}=== Some tests failed ===${NC}"
fi

exit $TEST_RESULT
