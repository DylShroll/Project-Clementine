FROM python:3.12-slim

WORKDIR /app

# System deps: Node.js 20 (for azure-mcp via npx), Azure CLI, git
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates gnupg git \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && curl -sL https://aka.ms/InstallAzureCLIDeb | bash \
    && rm -rf /var/lib/apt/lists/*

# azure-mcp — installed globally so npx can find it without network at runtime
RUN npm install -g @azure/mcp@latest

# Prowler with Azure extras
RUN pip install --no-cache-dir "prowler[azure]>=5.6"

# Python dependencies for Clementine
COPY pyproject.toml ./
RUN pip install --no-cache-dir \
        azure-identity \
        azure-mgmt-resource \
        azure-mgmt-authorization \
        azure-mgmt-resourcegraph \
        azure-mgmt-keyvault \
        azure-mgmt-storage \
        azure-mgmt-compute \
        azure-mgmt-containerservice \
        azure-mgmt-network \
        azure-mgmt-msi \
        azure-mgmt-web \
        azure-mgmt-monitor \
        msgraph-sdk \
        aiohttp

# Install Clementine itself (editable during dev, regular in prod)
COPY . .
RUN pip install --no-cache-dir -e .

# Smoke-check critical binaries
RUN az version > /dev/null \
    && prowler azure --help > /dev/null 2>&1 || true \
    && node --version

# Non-root user for runtime security
RUN useradd -m -u 1001 clementine
USER clementine

# Default command — override with docker run arguments
CMD ["clementine", "--help"]
