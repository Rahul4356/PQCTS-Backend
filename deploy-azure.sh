#!/bin/bash

# PQCTS Backend - Azure Deployment Script
# This script deploys the PQCTS backend to Azure Container Instances

set -e

# Configuration
RESOURCE_GROUP="pqcts-rg"
LOCATION="eastus"
ACR_NAME="pqctsregistry"
CONTAINER_GROUP_NAME="pqcts-app"
DNS_NAME_LABEL="pqcts-demo"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}=================================================="
echo "PQCTS Backend - Azure Deployment"
echo -e "==================================================${NC}"

# Check if Azure CLI is installed
if ! command -v az &> /dev/null; then
    echo -e "${RED}Error: Azure CLI not found. Install from https://aka.ms/azure-cli${NC}"
    exit 1
fi

# Login to Azure
echo -e "${YELLOW}Logging in to Azure...${NC}"
az login

# Create resource group
echo -e "${YELLOW}Creating resource group: $RESOURCE_GROUP${NC}"
az group create --name $RESOURCE_GROUP --location $LOCATION

# Create Azure Container Registry
echo -e "${YELLOW}Creating Azure Container Registry: $ACR_NAME${NC}"
az acr create \
  --resource-group $RESOURCE_GROUP \
  --name $ACR_NAME \
  --sku Basic \
  || echo "ACR already exists"

# Login to ACR
echo -e "${YELLOW}Logging in to ACR...${NC}"
az acr login --name $ACR_NAME

# Get ACR credentials
ACR_SERVER="${ACR_NAME}.azurecr.io"
ACR_USERNAME=$(az acr credential show --name $ACR_NAME --query username -o tsv)
ACR_PASSWORD=$(az acr credential show --name $ACR_NAME --query passwords[0].value -o tsv)

# Build and push quantum service
echo -e "${YELLOW}Building and pushing quantum service...${NC}"
docker build -t $ACR_SERVER/quantum-service:latest ./quantum_service_c
docker push $ACR_SERVER/quantum-service:latest

# Build and push FastAPI backend
echo -e "${YELLOW}Building and pushing FastAPI backend...${NC}"
docker build -t $ACR_SERVER/fastapi-backend:latest .
docker push $ACR_SERVER/fastapi-backend:latest

# Create container group with both services
echo -e "${YELLOW}Creating container group...${NC}"

# Generate a secure JWT secret
JWT_SECRET=$(openssl rand -hex 32)

# Create YAML configuration for multi-container deployment
cat > azure-container.yaml <<EOF
apiVersion: 2021-09-01
location: $LOCATION
name: $CONTAINER_GROUP_NAME
properties:
  containers:
  - name: quantum-service
    properties:
      image: $ACR_SERVER/quantum-service:latest
      resources:
        requests:
          cpu: 1
          memoryInGb: 1
      ports:
      - port: 3001
        protocol: TCP
  - name: fastapi-backend
    properties:
      image: $ACR_SERVER/fastapi-backend:latest
      resources:
        requests:
          cpu: 1
          memoryInGb: 1.5
      ports:
      - port: 4000
        protocol: TCP
      environmentVariables:
      - name: QUANTUM_API_URL
        value: http://localhost:3001
      - name: JWT_SECRET
        secureValue: $JWT_SECRET
  osType: Linux
  ipAddress:
    type: Public
    dnsNameLabel: $DNS_NAME_LABEL
    ports:
    - protocol: TCP
      port: 4000
  imageRegistryCredentials:
  - server: $ACR_SERVER
    username: $ACR_USERNAME
    password: $ACR_PASSWORD
tags: {}
type: Microsoft.ContainerInstance/containerGroups
EOF

# Deploy container group
az container create \
  --resource-group $RESOURCE_GROUP \
  --file azure-container.yaml

# Clean up YAML file
rm -f azure-container.yaml

# Get the FQDN
FQDN=$(az container show \
  --resource-group $RESOURCE_GROUP \
  --name $CONTAINER_GROUP_NAME \
  --query ipAddress.fqdn \
  --output tsv)

echo -e "${GREEN}=================================================="
echo "✅ Deployment Complete!"
echo -e "==================================================${NC}"
echo ""
echo "Your application is available at:"
echo -e "${GREEN}http://${FQDN}:4000${NC}"
echo ""
echo "API Documentation:"
echo -e "${GREEN}http://${FQDN}:4000/docs${NC}"
echo ""
echo "Health Check:"
echo "curl http://${FQDN}:4000/api/health"
echo ""
echo "Resource Group: $RESOURCE_GROUP"
echo "Container Group: $CONTAINER_GROUP_NAME"
echo ""
echo "To view logs:"
echo "az container logs --resource-group $RESOURCE_GROUP --name $CONTAINER_GROUP_NAME --container-name fastapi-backend"
echo ""
echo "To delete all resources:"
echo "az group delete --name $RESOURCE_GROUP --yes --no-wait"
echo -e "${GREEN}==================================================${NC}"

# Save deployment info
cat > deployment-info.txt <<EOF
PQCTS Backend - Azure Deployment Information
=============================================

Deployment Date: $(date)
Resource Group: $RESOURCE_GROUP
Container Group: $CONTAINER_GROUP_NAME
Location: $LOCATION

Application URL: http://${FQDN}:4000
API Docs: http://${FQDN}:4000/docs

JWT Secret (save securely): $JWT_SECRET

Azure Commands:
- View logs: az container logs --resource-group $RESOURCE_GROUP --name $CONTAINER_GROUP_NAME --container-name fastapi-backend
- Restart: az container restart --resource-group $RESOURCE_GROUP --name $CONTAINER_GROUP_NAME
- Delete: az group delete --name $RESOURCE_GROUP --yes
EOF

echo -e "${YELLOW}Deployment info saved to deployment-info.txt${NC}"
