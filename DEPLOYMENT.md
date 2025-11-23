# PQCTS Backend - Azure Deployment Guide

This guide explains how to deploy the PQCTS (Post-Quantum Cryptographic Transport System) backend to Azure.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Local Development](#local-development)
3. [Azure Deployment Options](#azure-deployment-options)
4. [Option 1: Azure Container Apps (Recommended)](#option-1-azure-container-apps-recommended)
5. [Option 2: Azure App Service with Containers](#option-2-azure-app-service-with-containers)
6. [Option 3: Azure Kubernetes Service (AKS)](#option-3-azure-kubernetes-service-aks)
7. [Database Configuration](#database-configuration)
8. [CI/CD Setup](#cicd-setup)
9. [Monitoring and Logging](#monitoring-and-logging)
10. [Troubleshooting](#troubleshooting)

---

## Prerequisites

- **Azure Account** with active subscription
- **Azure CLI** installed and configured (`az login`)
- **Docker** installed for local testing
- **Git** for version control
- **GitHub Account** (for CI/CD)
- **Python 3.10+** (for local development)

---

## Local Development

### 1. Clone the Repository

```bash
git clone https://github.com/Rahul4356/PQCTS-Backend.git
cd PQCTS-Backend
```

### 2. Set Up Environment Variables

```bash
cp .env.example .env
# Edit .env with your configuration
```

### 3. Run with Docker Compose

```bash
# Build and start services
docker-compose up --build

# Access the application
# Frontend: http://localhost:4000
# API Docs: http://localhost:4000/docs
# Quantum Service: http://localhost:3001/api/health
```

### 4. Run Without Docker (Development)

```bash
# Install dependencies
pip install -r requirements.txt

# Build C quantum service
cd quantum_service_c
make clean && make
./quantum_service &
cd ..

# Run FastAPI
python3 app_modified.py
```

---

## Azure Deployment Options

### Comparison Table

| Feature | Container Apps | App Service | AKS |
|---------|---------------|-------------|-----|
| **Ease of Setup** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐ |
| **Cost (Small Scale)** | $$ | $$$ | $$$$ |
| **Scalability** | Excellent | Good | Excellent |
| **Container Support** | Native | Good | Native |
| **Complexity** | Low | Low | High |
| **Recommendation** | ✅ Best for this app | Good alternative | Overkill |

---

## Option 1: Azure Container Apps (Recommended)

### Why Container Apps?

- ✅ Built for containerized applications
- ✅ Automatic scaling (including to zero)
- ✅ Cost-effective for variable workloads
- ✅ Easy deployment and management
- ✅ Built-in ingress and SSL

### Step 1: Create Azure Resources

```bash
# Login to Azure
az login

# Set variables
RESOURCE_GROUP="pqcts-rg"
LOCATION="eastus"
CONTAINER_APP_ENV="pqcts-env"
CONTAINER_APP_NAME="pqcts-backend"

# Create resource group
az group create \
  --name $RESOURCE_GROUP \
  --location $LOCATION

# Create Container Apps environment
az containerapp env create \
  --name $CONTAINER_APP_ENV \
  --resource-group $RESOURCE_GROUP \
  --location $LOCATION
```

### Step 2: Build and Push Docker Image

#### Option A: Using GitHub Container Registry (GHCR)

```bash
# Login to GHCR
echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin

# Build and push
docker build -t ghcr.io/rahul4356/pqcts-backend:latest .
docker push ghcr.io/rahul4356/pqcts-backend:latest
```

#### Option B: Using Azure Container Registry (ACR)

```bash
# Create ACR
ACR_NAME="pqctsacr"
az acr create \
  --resource-group $RESOURCE_GROUP \
  --name $ACR_NAME \
  --sku Basic \
  --location $LOCATION

# Login to ACR
az acr login --name $ACR_NAME

# Build and push
az acr build \
  --registry $ACR_NAME \
  --image pqcts-backend:latest \
  --file Dockerfile .
```

### Step 3: Deploy Container App

#### Using Bicep Template (Recommended)

```bash
# Generate a strong JWT secret
JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")

# Deploy using Bicep
az deployment group create \
  --resource-group $RESOURCE_GROUP \
  --template-file azure-deploy.bicep \
  --parameters \
    appName=pqcts-backend \
    environmentName=prod \
    containerImage=ghcr.io/rahul4356/pqcts-backend:latest \
    registryUsername=rahul4356 \
    registryPassword=$GITHUB_TOKEN \
    jwtSecret=$JWT_SECRET \
    databaseUrl="sqlite:///./qms_quantum.db"
```

#### Using Azure CLI

```bash
az containerapp create \
  --name $CONTAINER_APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --environment $CONTAINER_APP_ENV \
  --image ghcr.io/rahul4356/pqcts-backend:latest \
  --target-port 8000 \
  --ingress external \
  --min-replicas 1 \
  --max-replicas 5 \
  --cpu 1.0 \
  --memory 2.0Gi \
  --env-vars \
    PORT=8000 \
    QUANTUM_SERVICE_PORT=3001 \
    QUANTUM_API_URL=http://localhost:3001 \
    JWT_SECRET=$JWT_SECRET \
    ENVIRONMENT=production \
    LOG_LEVEL=INFO \
  --secrets \
    jwt-secret=$JWT_SECRET
```

### Step 4: Get Application URL

```bash
# Get the URL
az containerapp show \
  --name $CONTAINER_APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --query properties.configuration.ingress.fqdn \
  --output tsv
```

---

## Option 2: Azure App Service with Containers

### Step 1: Create App Service Plan

```bash
APP_SERVICE_PLAN="pqcts-plan"
WEB_APP_NAME="pqcts-backend-app"

# Create App Service Plan (Linux)
az appservice plan create \
  --name $APP_SERVICE_PLAN \
  --resource-group $RESOURCE_GROUP \
  --is-linux \
  --sku B2

# Create Web App
az webapp create \
  --name $WEB_APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --plan $APP_SERVICE_PLAN \
  --deployment-container-image-name ghcr.io/rahul4356/pqcts-backend:latest
```

### Step 2: Configure Application Settings

```bash
az webapp config appsettings set \
  --name $WEB_APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --settings \
    PORT=8000 \
    QUANTUM_SERVICE_PORT=3001 \
    JWT_SECRET=$JWT_SECRET \
    ENVIRONMENT=production
```

### Step 3: Configure Container Settings

```bash
# Set startup command
az webapp config set \
  --name $WEB_APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --startup-file "/app/startup.sh"

# Enable container logging
az webapp log config \
  --name $WEB_APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --docker-container-logging filesystem
```

---

## Option 3: Azure Kubernetes Service (AKS)

For production deployments requiring advanced orchestration:

```bash
# Create AKS cluster
az aks create \
  --resource-group $RESOURCE_GROUP \
  --name pqcts-aks \
  --node-count 2 \
  --enable-addons monitoring \
  --generate-ssh-keys

# Get credentials
az aks get-credentials \
  --resource-group $RESOURCE_GROUP \
  --name pqcts-aks

# Deploy using kubectl
kubectl create deployment pqcts-backend \
  --image=ghcr.io/rahul4356/pqcts-backend:latest

kubectl expose deployment pqcts-backend \
  --type=LoadBalancer \
  --port=80 \
  --target-port=8000
```

---

## Database Configuration

### Development: SQLite (Default)

```bash
DATABASE_URL=sqlite:///./qms_quantum.db
```

### Production: Azure PostgreSQL (Recommended)

#### Step 1: Create PostgreSQL Server

```bash
PG_SERVER="pqcts-postgres"
PG_ADMIN_USER="pqctsadmin"
PG_ADMIN_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(16))")
PG_DATABASE="pqcts_db"

az postgres flexible-server create \
  --name $PG_SERVER \
  --resource-group $RESOURCE_GROUP \
  --location $LOCATION \
  --admin-user $PG_ADMIN_USER \
  --admin-password $PG_ADMIN_PASSWORD \
  --sku-name Standard_B1ms \
  --tier Burstable \
  --version 15 \
  --storage-size 32

# Create database
az postgres flexible-server db create \
  --resource-group $RESOURCE_GROUP \
  --server-name $PG_SERVER \
  --database-name $PG_DATABASE

# Allow Azure services
az postgres flexible-server firewall-rule create \
  --resource-group $RESOURCE_GROUP \
  --name $PG_SERVER \
  --rule-name AllowAzureServices \
  --start-ip-address 0.0.0.0 \
  --end-ip-address 0.0.0.0
```

#### Step 2: Update Database URL

```bash
# Connection string format
DATABASE_URL="postgresql://${PG_ADMIN_USER}:${PG_ADMIN_PASSWORD}@${PG_SERVER}.postgres.database.azure.com:5432/${PG_DATABASE}?sslmode=require"

# Update Container App
az containerapp update \
  --name $CONTAINER_APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --set-env-vars DATABASE_URL=$DATABASE_URL
```

### Alternative: Azure SQL Database

```bash
# Connection string
DATABASE_URL="mssql+pyodbc://username:password@servername.database.windows.net:1433/pqcts_db?driver=ODBC+Driver+18+for+SQL+Server"
```

---

## CI/CD Setup

### GitHub Actions (Included)

The repository includes `.github/workflows/azure-deploy.yml` for automated deployment.

#### Step 1: Set Up Secrets

Go to GitHub Repository → Settings → Secrets and add:

1. **AZURE_CREDENTIALS**: Service principal credentials

```bash
# Create service principal
az ad sp create-for-rbac \
  --name "pqcts-github-actions" \
  --role contributor \
  --scopes /subscriptions/{subscription-id}/resourceGroups/$RESOURCE_GROUP \
  --sdk-auth

# Copy the JSON output to GitHub secret AZURE_CREDENTIALS
```

2. **GITHUB_TOKEN**: Automatically provided by GitHub

#### Step 2: Push to Deploy

```bash
# Push to main branch for dev deployment
git push origin main

# Push to production branch for prod deployment
git push origin production
```

### Azure DevOps Pipelines

Create `azure-pipelines.yml`:

```yaml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: Docker@2
    inputs:
      containerRegistry: 'your-acr'
      repository: 'pqcts-backend'
      command: 'buildAndPush'
      Dockerfile: '**/Dockerfile'

  - task: AzureContainerApps@1
    inputs:
      azureSubscription: 'your-subscription'
      resourceGroup: '$(RESOURCE_GROUP)'
      containerAppName: '$(CONTAINER_APP_NAME)'
      imageToDeploy: 'your-acr.azurecr.io/pqcts-backend:$(Build.BuildId)'
```

---

## Monitoring and Logging

### Application Insights

```bash
# Create Application Insights
az monitor app-insights component create \
  --app pqcts-insights \
  --location $LOCATION \
  --resource-group $RESOURCE_GROUP

# Get instrumentation key
INSTRUMENTATION_KEY=$(az monitor app-insights component show \
  --app pqcts-insights \
  --resource-group $RESOURCE_GROUP \
  --query instrumentationKey \
  --output tsv)

# Update container app
az containerapp update \
  --name $CONTAINER_APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --set-env-vars \
    APPLICATIONINSIGHTS_CONNECTION_STRING="InstrumentationKey=${INSTRUMENTATION_KEY}"
```

### View Logs

```bash
# Container App logs
az containerapp logs show \
  --name $CONTAINER_APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --tail 100

# App Service logs
az webapp log tail \
  --name $WEB_APP_NAME \
  --resource-group $RESOURCE_GROUP
```

---

## Troubleshooting

### Issue: Container fails to start

```bash
# Check logs
az containerapp logs show \
  --name $CONTAINER_APP_NAME \
  --resource-group $RESOURCE_GROUP

# Check revision status
az containerapp revision list \
  --name $CONTAINER_APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --output table
```

### Issue: Quantum Service not responding

- Check if both services are running in the container
- Verify `QUANTUM_API_URL` is set to `http://localhost:3001`
- Check supervisor logs inside container

### Issue: Database connection errors

- Verify `DATABASE_URL` is correctly formatted
- Check firewall rules for PostgreSQL
- Ensure SSL is enabled for Azure PostgreSQL

### Issue: Authentication errors

- Verify `JWT_SECRET` is set and consistent
- Check that secret is properly passed to container
- Regenerate JWT secret if needed

---

## Security Best Practices

1. **Use Azure Key Vault** for secrets:
```bash
az keyvault create \
  --name pqcts-keyvault \
  --resource-group $RESOURCE_GROUP \
  --location $LOCATION

# Store secrets
az keyvault secret set \
  --vault-name pqcts-keyvault \
  --name jwt-secret \
  --value $JWT_SECRET
```

2. **Enable HTTPS only**
3. **Use managed identities** for Azure service authentication
4. **Enable Azure Defender** for Container Apps
5. **Regular security updates** - rebuild containers monthly
6. **Monitor with Azure Sentinel**

---

## Cost Optimization

1. **Container Apps**: Use `--min-replicas 0` for dev environments
2. **PostgreSQL**: Use Burstable tier for development
3. **Container Registry**: Use Basic tier, enable image retention policies
4. **Monitor usage**: Set up budget alerts in Azure

---

## Support and Resources

- **Documentation**: [Azure Container Apps Docs](https://docs.microsoft.com/azure/container-apps/)
- **Issues**: [GitHub Issues](https://github.com/Rahul4356/PQCTS-Backend/issues)
- **Azure Support**: [Azure Portal](https://portal.azure.com)

---

## Quick Reference Commands

```bash
# Redeploy latest image
az containerapp update \
  --name $CONTAINER_APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --image ghcr.io/rahul4356/pqcts-backend:latest

# Scale manually
az containerapp update \
  --name $CONTAINER_APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --min-replicas 2 \
  --max-replicas 10

# View metrics
az monitor metrics list \
  --resource $CONTAINER_APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --resource-type Microsoft.App/containerApps \
  --metric-names Requests

# Delete all resources
az group delete --name $RESOURCE_GROUP --yes --no-wait
```

---

**Deployment Status**: ✅ Ready for Azure
**Last Updated**: 2025-11-23
**Version**: 1.0.0
