# Cloud Deployment Guide for PQCTS Backend

This guide explains how to deploy the PQCTS Backend with liboqs to various cloud platforms.

## 🚀 Quick Start (Local Testing)

```bash
# Build and run with Docker Compose
docker-compose up --build

# Or run in background
docker-compose up -d --build

# Check status
docker-compose ps

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

Access the application at: http://localhost:4000

## ☁️ Cloud Deployment Options

### Option 1: Azure Container Instances (Easiest)

**Step 1: Build and push images to Azure Container Registry**
```bash
# Login to Azure
az login

# Create resource group
az group create --name pqcts-rg --location eastus

# Create Azure Container Registry
az acr create --resource-group pqcts-rg \
  --name pqctsregistry --sku Basic

# Login to ACR
az acr login --name pqctsregistry

# Build and push C service
cd quantum_service_c
docker build -t pqctsregistry.azurecr.io/quantum-service:latest .
docker push pqctsregistry.azurecr.io/quantum-service:latest

# Build and push FastAPI service
cd ..
docker build -t pqctsregistry.azurecr.io/fastapi-backend:latest .
docker push pqctsregistry.azurecr.io/fastapi-backend:latest
```

**Step 2: Deploy to Azure Container Instances**
```bash
# Create container group
az container create \
  --resource-group pqcts-rg \
  --name pqcts-app \
  --image pqctsregistry.azurecr.io/fastapi-backend:latest \
  --registry-login-server pqctsregistry.azurecr.io \
  --registry-username $(az acr credential show --name pqctsregistry --query username -o tsv) \
  --registry-password $(az acr credential show --name pqctsregistry --query passwords[0].value -o tsv) \
  --dns-name-label pqcts-app \
  --ports 4000 \
  --environment-variables QUANTUM_API_URL=http://localhost:3001
```

### Option 2: Azure App Service (Container)

```bash
# Create App Service Plan
az appservice plan create \
  --name pqcts-plan \
  --resource-group pqcts-rg \
  --is-linux \
  --sku B1

# Create Web App for Containers
az webapp create \
  --resource-group pqcts-rg \
  --plan pqcts-plan \
  --name pqcts-backend \
  --deployment-container-image-name pqctsregistry.azurecr.io/fastapi-backend:latest

# Configure container registry credentials
az webapp config container set \
  --name pqcts-backend \
  --resource-group pqcts-rg \
  --docker-custom-image-name pqctsregistry.azurecr.io/fastapi-backend:latest \
  --docker-registry-server-url https://pqctsregistry.azurecr.io \
  --docker-registry-server-user $(az acr credential show --name pqctsregistry --query username -o tsv) \
  --docker-registry-server-password $(az acr credential show --name pqctsregistry --query passwords[0].value -o tsv)
```

### Option 3: Azure Kubernetes Service (Production Scale)

**Step 1: Create AKS cluster**
```bash
az aks create \
  --resource-group pqcts-rg \
  --name pqcts-cluster \
  --node-count 2 \
  --enable-addons monitoring \
  --generate-ssh-keys

# Get credentials
az aks get-credentials --resource-group pqcts-rg --name pqcts-cluster
```

**Step 2: Create Kubernetes deployment** (see kubernetes-deployment.yml below)

### Option 4: AWS (Amazon ECS with Fargate)

```bash
# Install AWS CLI and configure
aws configure

# Create ECR repositories
aws ecr create-repository --repository-name pqcts/quantum-service
aws ecr create-repository --repository-name pqcts/fastapi-backend

# Login to ECR
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <account-id>.dkr.ecr.us-east-1.amazonaws.com

# Build and push images
docker build -t <account-id>.dkr.ecr.us-east-1.amazonaws.com/pqcts/quantum-service:latest ./quantum_service_c
docker push <account-id>.dkr.ecr.us-east-1.amazonaws.com/pqcts/quantum-service:latest

docker build -t <account-id>.dkr.ecr.us-east-1.amazonaws.com/pqcts/fastapi-backend:latest .
docker push <account-id>.dkr.ecr.us-east-1.amazonaws.com/pqcts/fastapi-backend:latest

# Use ECS console or CLI to create task definitions and services
```

### Option 5: Google Cloud Run (Serverless)

```bash
# Install gcloud CLI and configure
gcloud auth login
gcloud config set project PROJECT_ID

# Build and deploy quantum service
gcloud builds submit --tag gcr.io/PROJECT_ID/quantum-service ./quantum_service_c
gcloud run deploy quantum-service \
  --image gcr.io/PROJECT_ID/quantum-service \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated

# Build and deploy FastAPI backend
gcloud builds submit --tag gcr.io/PROJECT_ID/fastapi-backend .
gcloud run deploy fastapi-backend \
  --image gcr.io/PROJECT_ID/fastapi-backend \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars QUANTUM_API_URL=<quantum-service-url>
```

### Option 6: DigitalOcean App Platform

```bash
# Use doctl CLI or web interface
doctl apps create --spec digitalocean-app.yaml
```

## 🔐 Environment Variables

Set these in your cloud platform:

- `QUANTUM_API_URL` - URL to quantum service (default: http://quantum-service:3001)
- `DATABASE_URL` - Database connection string (default: sqlite:///./data/qms_quantum.db)
- `JWT_SECRET` - Secret key for JWT tokens (REQUIRED in production)

## 📊 Production Recommendations

### 1. Database
Replace SQLite with a managed database:
- **Azure**: Azure Database for PostgreSQL
- **AWS**: Amazon RDS (PostgreSQL)
- **Google Cloud**: Cloud SQL

Update `DATABASE_URL`:
```
postgresql://user:password@host:5432/pqcts_db
```

### 2. Scaling
- Use load balancers for multiple instances
- Enable auto-scaling based on CPU/memory
- Use Redis for session management

### 3. Security
- Use managed secrets (Azure Key Vault, AWS Secrets Manager)
- Enable HTTPS with SSL certificates
- Use private networks for service communication
- Enable firewall rules

### 4. Monitoring
- Enable cloud platform monitoring (Azure Monitor, CloudWatch, Stackdriver)
- Set up alerts for health check failures
- Monitor liboqs performance metrics

## 🧪 Testing Deployment

```bash
# Health checks
curl https://your-domain.com/api/health

# Test quantum service
curl -X POST https://your-domain.com/api/quantum/keygen \
  -H "Content-Type: application/json" \
  -d '{"user_id":"test","key_type":"all"}'

# Test registration
curl -X POST https://your-domain.com/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","email":"test@example.com","password":"testpass123"}'
```

## 🔄 CI/CD Pipeline

Example GitHub Actions workflow (save as `.github/workflows/deploy.yml`):

```yaml
name: Deploy to Azure

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Login to Azure
        uses: azure/login@v1
        with:
          creds: ${{ secrets.AZURE_CREDENTIALS }}

      - name: Build and push images
        run: |
          az acr login --name pqctsregistry
          docker-compose build
          docker-compose push

      - name: Deploy to Azure
        run: |
          az container restart --name pqcts-app --resource-group pqcts-rg
```

## 💰 Cost Estimates (Monthly)

- **Azure Container Instances**: ~$30-50/month
- **Azure App Service (B1)**: ~$13/month
- **AWS ECS Fargate**: ~$30-60/month
- **Google Cloud Run**: Pay per use (~$10-30/month for low traffic)
- **DigitalOcean App Platform**: ~$12/month

## 🆘 Troubleshooting

**liboqs not found:**
- The Docker image builds liboqs from source automatically
- No manual installation needed in cloud deployment

**Service not responding:**
- Check health endpoints
- Review container logs
- Verify network connectivity between services

**Database errors:**
- Ensure data volume is mounted correctly
- Check DATABASE_URL environment variable
- Verify database permissions

## 📚 Additional Resources

- [liboqs Documentation](https://github.com/open-quantum-safe/liboqs)
- [Docker Documentation](https://docs.docker.com/)
- [Azure Container Instances](https://docs.microsoft.com/azure/container-instances/)
- [AWS ECS](https://docs.aws.amazon.com/ecs/)
- [Google Cloud Run](https://cloud.google.com/run/docs)
