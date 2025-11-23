# PQCTS Backend - Quick Start Guide

## 🚀 Local Development (Docker)

### Prerequisites
- Docker and Docker Compose installed
- 4GB free RAM
- Ports 3001 and 4000 available

### Run Locally

```bash
# Clone and enter directory
cd PQCTS-Backend

# Start all services
docker-compose up --build

# Or run in background
docker-compose up -d --build
```

Access at: **http://localhost:4000**

### Stop Services
```bash
docker-compose down
```

---

## ☁️ Cloud Deployment (Azure - Easiest)

### One-Command Deploy

```bash
# Make script executable (first time only)
chmod +x deploy-azure.sh

# Deploy to Azure
./deploy-azure.sh
```

The script will:
1. ✅ Login to Azure
2. ✅ Create resource group
3. ✅ Create container registry
4. ✅ Build Docker images with liboqs
5. ✅ Push images to Azure
6. ✅ Deploy containers
7. ✅ Give you the public URL

**Your app will be live at:** `http://pqcts-demo-{region}.azurecontainer.io:4000`

### Cost
- ~$30-50/month
- Delete anytime: `az group delete --name pqcts-rg --yes`

---

## 🌐 Other Cloud Platforms

### AWS (ECS Fargate)
```bash
# See DEPLOYMENT.md for full instructions
docker-compose build
# Push to ECR and deploy
```

### Google Cloud Run
```bash
gcloud builds submit --tag gcr.io/PROJECT_ID/fastapi-backend .
gcloud run deploy --image gcr.io/PROJECT_ID/fastapi-backend
```

### DigitalOcean
- Use App Platform
- Connect GitHub repo
- Auto-deploy on push

---

## 🔐 liboqs Handling

**The Problem:** Cloud platforms don't have liboqs pre-installed

**The Solution:** Docker containers!
- ✅ Dockerfile automatically builds liboqs from source
- ✅ Everything is packaged in the container
- ✅ Works on ANY cloud platform
- ✅ No manual installation needed

---

## 🧪 Testing Deployment

```bash
# Replace with your deployed URL
URL="http://your-app-url:4000"

# Health check
curl $URL/api/health

# Register user
curl -X POST $URL/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","email":"test@example.com","password":"Test123456"}'

# Test quantum keygen (through backend)
# Login first, then use token for authenticated requests
```

---

## 📊 Architecture

```
Internet
   ↓
FastAPI Backend (Port 4000)
   ↓ (HTTP)
C Quantum Service (Port 3001)
   └── liboqs (ML-KEM-768, Falcon-512)
```

**Both services run in Docker containers**, so liboqs is always available!

---

## 🆘 Troubleshooting

### "liboqs not found"
- This should never happen with Docker deployment
- If it does, rebuild: `docker-compose build --no-cache`

### "Port already in use"
```bash
# Stop conflicting services
docker-compose down
sudo lsof -ti:4000 | xargs kill -9
sudo lsof -ti:3001 | xargs kill -9
```

### "Cannot connect to quantum service"
```bash
# Check if quantum service is running
docker-compose logs quantum-service

# Restart services
docker-compose restart
```

---

## 📚 Next Steps

1. **Production Database:** Replace SQLite with PostgreSQL (see DEPLOYMENT.md)
2. **HTTPS:** Add SSL certificate (Let's Encrypt or cloud provider)
3. **Monitoring:** Enable cloud monitoring tools
4. **Scaling:** Increase replicas in docker-compose.yml or Kubernetes

---

## 💡 Key Benefits of This Setup

✅ **No manual liboqs installation** - Built into Docker image
✅ **Works on any cloud** - Azure, AWS, GCP, DigitalOcean
✅ **Easy deployment** - One command to deploy
✅ **Scalable** - Can add more containers easily
✅ **Portable** - Same config works everywhere

---

## 📞 Support

- Full deployment guide: See `DEPLOYMENT.md`
- Kubernetes setup: See `kubernetes-deployment.yml`
- Issues: Check container logs with `docker-compose logs`
