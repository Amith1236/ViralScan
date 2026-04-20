# ViralScan
A secure, containerised malware scanning web app using the VirusTotal API with AI-powered explanations from Gemini.


## Overview

**ViralScan** is a full-stack security-focused application designed to:
- Safely handle file uploads
- Validate file contents using magic byte detection
- Scan files using the VirusTotal API
- Generate human-readable explanations using Gemini AI

This project was built with a strong focus on learning DevOps practices, including:
- Containerisation (Docker)
- Infrastructure deployment (AWS EC2)
- Reverse proxy configuration (Nginx)
- CI/CD automation (GitHub Actions)

## Architecture

Browser  

Nginx (reverse proxy, TLS, rate limiting)  


FastAPI Backend  
- controllers/     API routes  
- services/        VirusTotal, Gemini, validation logic  
- models/          Pydantic schemas  
- middleware/      Logging, security, rate limiting  

External APIs: VirusTotal, Gemini

## Project Structure

- backend/ - FastAPI backend, business logic, validation, API integrations  
- frontend/ - Static UI (HTML, CSS, JS)  
- nginx/ - Reverse proxy configuration for production  
- Dockerfile - Multi-stage production build  
- docker-compose.yml - Development environment  
- docker-compose.prod.yml - Production setup  


## Setup

### Prerequisites

- Docker + Docker Compose  
- VirusTotal API key  
- Gemini API key  
- AWS EC2 instance (for deployment)  


### Local Development (Docker)

```bash
docker compose up --build
```

Access: http://localhost:8000



## Production Deployment (EC2 - Manual)

### 1. SSH into EC2

```bash
ssh -i your-key.pem ec2-user@<EC2_IP>
```

### 2. Install Docker

```bash
sudo yum update -y
sudo yum install -y docker
sudo service docker start
sudo usermod -aG docker ec2-user
```

Reconnect after this step.

### 3. Install Docker Compose (plugin)

```bash
mkdir -p ~/.docker/cli-plugins

curl -L https://github.com/docker/compose/releases/latest/download/docker-compose-linux-x86_64   -o ~/.docker/cli-plugins/docker-compose

chmod +x ~/.docker/cli-plugins/docker-compose
```

### 4. Clone Repository

```bash
git clone <repo-url>
cd ViralScan
```

### 5. Configure Environment

```bash
nano .env
```

Add:

VIRUSTOTAL_API_KEY=...
GEMINI_API_KEY=...
SECRET_KEY=...

### 6. Run Application

```bash
docker compose up --build -d
```

### 7. Access Application

http://<EC2_PUBLIC_IP>:8000

### 8. Access Application (HTTPS)

1. Replace `<EC2_PUBLIC_IP>` with your instance IP.
   Example: `<EC2_PUBLIC_IP>.sslip.io`

2. Install Certbot:

```bash
sudo yum install -y certbot
```

3. Stop your app temporarily (Certbot needs port 80):

```bash
docker compose down
```

4. Obtain SSL certificate (standalone mode):

```bash
sudo certbot certonly --standalone -d <EC2_PUBLIC_IP>.sslip.io
```

Certificates will be stored in:

```text
/etc/letsencrypt/live/<EC2_PUBLIC_IP>.sslip.io/
```

5. Copy certificates into your project:

```bash
mkdir -p nginx/certs
sudo cp /etc/letsencrypt/live/<EC2_PUBLIC_IP>.sslip.io/fullchain.pem nginx/certs/
sudo cp /etc/letsencrypt/live/<EC2_PUBLIC_IP>.sslip.io/privkey.pem nginx/certs/
```

6. Update Nginx to use HTTPS (port 443).

Ensure your `nginx` config:
- listens on port 443
- uses the copied certs
- proxies to your FastAPI app

7. Restart the application with Nginx:

```bash
docker compose -f docker-compose.prod.yml up --build -d
```

Then access the secure app at:

```text
https://<EC2_PUBLIC_IP>.sslip.io
```

## CI/CD (In Progress)

Planned pipeline using GitHub Actions:
1. Run tests  
2. Build Docker image  
3. Push to container registry  
4. SSH into EC2 and deploy  


## Challenges Faced

### 1. File upload validation

My inital naive implementation trusted the client-supplied filename and Content-Type header but this lead to vulnerabilites when threat-modelling the upload flow.

1. A filename like ../../etc/passwd would write outside the intended directory if not sanitised
2. A .exe renamed to .pdf would bypass any extension check

I added the additional layer of mitigation through a file_validator service to sanitise the files. Files are written to a tmpfs RAM-backed mount with chmod 0400 and deleted immediately after submission to VirusTotal via FastAPI's BackgroundTasks

### 2. VirusTotal API

The VirusTotal API returns an analysis_id immediately and we have to poll a separate endpoint repeatedly until the status flips to completed. This can take anywhere from 30 seconds to two minutes depending on file type and engine queue depth. I found that the API requests were taking much longer than the in browser requests, so I had to plan around it with a timer constantly polling to check if analysis is done. The user experience was also different when testing locally and in production, due to the lag in connection.

This led me to try to improve the user experience on the UI side with more transparent timers, as well as trying to implement a queue system to batch upload the files for testing multiple at once.

### 3. LLM Integration

The test suite passed cleanly, but when the application was running in the production environment, there were failures in the Gemini service that only appeared as missing explainations on the frontend. 

Initially I did not have detailed logging implemented for each component. I had to improve my logging inside gemini.py to log the specific exception type and message at ERROR level. Only then I realised that the Gemini API was rejecting requests because the API key was valid but the default model name gemini-1.5-flash had been updated and the old string was returning a 404.

## Solutions and Improvements

- Added middleware for request logging and rate limiting to support safer API usage.
- Used Nginx as a reverse proxy to provide additional security and to serve static content efficiently.
- Built the app to be container-friendly with Docker and compose for reproducible deployment.

## Future Work

- Add more detailed testing for the frontend and backend
- Extend file validation to support additional safe file formats
- Improve user-facing AI explanations and scan result summaries
- Harden deployment settings for production and CI/CD

## Notes

This README will continue to expand with more setup guidance, testing instructions, and challenge documentation as the project evolves.
