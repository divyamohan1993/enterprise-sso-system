# MILNET SSO Deployment Guide

## Local Development

Build and run the SSO system locally using Docker Compose:

```bash
docker-compose up --build
```

The admin UI will be available at `http://localhost:8080`.

## Google Cloud Run

### Prerequisites

- Google Cloud SDK installed and authenticated
- A GCP project with Cloud Build and Cloud Run APIs enabled

### Deploy

Submit a build and deploy to Cloud Run in one step:

```bash
gcloud builds submit --config deploy/cloudbuild.yaml
```

This will:
1. Build the Docker image
2. Push it to Google Container Registry
3. Deploy to Cloud Run in `us-central1`

The deployed service URL will be printed at the end of the build output.

### Using the Cloud Run Service Spec

You can also deploy using the Knative service spec directly:

```bash
gcloud run services replace deploy/cloudrun.yaml --region us-central1
```

Replace `PROJECT_ID` in `deploy/cloudrun.yaml` with your actual GCP project ID first.

## Google Kubernetes Engine (GKE)

### Prerequisites

- A GKE cluster created and `kubectl` configured to access it
- The Docker image pushed to GCR:
  ```bash
  docker build -t gcr.io/PROJECT_ID/milnet-sso:latest .
  docker push gcr.io/PROJECT_ID/milnet-sso:latest
  ```

### Deploy

Apply all Kubernetes manifests:

```bash
kubectl apply -f deploy/k8s/
```

This creates:
- A Deployment with 3 replicas of the admin API
- A ClusterIP Service on port 80
- An Ingress for external HTTP access

Check status:

```bash
kubectl get pods -l app=milnet-sso
kubectl get ingress milnet-sso
```

The external IP from the Ingress output is where the MVP demo is accessible.

## Environment Variables

| Variable     | Default | Description                        |
|--------------|---------|------------------------------------|
| `ADMIN_PORT` | `8080`  | Port the admin server listens on   |
| `RUST_LOG`   | `info`  | Log level (trace, debug, info, warn, error) |

## Accessing the MVP Demo

- **Local**: http://localhost:8080
- **Cloud Run**: URL printed after `gcloud builds submit` completes
- **GKE**: External IP from `kubectl get ingress milnet-sso`
