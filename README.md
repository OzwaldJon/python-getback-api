# python-getback-api

## Run locally with Docker Compose

```bash
docker compose up --build
```

API:

- `POST /` (accepts `application/json` or `text/plain`) returns `{"id": "<uuid>"}`
- `GET /{uuid}` returns stored payload (404 if not found/expired)
- `POST /{uuid}` updates stored payload (404 if not found/expired)

Swagger:

- `http://localhost:8000/docs`

## GitHub Actions: build & push Docker image

A workflow is included at `.github/workflows/docker-image.yml`.

### Where the image is pushed

- Registry: `ghcr.io`
- Image name: `ghcr.io/<owner>/<repo>`

Example:

```bash
docker pull ghcr.io/my-user/python-getback-api:latest
```

### Requirements

- The repository must be on GitHub.
- In GitHub, ensure Actions can publish packages:

`Settings -> Actions -> General -> Workflow permissions -> Read and write permissions`

(Also ensure your package visibility/permissions allow pulls as you intend.)

### Tags

The workflow publishes tags based on:

- `main` branch (includes a `latest`-like tag derived from branch metadata)
- git tags like `v1.0.0`
- commit SHA tags
