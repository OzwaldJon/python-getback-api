# python-getback-api

Small API to store short payloads for 48 hours and retrieve them later by UUID.

## Run locally with Docker Compose

```bash
docker compose up --build
```

Swagger:

- `http://localhost:8000/docs`

## Features

### TTL storage (48h)

- Items are stored for **48 hours** from creation/update.
- Expired items are deleted automatically.

### Accepted payloads

Only these `Content-Type` values are accepted:

- `application/json`
- `text/plain`

### Endpoints

#### Create

- `POST /`
- Body: `application/json` or `text/plain`
- Returns: `{"id": "<uuid>"}`

#### Read

- `GET /{uuid}`
- Returns: the stored payload with its original `Content-Type`
- If uuid does not exist (or is expired): `404`

#### Update

- `POST /{uuid}`
- Body: `application/json` or `text/plain`
- If uuid does not exist (or is expired): `404`

### Optional encryption with passphrase

If you include the request header `X-Passphrase`, the API will store the payload **encrypted at rest**.

- Encryption: AES-GCM
- Key derivation: PBKDF2-HMAC-SHA256 with a per-item random salt

Behavior:

- If an item was created encrypted, reading/updating it requires the same `X-Passphrase`.
- If `X-Passphrase` is missing or incorrect, the API returns **404** (to not reveal existence).
- Responses preserve the original `Content-Type`.

#### Encryption examples

Create encrypted JSON:

```bash
curl -X POST http://localhost:8000/ \
  -H "Content-Type: application/json" \
  -H "X-Passphrase: mysecret" \
  -d '{"hello":"world"}'
```

Read encrypted item:

```bash
curl http://localhost:8000/<uuid> \
  -H "X-Passphrase: mysecret"
```

Update encrypted item:

```bash
curl -X POST http://localhost:8000/<uuid> \
  -H "Content-Type: text/plain" \
  -H "X-Passphrase: mysecret" \
  -d "new payload"
```

Convert an existing plaintext item to encrypted (send `X-Passphrase` on update):

```bash
curl -X POST http://localhost:8000/<uuid> \
  -H "Content-Type: application/json" \
  -H "X-Passphrase: mysecret" \
  -d '{"now":"encrypted"}'
```

## API (quick summary)

- `POST /` (accepts `application/json` or `text/plain`) returns `{"id": "<uuid>"}`
- `GET /{uuid}` returns stored payload (404 if not found/expired)
- `POST /{uuid}` updates stored payload (404 if not found/expired)

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
