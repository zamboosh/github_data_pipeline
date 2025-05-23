# GitHub Data Pipeline

A GitHub data pipeline and policy evaluation service with a gRPC API. This system extracts repository metadata and access data from GitHub organizations, processes it into a normalized schema, stores it efficiently, and provides policy-based querying to assess data quality and detect access pattern issues.

## Key Features

- Data extraction from GitHub API
- Storage in DuckDB for efficient queries
- Policy evaluation engine - CEL
- gRPC API service
- Containerized deployment

## Usage

```bash
# Start the service
docker compose up --build -d
```

## Environment Variables

- `GITHUB_TOKEN`: GitHub API token
- `GITHUB_ORG`: GitHub organization name
- `STORAGE_TYPE`: Storage backend (duckdb, jsonl)
- `STORAGE_PATH`: Path to storage file
- `GRPC_SERVER_PORT`: Port for gRPC server
- `LOG_LEVEL`: Logging level

## gRPC Examples

### Python Client

```bash
docker exec -it github-pipeline bash
```

get list of repositories in organization:
```bash
uv run client_example.py list-repos
```

get access to repo:
```bash
uv run client_example.py get-access <YOUR-REPO-NAME>
```

get list of available rules:
```bash
uv run client_example.py list-rules
```
