FROM python:3.11-slim

WORKDIR /app

# Install uv directly - no system packages needed
RUN pip install --no-cache-dir uv

# Copy project files
COPY . .

# Set up directories and package
RUN mkdir -p data logs github_data_pipeline/proto

# Install the package and dependencies
RUN uv pip install --system --no-cache -e .

# Generate gRPC code
RUN python -m grpc_tools.protoc -I./proto \
    --python_out=. --grpc_python_out=. ./proto/github_service.proto \
    && cp ./github_service_pb2.py ./github_service_pb2_grpc.py github_data_pipeline/proto/

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    STORAGE_TYPE=duckdb \
    STORAGE_PATH=data/github_data.db \
    GRPC_SERVER_PORT=50051 \
    LOG_LEVEL=INFO

# Expose port and set entrypoint
EXPOSE 50051
ENTRYPOINT ["python", "main.py"]
CMD ["serve"]