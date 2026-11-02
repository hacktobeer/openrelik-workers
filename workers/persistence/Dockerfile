# Use the official Docker Hub Ubuntu base image
FROM ubuntu:24.04

# Prevent debconf interactive prompts
RUN echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections

# Install system dependencies for disk image mounting and file analysis
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    sudo \
    fdisk \
    util-linux \
    qemu-utils \
    ntfs-3g \
    ewf-tools \
  && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /openrelik

# Install uv from official container image
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Copy dependency specifications
COPY .python-version uv.lock pyproject.toml ./

# Install dependencies using locked versions
RUN uv sync --locked --no-install-project --no-dev

# Copy worker application source
COPY . ./

# Install project into virtualenv
RUN uv sync --locked --no-dev

# Set PATH to use virtual environment binaries
ENV PATH="/openrelik/.venv/bin:$PATH"

# Default Celery execution entrypoint
CMD ["celery", "--app=src.tasks", "worker", "--task-events", "--concurrency=1", "--loglevel=INFO"]
