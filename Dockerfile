# IPFindX v4 — Advanced IP Intelligence Toolkit
FROM python:3.12-slim

# ping/traceroute need raw-socket privileges at runtime (use --cap-add=NET_RAW)
RUN apt-get update \
    && apt-get install -y --no-install-recommends iputils-ping traceroute \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ipfindx/ ./ipfindx/
COPY ipfindx.py pyproject.toml README.md ./
RUN pip install --no-cache-dir .

# non-root user
RUN useradd -m scanner
USER scanner

ENTRYPOINT ["ipfindx"]
CMD ["--help"]
