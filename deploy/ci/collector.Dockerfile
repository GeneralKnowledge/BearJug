# CI only: the collector, packaged as a container so the deployment tests can
# run it on a separate network from the sensor (and stop it to simulate an
# outage). Production collectors are deployed by deploy/ansible/collector.yml.
FROM python:3.12-slim-bookworm
COPY pyproject.toml README.md LICENSE NOTICE /src/
COPY src /src/src
RUN pip install --no-cache-dir /src
