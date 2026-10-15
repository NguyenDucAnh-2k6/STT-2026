FROM python:3.12-slim
ENV DEBIAN_FRONTEND=noninteractive PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends tshark && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir pandas pyarrow scikit-learn psutil paho-mqtt python-dotenv cryptography
WORKDIR /app
# Copy only source: no host credentials, datasets, models or captures.
COPY ml_engine/__init__.py ml_engine/__init__.py
COPY ml_engine/config/ ml_engine/config/
COPY ml_engine/preprocessing/ ml_engine/preprocessing/
COPY data_lake/*.py data_lake/
COPY firmware/host_probe/*.py firmware/host_probe/
COPY firmware/simulator/*.py firmware/simulator/
COPY digital_twin/experiment_service.py digital_twin/experiment_service.py
COPY digital_twin/lab/ digital_twin/lab/
ENTRYPOINT ["python", "-m", "digital_twin.lab.container_worker"]
