FROM python:3.13-slim@sha256:ae14d4ce8771606477a81446e7ef429edd6762305fc50c84507c1041fa8285d1
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --disable-pip-version-check --require-hashes --only-binary :all: -r /app/requirements.txt
COPY app.py /app/app.py
WORKDIR /app
USER 65534:65534
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--no-access-log", "--no-server-header"]
