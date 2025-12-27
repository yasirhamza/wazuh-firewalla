FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY threat_intel.py .

CMD ["python", "-u", "threat_intel.py"]
