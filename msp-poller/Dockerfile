FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Run with unbuffered output for real-time logging
CMD ["python", "-u", "msp_poller.py"]
