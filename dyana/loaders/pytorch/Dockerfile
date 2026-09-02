FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y build-essential
COPY dyana.py .
COPY dyana-requirements.txt .
RUN pip install --no-cache-dir --root-user-action=ignore -r dyana-requirements.txt

COPY main.py .

ENTRYPOINT ["python3", "-W", "ignore", "main.py"]
