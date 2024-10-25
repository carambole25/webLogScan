FROM python:3.9-slim

WORKDIR /app

COPY wls.py /app/

RUN apt-get update && apt-get install -y ufw && apt-get clean

ENTRYPOINT ["python3", "wls.py"]
