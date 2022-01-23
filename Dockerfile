FROM python:3.9-slim-buster

#WORKDIR /guard

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY . .

WORKDIR /app

CMD ["gunicorn", "--certfile", "certificates/cert.pem", "--keyfile", "certificates/key.pem", "-w", "1", "-t", "4", "--bind", "0.0.0.0:5000", "app:app"]