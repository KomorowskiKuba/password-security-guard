FROM python:3.9-slim-buster

#WORKDIR /guard

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY . .

WORKDIR /app

#CMD ["export", "FLASK_APP=app"]
#CMD ["flask", "run", "--host", "0.0.0.0"]
CMD ["gunicorn", "--certfile", "certificates/cert.pem", "--keyfile", "certificates/key.pem", "-w", "4", "--bind", "0.0.0.0:5000", "app:app"]
#CMD ["python", "/app/app.py"]