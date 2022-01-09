FROM python:3.9-slim-buster

WORKDIR /guard

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY . .

ENTRYPOINT ["python"]
CMD ["/guard/app/app.py"]