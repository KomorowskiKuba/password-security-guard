FROM python:3.9-slim-buster

WORKDIR /app
COPY . .

RUN pip3 install --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host=files.pythonhosted.org --no-cache-dir -r requirements.txt

ENTRYPOINT ["python"]
CMD ["app.py"]
