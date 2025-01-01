FROM python:3.12.8-alpine3.21

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD [ "uvicorn", "app:app" ,"--host", "0.0.0.0", "--port", "8000" ]