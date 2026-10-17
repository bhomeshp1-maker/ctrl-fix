FROM python:3.9-slim

WORKDIR /app

# Zero-knowledge secret sharing server - zero external dependencies needed!
COPY server.py ./
COPY static/ ./static/

ENV PORT=8000
EXPOSE 8000

CMD ["python3", "server.py"]
