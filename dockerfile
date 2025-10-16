FROM python:3.11-slim
WORKDIR /app
COPY zip_scanner.py /app/
RUN pip install --no-cache-dir any-deps-if-needed
ENTRYPOINT ["python","/app/zip_scanner.py"]
