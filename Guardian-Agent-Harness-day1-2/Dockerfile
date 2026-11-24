FROM python:3.13-slim
WORKDIR /app
COPY guardian /app/guardian
COPY examples /app/examples
RUN groupadd --gid 10001 guardian && useradd --uid 10001 --gid guardian --no-create-home guardian
USER 10001:10001
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "-m", "guardian", "--data", "/data"]
CMD ["eval"]
