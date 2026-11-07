FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends bash curl jq dnsutils \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 checker
WORKDIR /app
COPY --chown=checker:checker dashboard.py ip-checker.sh ./
COPY --chown=checker:checker web ./web
USER checker
EXPOSE 8080
CMD ["python3", "dashboard.py", "--host", "0.0.0.0", "--port", "8080"]
