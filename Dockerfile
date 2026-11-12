FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends bash curl jq dnsutils \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 checker
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=checker:checker dashboard.py database.py security.py mailer.py provider_data.py maxmind_geo.py email_lookup.py domain_lookup.py spamhaus_domain.py ip-checker.sh ./
COPY --chown=checker:checker web ./web
# Compose may run as the host UID to read a mode-600 secrets mount. Make
# application code readable by that UID even when built from an umask-077 checkout.
# Secrets are excluded from the build context and never chmodded here.
RUN chmod -R u=rwX,go=rX /app
USER checker
EXPOSE 8080
CMD ["python3", "dashboard.py", "--host", "0.0.0.0", "--port", "8080"]
