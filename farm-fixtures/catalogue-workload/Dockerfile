# syntax=docker/dockerfile:1.7
FROM --platform=linux/amd64 docker.io/library/python:3.12.7-slim-bookworm@sha256:60d9996b6a8a3689d36db740b49f4327be3be09a21122bd02fb8895abb38b50d
COPY --chmod=0555 farm-fixtures/catalogue-workload/server.py /opt/catalogue/server.py
COPY --chmod=0555 farm-fixtures/catalogue-workload/curl /usr/local/bin/curl
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["python3", "-I", "/opt/catalogue/server.py"]
