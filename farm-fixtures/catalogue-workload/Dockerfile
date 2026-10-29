# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM --platform=linux/amd64 docker.io/library/python:3.12.7-slim-bookworm@sha256:60d9996b6a8a3689d36db740b49f4327be3be09a21122bd02fb8895abb38b50d
ARG SOURCE_DATE_EPOCH
RUN --mount=type=bind,source=farm-fixtures/catalogue-workload,target=/fixture,ro \
    case "${SOURCE_DATE_EPOCH}" in ''|*[!0-9]*) echo "SOURCE_DATE_EPOCH must be an unsigned integer" >&2; exit 1;; esac && \
    install -d -o 0 -g 0 -m 0755 /opt /opt/catalogue /usr/local/bin && \
    install -o 0 -g 0 -m 0555 /fixture/server.py /opt/catalogue/server.py && \
    install -o 0 -g 0 -m 0555 /fixture/curl /usr/local/bin/curl && \
    touch -d "@${SOURCE_DATE_EPOCH}" /opt /opt/catalogue /opt/catalogue/server.py \
        /usr /usr/local /usr/local/bin /usr/local/bin/curl
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["python3", "-I", "/opt/catalogue/server.py"]
