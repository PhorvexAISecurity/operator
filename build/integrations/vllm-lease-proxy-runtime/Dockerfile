FROM --platform=linux/amd64 docker.io/library/python@sha256:90744cff8f32887f075c47d747a173ff333e9e98801667af93c357fa9f5e28ff

ENV PIP_NO_INDEX=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_INPUT=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HF_HOME=/tmp/hf

RUN install -d -m 0755 /opt/phorvex-lease-proxy /src
COPY --chmod=0644 requirements.lock wheelhouse.sha256 verify_wheelhouse.py verify_runtime.py /opt/phorvex-lease-proxy/
COPY wheelhouse/ /opt/phorvex-lease-proxy/wheelhouse/

RUN python3 /opt/phorvex-lease-proxy/verify_wheelhouse.py \
      /opt/phorvex-lease-proxy/requirements.lock \
      /opt/phorvex-lease-proxy/wheelhouse.sha256 \
      /opt/phorvex-lease-proxy/wheelhouse \
 && python3 -m pip install --no-index --no-cache-dir --no-deps --force-reinstall \
      --require-hashes --only-binary=:all: \
      --find-links=/opt/phorvex-lease-proxy/wheelhouse \
      -r /opt/phorvex-lease-proxy/requirements.lock \
 && python3 -m pip check \
 && python3 /opt/phorvex-lease-proxy/verify_runtime.py \
      /opt/phorvex-lease-proxy/requirements.lock

USER 10001:10001
WORKDIR /src
RUN python3 /opt/phorvex-lease-proxy/verify_runtime.py \
      /opt/phorvex-lease-proxy/requirements.lock

EXPOSE 8000 8443
CMD ["python3", "-B", "/src/dual_server.py"]
