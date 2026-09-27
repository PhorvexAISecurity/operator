FROM --platform=linux/amd64 docker.io/library/python@sha256:90744cff8f32887f075c47d747a173ff333e9e98801667af93c357fa9f5e28ff

ENV PIP_NO_INDEX=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_INPUT=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN install -d -m 0755 /opt/voice-mcp /app

COPY --chmod=0644 requirements.lock wheelhouse.sha256 verify_wheelhouse.py verify_runtime.py server.py test_server.py /opt/voice-mcp/
COPY wheelhouse/ /opt/voice-mcp/wheelhouse/

RUN python3 /opt/voice-mcp/verify_wheelhouse.py \
      /opt/voice-mcp/requirements.lock \
      /opt/voice-mcp/wheelhouse.sha256 \
      /opt/voice-mcp/wheelhouse \
 && python3 -m pip install --no-index --no-cache-dir --no-deps --force-reinstall \
      --require-hashes --only-binary=:all: \
      --find-links=/opt/voice-mcp/wheelhouse \
      -r /opt/voice-mcp/requirements.lock \
 && python3 -m pip check \
 && cd /opt/voice-mcp \
 && python3 verify_runtime.py requirements.lock \
 && python3 -m unittest test_server.py

USER 10001:10001
WORKDIR /opt/voice-mcp
RUN python3 verify_runtime.py requirements.lock \
 && python3 -m unittest test_server.py

WORKDIR /app
EXPOSE 8000
CMD ["python3", "-B", "/app/server.py"]
