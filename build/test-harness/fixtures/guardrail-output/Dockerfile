FROM --platform=linux/amd64 docker.io/library/python@sha256:90744cff8f32887f075c47d747a173ff333e9e98801667af93c357fa9f5e28ff

ENV PIP_NO_INDEX=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_INPUT=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN install -d -m 0755 /opt/guardrail-output

COPY --chmod=0644 requirements.lock wheelhouse.sha256 verify_wheelhouse.py verify_runtime.py /opt/guardrail-output/
COPY wheelhouse/ /opt/guardrail-output/wheelhouse/

RUN python3 /opt/guardrail-output/verify_wheelhouse.py \
      /opt/guardrail-output/requirements.lock \
      /opt/guardrail-output/wheelhouse.sha256 \
      /opt/guardrail-output/wheelhouse \
 && python3 -m pip install --no-index --no-cache-dir --force-reinstall --no-deps \
      --require-hashes --only-binary=:all: \
      --find-links=/opt/guardrail-output/wheelhouse \
      -r /opt/guardrail-output/requirements.lock \
 && python3 -m pip check \
 && python3 /opt/guardrail-output/verify_runtime.py \
      /opt/guardrail-output/requirements.lock

USER 10001:10001
WORKDIR /tmp
RUN python3 /opt/guardrail-output/verify_runtime.py \
      /opt/guardrail-output/requirements.lock

CMD ["python3", "-V"]
