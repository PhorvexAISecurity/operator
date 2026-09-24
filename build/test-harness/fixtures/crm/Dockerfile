FROM docker.io/library/python@sha256:90744cff8f32887f075c47d747a173ff333e9e98801667af93c357fa9f5e28ff

WORKDIR /app
ENV PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1

COPY --chmod=0644 app.py /app/app.py
COPY --chmod=0644 dependencies.lock.json requirements.pinned.txt verify_wheelhouse.py verify_runtime_closure.py /opt/crm/
COPY --chmod=0644 wheelhouse.sha256 /opt/crm/wheelhouse.sha256
COPY wheelhouse/ /opt/crm/wheelhouse/

RUN chmod 0755 /opt/crm \
 && python /opt/crm/verify_wheelhouse.py /opt/crm/requirements.pinned.txt /opt/crm/wheelhouse.sha256 /opt/crm/wheelhouse \
 && python -m pip install --no-index --no-deps --find-links=/opt/crm/wheelhouse -r /opt/crm/requirements.pinned.txt

USER 65532:65532
RUN python /opt/crm/verify_runtime_closure.py /opt/crm/dependencies.lock.json /app/app.py

CMD ["uvicorn", "app:app", "--host", "127.0.0.1", "--port", "8080"]
