FROM vllm/vllm-openai:v0.7.3@sha256:4f4039589120397ce64231883a1b8a78e7bc83b2a8999c5951af0bd72f6eea79

LABEL org.opencontainers.image.base.name="vllm/vllm-openai:v0.7.3" \
      org.opencontainers.image.base.digest="sha256:4f4039589120397ce64231883a1b8a78e7bc83b2a8999c5951af0bd72f6eea79" \
      org.opencontainers.image.source="https://github.com/vllm-project/vllm.git" \
      org.opencontainers.image.revision="ed6e9075d31e32c8548b480a47d1ffb77da1f54c" \
      ai.phorvex.patch-id="phorvex-vllm-0.7.3-reset-ack-v1"

COPY manifest.json vllm-0.7.3-reset-ack.patch apply_patch.py test_contract.py /opt/phorvex-vllm-reset-ack/

RUN python3 /opt/phorvex-vllm-reset-ack/apply_patch.py \
        --installed \
        --receipt /opt/phorvex-vllm-reset-ack/runtime-receipt.json \
    && python3 /opt/phorvex-vllm-reset-ack/test_contract.py --installed
