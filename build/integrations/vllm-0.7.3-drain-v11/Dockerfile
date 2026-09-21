FROM vllm/vllm-openai:v0.7.3@sha256:4f4037303e8c7b69439db1077bb849a0823517c0f785b894dc8e96d58ef3a0c2

LABEL org.opencontainers.image.base.name="vllm/vllm-openai:v0.7.3" \
      org.opencontainers.image.base.digest="sha256:4f4037303e8c7b69439db1077bb849a0823517c0f785b894dc8e96d58ef3a0c2" \
      org.opencontainers.image.source="https://github.com/vllm-project/vllm.git" \
      org.opencontainers.image.revision="ed6e9075d31e32c8548b480a47d1ffb77da1f54c" \
      ai.phorvex.patch-id="phorvex-vllm-0.7.3-drain-v11"

COPY Dockerfile manifest.json base-image-receipt.json verify_recipe.py vllm-0.7.3-drain-v11.patch apply_patch.py test_contract.py test_drain_contract.py /opt/phorvex-vllm-drain-v11/

RUN python3 /opt/phorvex-vllm-drain-v11/verify_recipe.py \
    && python3 /opt/phorvex-vllm-drain-v11/apply_patch.py \
        --installed \
        --receipt /opt/phorvex-vllm-drain-v11/runtime-receipt.json \
    && python3 /opt/phorvex-vllm-drain-v11/test_contract.py --installed \
    && python3 /opt/phorvex-vllm-drain-v11/test_drain_contract.py --installed
