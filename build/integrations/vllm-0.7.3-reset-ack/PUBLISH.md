# Publishing the reset acknowledgement derivative

After the recipe is reviewed and merged to `main`, dispatch **Publish vLLM reset acknowledgement image** on the `main` ref. The self-hosted job verifies the pinned recipe, builds only this directory for `linux/amd64`, and pushes to the existing `phorvex` ECR repository as `vllm-reset-ack-<full main commit SHA>`. It refuses an existing tag and does not deploy or change any serving configuration.

The run artifact `vllm-reset-ack-publish-<SHA>` contains the pushed digest, digest reference, base image, and SHA-256 values for every Dockerfile `COPY` source. Use the digest reference when separately reviewing a deployment change. A green publication run establishes the image build and push only; runtime response behavior still needs its own test.
