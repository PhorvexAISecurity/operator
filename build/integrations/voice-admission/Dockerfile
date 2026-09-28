FROM --platform=linux/amd64 753556437180.dkr.ecr.us-east-2.amazonaws.com/pipecat-voice@sha256:c9c598c406ed517eebf17f92a36863b39a15d9a7875cfcb2710f7b084dd539b8

COPY requirements.lock overlay_install.py /opt/admission-sdk/
COPY wheelhouse /opt/admission-sdk/wheelhouse
RUN python3 -B /opt/admission-sdk/overlay_install.py && rm -rf /opt/admission-sdk/wheelhouse

# The Deployment mounts reviewed legacy /app bytes and separate wrapper bytes;
# this overlay deliberately preserves the base command, environment and user.
