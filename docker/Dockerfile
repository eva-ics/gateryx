FROM --platform=linux/${TARGETARCH} debian:bookworm-slim
ARG BUILDPLATFORM
ARG TARGETARCH

RUN echo "Building on platform: ${BUILDPLATFORM}"
RUN echo "Building for architecture: ${TARGETARCH}"

COPY ./_build/gateryx-client-${TARGETARCH}.deb /tmp/
COPY ./_build/gateryx-server-${TARGETARCH}.deb /tmp/
RUN apt-get update && apt-get install -y libssl3 ca-certificates \
  /tmp/gateryx-client-${TARGETARCH}.deb /tmp/gateryx-server-${TARGETARCH}.deb && \
    rm -f /tmp/*.deb
ENTRYPOINT ["/usr/sbin/gateryx-server"]
