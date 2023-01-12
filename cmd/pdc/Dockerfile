FROM alpine:3.17
RUN apk add --update openssh && \
    rm -rf /var/cache/apk/*
COPY pdc /usr/bin/pdc

ENTRYPOINT ["/usr/bin/pdc"]
