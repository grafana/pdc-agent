FROM alpine:3.17
RUN apk add --update openssh && \
    rm -rf /var/cache/apk/*
ENTRYPOINT ["/usr/bin/pdc"]
COPY pdc /usr/bin/pdc
