FROM alpine:3.17
RUN apk add --no-cache openssh
COPY pdc /usr/bin/pdc

ENTRYPOINT ["/usr/bin/pdc"]
