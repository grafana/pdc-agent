FROM alpine:3.17
RUN apk add --no-cache openssh
COPY pdc /usr/bin/pdc
RUN addgroup -g 30000 pdc && adduser -G pdc -u 30000 pdc -D
USER 30000:30000
ENTRYPOINT ["/usr/bin/pdc"]
