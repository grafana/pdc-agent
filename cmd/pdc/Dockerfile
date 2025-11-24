FROM alpine:3.22.2
RUN apk add --no-cache --repository=http://dl-cdn.alpinelinux.org/alpine/edge/main openssh
COPY pdc /usr/bin/pdc
RUN addgroup -g 30000 pdc && adduser -G pdc -u 30000 pdc -D
RUN chown -R pdc:pdc /usr/bin/pdc
USER 30000:30000
ENTRYPOINT ["/usr/bin/pdc"]
