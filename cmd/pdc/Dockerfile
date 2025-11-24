FROM alpine:3.22.2
RUN apk update && apk upgrade && apk add --no-cache openssh
COPY pdc /usr/bin/pdc
RUN addgroup -g 30000 pdc && adduser -G pdc -u 30000 pdc -D
RUN chown -R pdc:pdc /usr/bin/pdc
USER 30000:30000
ENTRYPOINT ["/usr/bin/pdc"]
