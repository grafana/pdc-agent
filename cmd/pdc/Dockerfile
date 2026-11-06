FROM alpine:3.24@sha256:3f4d6b32e26703c6082839234f43769d5046b3ac7c910033911d1e71d8cd630a
RUN apk update && apk upgrade
RUN apk add openssh
COPY pdc /usr/bin/pdc
RUN addgroup -g 30000 pdc && adduser -G pdc -u 30000 pdc -D
RUN chown -R pdc:pdc /usr/bin/pdc
USER 30000:30000
ENTRYPOINT ["/usr/bin/pdc"]
