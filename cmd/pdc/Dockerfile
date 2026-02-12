FROM alpine:3.23@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659
RUN apk update && apk upgrade
RUN apk add openssh
COPY pdc /usr/bin/pdc
RUN addgroup -g 30000 pdc && adduser -G pdc -u 30000 pdc -D
RUN chown -R pdc:pdc /usr/bin/pdc
USER 30000:30000
ENTRYPOINT ["/usr/bin/pdc"]
