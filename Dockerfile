FROM golang:1.17.0-alpine3.14 as builder
WORKDIR /app
COPY . /app/
RUN CGO_ENABLED=0 go build -o /gokart && \
    adduser -D -g '' gokart

FROM alpine:3.14.2
ENV HOME=/opt/gokart
ENV BIN=/opt/gokart/bin
ENV PATH=${BIN}:${PATH}
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /gokart ${BIN}/
RUN mkdir -p ${BIN} && \
    echo -e "#!/bin/sh -e\nexec \"\$@\"" > ${BIN}/entrypoint.sh && \
    chmod +x ${BIN}/entrypoint.sh
USER gokart
ENTRYPOINT ["entrypoint.sh"]
CMD ["gokart"]
