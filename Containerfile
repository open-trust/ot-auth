FROM alpine

WORKDIR /opt/bin

ENV CONFIG_FILE_PATH=/etc/app/config.yaml
COPY config/default.yaml /etc/app/config.yaml

COPY ./dist/ot-auth .

ENTRYPOINT ["./ot-auth"]
