FROM alpine

WORKDIR /opt/bin

ENV CONFIG_FILE_PATH=/etc/app/config.yml
COPY config/default.yml /etc/app/config.yml

COPY ./dist/app .

ENTRYPOINT ["./app"]
