#TAG=12-1-2023
#PROJECT=cerit
FROM golang:alpine3.16
RUN apk update && apk add --no-cache bash vim procps
WORKDIR /home
COPY additional_files/env-injector/main.go ./
COPY additional_files/env-injector/go.mod ./
COPY additional_files/env-injector/go.sum ./
RUN CGO_ENABLED=0 go build -o /usr/local/bin/env-injector-mw
RUN adduser --disabled-password --no-create-home --uid 1000 envinj
RUN chmod a+rwx /usr/local/bin && chmod a+rx /usr/local/bin/env-injector-mw
WORKDIR /home

USER 1000
ENTRYPOINT ["/usr/local/bin/env-injector-mw"]
