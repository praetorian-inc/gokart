# syntax=docker/dockerfile:1

FROM golang:1.19-alpine
WORKDIR /app
COPY . /app/
RUN go build -o /gokart

ENTRYPOINT [ "/gokart" ]