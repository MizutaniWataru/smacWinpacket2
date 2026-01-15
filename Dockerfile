FROM docker.io/alpine:latest

RUN apk update && apk upgrade \
 && apk add --no-cache python3 tzdata

ENV PYTHONUNBUFFERED=1
