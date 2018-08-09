FROM alpine:3.7
WORKDIR /srv/xforum
COPY ./xforum ./xforum
COPY ./static ./static
RUN apk --no-cache add ca-certificates && update-ca-certificates &&  chmod u+x ./xforum
ENTRYPOINT [ "./xforum", "-config=./config/config.yaml" ]
