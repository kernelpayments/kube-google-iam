FROM alpine:3.6

RUN apk --no-cache add \
    ca-certificates \
    iptables

ADD build/bin/linux/kube-google-iam /bin/kube-google-iam

ENTRYPOINT ["kube-google-iam"]
