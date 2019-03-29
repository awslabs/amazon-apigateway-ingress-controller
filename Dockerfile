# Build the manager binary
FROM golang:1.12.1-alpine3.9 as builder

# Copy in the go src
WORKDIR /go/src/github.com/awslabs/amazon-apigateway-ingress-controller
COPY pkg/    pkg/
COPY cmd/    cmd/
COPY vendor/ vendor/

# Build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o manager github.com/awslabs/amazon-apigateway-ingress-controller/cmd/manager

# Copy the controller-manager into a thin image
FROM alpine:3.9
RUN apk update && apk add ca-certificates && rm -rf /var/cache/apk/*
WORKDIR /
COPY --from=builder /go/src/github.com/awslabs/amazon-apigateway-ingress-controller/manager .
ENTRYPOINT ["/manager"]
