FROM golang:1.25-alpine AS builder

WORKDIR /go/src/minescan

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o minescan /go/src/minescan/cmd

FROM alpine:3.22

COPY --from=builder /go/src/minescan/minescan /usr/bin/minescan

ENTRYPOINT ["/usr/bin/minescan"]