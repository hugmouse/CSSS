FROM golang:1.24.1-alpine3.21 AS builder

WORKDIR /app
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
ENV GOCACHE=/root/.cache/go-build
RUN --mount=type=cache,target="/root/.cache/go-build" go generate
RUN --mount=type=cache,target="/root/.cache/go-build" go build -o /application main.go

FROM alpine:3.21.3

COPY --from=builder /application /application
EXPOSE 8080
ENTRYPOINT ["/application"]