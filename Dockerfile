FROM golang:latest as builder
RUN mkdir /app
ADD . /app
WORKDIR /app
RUN go mod tidy
RUN go build -o main .

FROM debian:bookworm-slim
RUN mkdir /app
COPY --from=builder /app/main /app
CMD ["/app/main"]