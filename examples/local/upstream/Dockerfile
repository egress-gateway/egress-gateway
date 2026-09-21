FROM golang:1.26.7-bookworm AS build
WORKDIR /src
COPY examples/local/upstream/main.go .
RUN CGO_ENABLED=0 go build -trimpath -o /upstream main.go
FROM scratch
COPY --from=build /upstream /upstream
USER 1337:1337
ENTRYPOINT ["/upstream"]
