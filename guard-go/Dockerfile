FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /guard-go .

FROM gcr.io/distroless/static:nonroot
COPY --from=build /guard-go /guard-go
USER nonroot
ENTRYPOINT ["/guard-go"]
