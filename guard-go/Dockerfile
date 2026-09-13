FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /guard-go .

# WSL kiểm chứng: distroless static:nonroot + volume docker root-owned khiến
# guard không ghi được sealed-used.json -> single-use không burn (lần 2 vẫn 200).
# Dùng alpine + user guard riêng + chown store dir để ghi được volume.
FROM alpine:3.21
RUN addgroup -S guard && adduser -S guard -G guard \
 && mkdir -p /var/lib/sr8 && chown -R guard:guard /var/lib/sr8
COPY --from=build /guard-go /guard-go
USER guard
ENTRYPOINT ["/guard-go"]
