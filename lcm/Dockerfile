# lcm + lcmctl in one small image.
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ ./cmd/lcm ./cmd/lcmctl

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ /usr/local/bin/
ENV LISTEN_ADDR=:8080 DATA_DIR=/data
USER nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/lcm"]
