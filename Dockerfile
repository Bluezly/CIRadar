FROM golang:1.26.5-alpine AS build
WORKDIR /src
COPY . .
ARG VERSION=1.3.2-oss-rc.6-hardening-fix.3
ARG COMMIT=container
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags "-s -w -X ciradar/internal/version.Version=${VERSION} -X ciradar/internal/version.Commit=${COMMIT} -X ciradar/internal/version.BuildDate=${BUILD_DATE}" -o /out/ciradar ./cmd/ciradar

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/ciradar /app/ciradar
VOLUME ["/app/.ciradar"]
EXPOSE 8787
USER nonroot:nonroot
ENTRYPOINT ["/app/ciradar"]
CMD ["serve", "--config", "/app/ciradar.json"]
