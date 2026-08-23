FROM golang:1.27-alpine AS build
WORKDIR /src
COPY . .
ARG VERSION=0.10.1
ARG COMMIT=container
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags "-s -w -X github.com/Bluezly/CIRadar/internal/version.Version=${VERSION} -X github.com/Bluezly/CIRadar/internal/version.Commit=${COMMIT} -X github.com/Bluezly/CIRadar/internal/version.BuildDate=${BUILD_DATE}" -o /out/ciradar ./cmd/ciradar

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/ciradar /app/ciradar
VOLUME ["/app/.ciradar"]
EXPOSE 8787
USER nonroot:nonroot
ENTRYPOINT ["/app/ciradar"]
CMD ["serve", "--config", "/app/ciradar.json"]
