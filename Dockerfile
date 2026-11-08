FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -buildid=" -o /c2dip ./cmd/c2dip \
    && /c2dip --version

FROM scratch AS binary
COPY --from=build /c2dip /c2dip
