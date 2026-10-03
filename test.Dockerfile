FROM golang:1.27

# Fail instead of silently downloading a newer toolchain: the image's Go
# version is the one under test.
ENV GOTOOLCHAIN=local

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

CMD ["./script/test.sh"]
