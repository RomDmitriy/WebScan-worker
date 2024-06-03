FROM golang:1.22.3

WORKDIR /app

# Копируем файлы с пакетами
COPY go.mod go.sum ./
# Устанавливаем пакеты
RUN go mod download

# Копируем все файлы
COPY ./ ./

# Компилируем Prisma
ENV DATABASE_URL=postgresql://postgres:postgres@postgres:5432/webscan?schema=public
RUN go run github.com/steebchen/prisma-client-go generate

# Компилируем
RUN CGO_ENABLED=0 GOOS=linux go build -o worker

EXPOSE 1323

CMD ["./worker"]