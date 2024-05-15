FROM golang:1.22.3

WORKDIR /app

# Копируем файлы с пакетами
COPY go.mod go.sum ./
# Устанавливаем пакеты
RUN go mod download

# Копируем все файлы
COPY ./ ./

# Компилируем
RUN CGO_ENABLED=0 GOOS=linux go build -o worker

CMD ["worker"]