package database

import (
	"context"
	"web-scan-worker/db"
)

type PrismaDB struct {
	Client  *db.PrismaClient
	Context context.Context
}

var PClient = &PrismaDB{}

func ConnectDB() (*PrismaDB, error) {
	client := db.NewClient()
	if err := client.Prisma.Connect(); err != nil {
		return nil, err
	}

	PClient.Client = client
	PClient.Context = context.Background()
	return PClient, nil

}
