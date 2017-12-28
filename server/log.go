package server

import (
	"context"

	"github.com/sirupsen/logrus"
)

type key int

const loggerKey key = 0

func ContextWithLogger(ctx context.Context, logger *logrus.Entry) context.Context {
	ctx = context.WithValue(ctx, loggerKey, logger)
	return ctx
}
func LoggerFromContext(ctx context.Context) *logrus.Entry {
	res, _ := ctx.Value(loggerKey).(*logrus.Entry)
	return res
}
