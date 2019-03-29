package logging

import (
	"go.uber.org/zap"
)

func New() *zap.Logger {

	logger, err := zap.NewProductionConfig().Build()
	if err != nil {
		panic(err)
	}
	return logger
}
