package authara

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const redisConnectTimeout = 5 * time.Second

type redisRevocationStore struct {
	client *redis.Client
}

func newRedisRevocationStore(cfg RedisConfig) (*redisRevocationStore, error) {
	cfg.Host = strings.TrimSpace(cfg.Host)
	if cfg.Host == "" {
		cfg.Host = "localhost"
	}
	if cfg.Port == 0 {
		cfg.Port = 6379
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return nil, fmt.Errorf("authara: Redis port must be between 1 and 65535, got %d", cfg.Port)
	}
	if cfg.DB < 0 {
		return nil, fmt.Errorf("authara: Redis DB must be >= 0, got %d", cfg.DB)
	}

	client := redis.NewClient(&redis.Options{
		Addr:     net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port)),
		Password: cfg.Password,
		DB:       cfg.DB,
	})
	ctx, cancel := context.WithTimeout(context.Background(), redisConnectTimeout)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		if closeErr := client.Close(); closeErr != nil {
			return nil, fmt.Errorf("authara: connect to Redis: %w; close Redis: %v", err, closeErr)
		}
		return nil, fmt.Errorf("authara: connect to Redis: %w", err)
	}
	return &redisRevocationStore{client: client}, nil
}

func (r *redisRevocationStore) GetMany(ctx context.Context, keys ...string) ([][]byte, error) {
	values, err := r.client.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, fmt.Errorf("Redis MGET: %w", err)
	}

	out := make([][]byte, len(values))
	for i, value := range values {
		if value == nil {
			continue
		}
		stringValue, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("Redis MGET: unexpected value type %T", value)
		}
		out[i] = []byte(stringValue)
	}
	return out, nil
}

func (r *redisRevocationStore) Close() error {
	if r == nil || r.client == nil {
		return nil
	}
	if err := r.client.Close(); err != nil {
		return fmt.Errorf("authara: close Redis: %w", err)
	}
	return nil
}
