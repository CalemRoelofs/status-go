package market

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/event"

	"github.com/status-im/status-go/circuitbreaker"
	"github.com/status-im/status-go/logutils"
	"github.com/status-im/status-go/services/wallet/thirdparty"
	"github.com/status-im/status-go/services/wallet/token"
	"github.com/status-im/status-go/services/wallet/walletevent"
)

const (
	EventMarketStatusChanged walletevent.EventType = "wallet-market-status-changed"
)

const (
	MaxAgeInSecondsForFresh    int64 = -1
	MaxAgeInSecondsForBalances int64 = 60
)

type DataPoint struct {
	Price     float64
	UpdatedAt int64
}

type MarketValuesSnapshot struct {
	MarketValues thirdparty.TokenMarketValues
	UpdatedAt    int64
}

type DataPerTokenAndCurrency = map[string]map[string]DataPoint
type MarketValuesPerCurrencyAndToken = map[string]map[string]MarketValuesSnapshot
type TokenMarketCache MarketValuesPerCurrencyAndToken
type TokenPriceCache DataPerTokenAndCurrency

type Manager struct {
	tokenManager    *token.Manager
	feed            *event.Feed
	priceCache      MarketCache[TokenPriceCache]
	marketCache     MarketCache[TokenMarketCache]
	IsConnected     bool
	LastCheckedAt   int64
	IsConnectedLock sync.RWMutex
	circuitbreaker  *circuitbreaker.CircuitBreaker
	providers       []thirdparty.MarketDataProvider
}

func NewManager(providers []thirdparty.MarketDataProvider, tokenManager *token.Manager, feed *event.Feed) *Manager {
	cb := circuitbreaker.NewCircuitBreaker(circuitbreaker.Config{
		Timeout:               60000,
		MaxConcurrentRequests: 100,
		SleepWindow:           300000,
		ErrorPercentThreshold: 25,
	})

	return &Manager{
		tokenManager:   tokenManager,
		feed:           feed,
		priceCache:     *NewCache(make(TokenPriceCache)),
		marketCache:    *NewCache(make(TokenMarketCache)),
		IsConnected:    true,
		LastCheckedAt:  time.Now().Unix(),
		circuitbreaker: cb,
		providers:      providers,
	}
}

func (pm *Manager) setIsConnected(value bool) {
	pm.IsConnectedLock.Lock()
	defer pm.IsConnectedLock.Unlock()
	pm.LastCheckedAt = time.Now().Unix()
	if value != pm.IsConnected {
		message := "down"
		if value {
			message = "up"
		}
		pm.feed.Send(walletevent.Event{
			Type:     EventMarketStatusChanged,
			Accounts: []common.Address{},
			Message:  message,
			At:       time.Now().Unix(),
		})
	}
	pm.IsConnected = value
}

func (pm *Manager) makeCall(providers []thirdparty.MarketDataProvider, f func(provider thirdparty.MarketDataProvider) (interface{}, error)) (interface{}, error) {
	cmd := circuitbreaker.NewCommand(context.Background(), nil)
	for _, provider := range providers {
		provider := provider
		// FIXME: we might want a different circuitName. See other uses of NewFunctor
		circuitName := provider.ID()
		cmd.Add(circuitbreaker.NewFunctor(func() ([]interface{}, error) {
			result, err := f(provider)
			return []interface{}{result}, err
		}, circuitName, provider.ID()))
	}

	result := pm.circuitbreaker.Execute(cmd)
	pm.setIsConnected(result.Error() == nil)

	if result.Error() != nil {
		logutils.ZapLogger().Error("Error fetching prices", zap.Error(result.Error()))
		return nil, result.Error()
	}

	return result.Result()[0], nil
}

func (pm *Manager) FetchHistoricalDailyPrices(tokenGroupKey string, currency string, limit int, allData bool, aggregate int) ([]thirdparty.HistoricalPrice, error) {
	result, err := pm.makeCall(pm.providers, func(provider thirdparty.MarketDataProvider) (interface{}, error) {
		return provider.FetchHistoricalDailyPrices(tokenGroupKey, currency, limit, allData, aggregate)
	})

	if err != nil {
		logutils.ZapLogger().Error("Error fetching prices", zap.Error(err))
		return nil, err
	}

	prices := result.([]thirdparty.HistoricalPrice)
	return prices, nil
}

func (pm *Manager) FetchHistoricalHourlyPrices(tokenGroupKey string, currency string, limit int, aggregate int) ([]thirdparty.HistoricalPrice, error) {
	result, err := pm.makeCall(pm.providers, func(provider thirdparty.MarketDataProvider) (interface{}, error) {
		return provider.FetchHistoricalHourlyPrices(tokenGroupKey, currency, limit, aggregate)
	})

	if err != nil {
		logutils.ZapLogger().Error("Error fetching prices", zap.Error(err))
		return nil, err
	}

	prices := result.([]thirdparty.HistoricalPrice)
	return prices, nil
}

func (pm *Manager) FetchTokenMarketValues(tokenGroupKeys []string, currency string) (map[string]thirdparty.TokenMarketValues, error) {
	result, err := pm.makeCall(pm.providers, func(provider thirdparty.MarketDataProvider) (interface{}, error) {
		return provider.FetchTokenMarketValues(tokenGroupKeys, currency)
	})

	if err != nil {
		logutils.ZapLogger().Error("Error fetching prices", zap.Error(err))
		return nil, err
	}

	marketValues := result.(map[string]thirdparty.TokenMarketValues)
	return marketValues, nil
}

func (pm *Manager) FetchTokenDetails(tokenGroupKeys []string) (map[string]thirdparty.TokenDetails, error) {
	result, err := pm.makeCall(pm.providers, func(provider thirdparty.MarketDataProvider) (interface{}, error) {
		return provider.FetchTokenDetails(tokenGroupKeys)
	})

	if err != nil {
		logutils.ZapLogger().Error("Error fetching prices", zap.Error(err))
		return nil, err
	}

	tokenDetails := result.(map[string]thirdparty.TokenDetails)
	return tokenDetails, nil
}

func (pm *Manager) FetchPrice(tokenGroupKey string, currency string) (float64, error) {
	tokenGroupKeys := [1]string{tokenGroupKey}
	currencies := [1]string{currency}

	prices, err := pm.FetchPrices(tokenGroupKeys[:], currencies[:])

	if err != nil {
		return 0, err
	}

	return prices[tokenGroupKey][currency], nil
}

func (pm *Manager) FetchPrices(tokenGroupKeys []string, currencies []string) (map[string]map[string]float64, error) {
	response, err := pm.makeCall(pm.providers, func(provider thirdparty.MarketDataProvider) (interface{}, error) {
		return provider.FetchPrices(tokenGroupKeys, currencies)
	})

	if err != nil {
		logutils.ZapLogger().Error("Error fetching prices", zap.Error(err))
		return nil, err
	}
	prices := response.(map[string]map[string]float64)
	pm.updatePriceCache(prices)
	return prices, nil
}

func (pm *Manager) getCachedPricesFor(tokenGroupKeys []string, currencies []string) DataPerTokenAndCurrency {
	return Read(&pm.priceCache, func(tokenPriceCache TokenPriceCache) DataPerTokenAndCurrency {
		prices := make(DataPerTokenAndCurrency)
		for _, tokenGroupKey := range tokenGroupKeys {
			prices[tokenGroupKey] = make(map[string]DataPoint)
			for _, currency := range currencies {
				prices[tokenGroupKey][currency] = tokenPriceCache[tokenGroupKey][currency]
			}
		}
		return prices
	})
}

func (pm *Manager) updatePriceCache(prices map[string]map[string]float64) {
	Write(&pm.priceCache, func(tokenPriceCache TokenPriceCache) TokenPriceCache {
		for token, pricesPerCurrency := range prices {
			_, present := tokenPriceCache[token]
			if !present {
				tokenPriceCache[token] = make(map[string]DataPoint)
			}
			for currency, price := range pricesPerCurrency {
				tokenPriceCache[token][currency] = DataPoint{
					Price:     price,
					UpdatedAt: time.Now().Unix(),
				}
			}
		}

		return tokenPriceCache
	})
}

// Return cached price if present in cache and age is less than maxAgeInSeconds. Fetch otherwise.
func (pm *Manager) GetOrFetchPrices(tokenGroupKeys []string, currencies []string, maxAgeInSeconds int64) (DataPerTokenAndCurrency, error) {
	tokenGroupKeysToFetch := Read(&pm.priceCache, func(tokenPriceCache TokenPriceCache) []string {
		tokenGroupKeysToFetchMap := make(map[string]bool)
		tokenGroupKeysToFetch := make([]string, 0, len(tokenGroupKeys))

		now := time.Now().Unix()

		for _, tokenGroupKey := range tokenGroupKeys {
			tokenPriceCache, ok := tokenPriceCache[tokenGroupKey]
			if !ok {
				if !tokenGroupKeysToFetchMap[tokenGroupKey] {
					tokenGroupKeysToFetchMap[tokenGroupKey] = true
					tokenGroupKeysToFetch = append(tokenGroupKeysToFetch, tokenGroupKey)
				}
				continue
			}
			for _, currency := range currencies {
				if now-tokenPriceCache[currency].UpdatedAt > maxAgeInSeconds {
					if !tokenGroupKeysToFetchMap[tokenGroupKey] {
						tokenGroupKeysToFetchMap[tokenGroupKey] = true
						tokenGroupKeysToFetch = append(tokenGroupKeysToFetch, tokenGroupKey)
					}
					break
				}
			}
		}

		return tokenGroupKeysToFetch
	})

	if len(tokenGroupKeysToFetch) > 0 {
		_, err := pm.FetchPrices(tokenGroupKeysToFetch, currencies)
		if err != nil {
			return nil, err
		}
	}

	prices := pm.getCachedPricesFor(tokenGroupKeys, currencies)

	return prices, nil
}
