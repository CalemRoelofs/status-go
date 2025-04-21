package market

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/mock/gomock"

	"github.com/ethereum/go-ethereum/event"

	"github.com/stretchr/testify/require"

	"github.com/status-im/status-go/appdatabase"
	"github.com/status-im/status-go/rpc/network"
	mock_market "github.com/status-im/status-go/services/wallet/market/mock"
	"github.com/status-im/status-go/services/wallet/thirdparty"
	"github.com/status-im/status-go/services/wallet/token"
	"github.com/status-im/status-go/t/helpers"
	"github.com/status-im/status-go/walletdatabase"
)

const (
	btcGroupTokenKey = "bitcoin"
	ethGroupTokenKey = "ethereum"
	sntGroupTokenKey = "status"
)

func setupTokenManager(t *testing.T) (*token.Manager, func()) {
	appDb, err := helpers.SetupTestMemorySQLDB(appdatabase.DbInitializer{})
	require.NoError(t, err)

	walletDb, err := helpers.SetupTestMemorySQLDB(walletdatabase.DbInitializer{})
	require.NoError(t, err)

	nm := network.NewManager(appDb, nil, nil, nil)

	return token.NewTokenManager(walletDb, nil, nil, nm, appDb, nil, nil, nil, nil, token.NewPersistence(walletDb)),
		func() {
			require.NoError(t, appDb.Close())
			require.NoError(t, walletDb.Close())
		}
}

func setupMarketManager(t *testing.T, providers []thirdparty.MarketDataProvider, feedEvent *event.Feed) (*Manager, func()) {
	tokenManager, close := setupTokenManager(t)

	tokenManager.Start(context.Background(), 10000, 1000)

	return NewManager(providers, tokenManager, feedEvent), close
}

var mockPrices = map[string]map[string]float64{
	btcGroupTokenKey: {
		"USD": 1.23456,
		"EUR": 2.34567,
		"DAI": 3.45678,
		"ARS": 9.87654,
	},
	ethGroupTokenKey: {
		"USD": 4.56789,
		"EUR": 5.67891,
		"DAI": 6.78912,
		"ARS": 8.76543,
	},
	sntGroupTokenKey: {
		"USD": 7.654,
		"EUR": 6.0,
		"DAI": 1455.12,
		"ARS": 0.0,
	},
}

func TestPrice(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	priceProvider := mock_market.NewMockPriceProvider(ctrl)
	priceProvider.SetMockPrices(mockPrices)

	manager, close := setupMarketManager(t, []thirdparty.MarketDataProvider{priceProvider, priceProvider}, &event.Feed{})
	t.Cleanup(close)

	{
		rst := manager.priceCache.Get()
		require.Empty(t, rst)
	}

	{
		groupTokenKeys := []string{btcGroupTokenKey, ethGroupTokenKey}
		currencies := []string{"USD", "EUR"}
		rst, err := manager.FetchPrices(groupTokenKeys, currencies)
		require.NoError(t, err)
		for _, tokenKey := range groupTokenKeys {
			for _, currency := range currencies {
				require.Equal(t, rst[tokenKey][currency], mockPrices[tokenKey][currency])
			}
		}
	}

	{
		groupTokenKeys := []string{btcGroupTokenKey, ethGroupTokenKey, sntGroupTokenKey}
		currencies := []string{"USD", "EUR", "DAI", "ARS"}
		rst, err := manager.FetchPrices(groupTokenKeys, currencies)
		require.NoError(t, err)
		for _, tokenKey := range groupTokenKeys {
			for _, currency := range currencies {
				require.Equal(t, rst[tokenKey][currency], mockPrices[tokenKey][currency])
			}
		}
	}

	cache := manager.priceCache.Get()
	for tokenKey, pricePerCurrency := range mockPrices {
		for currency, price := range pricePerCurrency {
			require.Equal(t, price, cache[tokenKey][currency].Price)
		}
	}
}

func TestFetchPriceErrorFirstProvider(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	priceProvider := mock_market.NewMockPriceProvider(ctrl)
	priceProvider.SetMockPrices(mockPrices)

	customErr := errors.New("error")
	priceProviderWithError := mock_market.NewMockPriceProviderWithError(ctrl, customErr)

	groupTokenKeys := []string{btcGroupTokenKey, ethGroupTokenKey}
	currencies := []string{"USD", "EUR"}

	manager, close := setupMarketManager(t, []thirdparty.MarketDataProvider{priceProviderWithError, priceProvider}, &event.Feed{})
	t.Cleanup(close)

	rst, err := manager.FetchPrices(groupTokenKeys, currencies)
	require.NoError(t, err)
	for _, tokenKey := range groupTokenKeys {
		for _, currency := range currencies {
			require.Equal(t, rst[tokenKey][currency], mockPrices[tokenKey][currency])
		}
	}
}
