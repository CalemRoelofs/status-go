package fetcher

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDbActions(t *testing.T) {
	walletDb, closeFn := SetupTestWalletDB(t)
	t.Cleanup(closeFn)

	tokenListsFetcher := NewTokenListsFetcher(walletDb)

	tokenListsFetched := []FetchedTokenList{
		{
			TokenList: TokenList{
				ID:        "id-1",
				SourceURL: "source-1",
				Schema:    "schema-1",
			},
			Etag:     "etag1",
			Fetched:  time.Now().Add(-48 * time.Hour),
			JsonData: "json-data-1",
		},
		{
			TokenList: TokenList{
				ID:        "id-2",
				SourceURL: "source-2",
				Schema:    "schema-2",
			},
			Etag:     "etag2",
			Fetched:  time.Now().Add(-48 * time.Hour),
			JsonData: "json-data-2",
		},
	}

	etag, err := tokenListsFetcher.GetEtagForTokenList(tokenListsFetched[0].ID)
	require.NoError(t, err)
	require.Empty(t, etag)

	for _, tokenList := range tokenListsFetched {
		err := tokenListsFetcher.StoreTokenList(tokenList.ID, tokenList.Etag, tokenList.JsonData)
		require.NoError(t, err)
	}

	dbTokenLists, err := tokenListsFetcher.GetAllTokenLists()
	require.NoError(t, err)
	require.Len(t, dbTokenLists, len(tokenListsFetched))
	id1Index := 0
	if dbTokenLists[0].ID == "id-2" {
		id1Index = 1
	}

	require.Equal(t, tokenListsFetched[0].ID, dbTokenLists[id1Index].ID)
	require.Equal(t, tokenListsFetched[0].Etag, dbTokenLists[id1Index].Etag)
	require.Equal(t, tokenListsFetched[0].JsonData, dbTokenLists[id1Index].JsonData)
	require.True(t, dbTokenLists[id1Index].Fetched.Compare(tokenListsFetched[0].Fetched) == 1)

	require.Equal(t, tokenListsFetched[1].ID, dbTokenLists[1-id1Index].ID)
	require.Equal(t, tokenListsFetched[1].Etag, dbTokenLists[1-id1Index].Etag)
	require.Equal(t, tokenListsFetched[1].JsonData, dbTokenLists[1-id1Index].JsonData)
	require.True(t, dbTokenLists[1-id1Index].Fetched.Compare(tokenListsFetched[1].Fetched) == 1)

	etag, err = tokenListsFetcher.GetEtagForTokenList(tokenListsFetched[0].ID)
	require.NoError(t, err)
	require.Equal(t, tokenListsFetched[0].Etag, etag)
}
