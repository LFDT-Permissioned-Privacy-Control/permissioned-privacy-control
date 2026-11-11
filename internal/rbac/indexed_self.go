package rbac

import "privacy-proxy/internal/readprivacyabi"

type IndexedSelfMatcher = readprivacyabi.IndexedSelfMatcher

func NewIndexedSelfMatcher() *IndexedSelfMatcher { return readprivacyabi.NewIndexedSelfMatcher() }
