// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package modelsets

import "github.com/noomesh/noomesh/node-agent-go/internal/config"

func configWithCA(path string) *config.Config { return &config.Config{TLSCA: path} }
