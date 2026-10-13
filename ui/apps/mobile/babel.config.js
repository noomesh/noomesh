// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

module.exports = function (api) {
  api.cache(true);
  return {
    presets: ['babel-preset-expo'],
  };
};
