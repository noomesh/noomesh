// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// @metis/api — public surface.
//
// The typed gateway client plus the auth + socket primitives, all
// framework-agnostic so web (apps/web) and mobile (apps/mobile) share one
// contract-checked data layer. Generate types with `npm run gen:api`.

export { createMetisClient } from './client.ts';
export type { MetisClient, MetisClientOptions } from './client.ts';

export { createAuthFetch, createBearerFetch, createTokenRefresher } from './auth.ts';
export type { TokenStore, AuthFetchOptions, TokenRefreshOptions } from './auth.ts';

export { memoryTokenStore, webTokenStore } from './stores.ts';

export { createAuthApi } from './authApi.ts';
export type { AuthApi, AuthApiOptions, MeInfo } from './authApi.ts';

export { createSocket, wsUrl } from './ws.ts';
export type { ManagedSocket, SocketOptions, SocketAuth } from './ws.ts';

export { createEventStream } from './sse.ts';
export type { EventStream, EventStreamOptions, StreamEvent } from './sse.ts';

export { awaitOperation, isOperationHandle, OperationError } from './ops.ts';
export type { AwaitOptions, Operation, OperationHandle, OperationStatus } from './ops.ts';

// Generated from contracts/openapi.json — the full REST surface as types.
export type { paths, components, operations } from './schema';
