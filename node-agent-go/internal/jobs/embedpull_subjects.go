// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package jobs

// The bus contract of the pulled-embedding worker (proposal i179), stated
// once and as constants only. The worker itself lands later and must build
// every subject from these, never from a literal of its own.
//
// Why this file exists: the node's NATS credential (`perms_for` Role::Node in
// noo-cli/src/commands/nats_users.rs) must authorise exactly the JetStream
// subjects the pull worker sends, and `nc.Publish` returns nil on a DENIED
// publish, so a gap is a silent outage (#1218). tests/
// test_nats_node_pull_grants_parity.py parses THIS file and the grant and
// asserts they agree in both directions.
//
// The node only BINDS consumers the gateway created
// (`PullSubscribe(..., nats.Bind(EmbedStream, consumer))`). It never creates
// or deletes one, and it touches no stream API.
//
// Each `%s` below is the consumer name, `EmbedConsumerPrefix` + a model slug.
const (
	// EmbedStream is the WorkQueue stream the gateway declares.
	EmbedStream = "WORK_EMBED"

	// EmbedConsumerPrefix starts every per-model durable pull consumer name.
	EmbedConsumerPrefix = "embed_"

	// EmbedConsumerInfoSubjectFmt: nats.go getConsumerInfoContext, run by
	// js.subscribe before binding.
	EmbedConsumerInfoSubjectFmt = "$JS.API.CONSUMER.INFO.WORK_EMBED.%s"

	// EmbedConsumerNextSubjectFmt: the pull request Fetch publishes
	// (apiRequestNextT).
	EmbedConsumerNextSubjectFmt = "$JS.API.CONSUMER.MSG.NEXT.WORK_EMBED.%s"

	// EmbedAckSubjectFmt: the reply subject on each delivered message, which
	// Ack/Nak/InProgress publish to. The server appends delivery-count and
	// sequence tokens after the consumer name.
	EmbedAckSubjectFmt = "$JS.ACK.WORK_EMBED.%s.>"
)
