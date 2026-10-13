// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { FlatList, StyleSheet, Text, View } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { theme } from '../theme';
import { useProposals, type Proposal } from '../lib/data';
import { Card, Empty, ErrorState, Loading, Pill, ScreenTitle } from '../components/ui';

const statusTone = (s: string) =>
  s === 'approved' || s === 'executed'
    ? 'good'
    : s === 'failed'
      ? 'bad'
      : s === 'pending'
        ? 'warn'
        : ('neutral' as const);

function ProposalCard({ p }: { p: Proposal }) {
  return (
    <Card>
      <View style={styles.row}>
        <Text style={styles.title}>
          {p.user} → {p.role}
        </Text>
        <Pill tone={statusTone(p.status)}>{p.status}</Pill>
      </View>
      <Text style={styles.meta}>host {p.host}</Text>
      {!!p.reason && <Text style={styles.reason}>{p.reason}</Text>}
    </Card>
  );
}

export function ProposalsScreen() {
  const proposals = useProposals();

  return (
    <SafeAreaView style={styles.root} edges={['top']}>
      <ScreenTitle title="Proposals" />
      {proposals.isLoading && <Loading label="Loading proposals…" />}
      {proposals.isError && <ErrorState message={(proposals.error as Error)?.message ?? 'Error'} />}
      {proposals.data && (
        <FlatList
          data={proposals.data}
          keyExtractor={(p) => p.id}
          contentContainerStyle={{ paddingTop: 12 }}
          renderItem={({ item }) => <ProposalCard p={item} />}
          ListEmptyComponent={<Empty message="No proposals." />}
          refreshing={proposals.isFetching}
          onRefresh={() => proposals.refetch()}
        />
      )}
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: theme.bg },
  row: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 },
  title: { color: theme.text, fontSize: 15, fontWeight: '600', flexShrink: 1 },
  meta: { color: theme.dim, fontSize: 12 },
  reason: { color: theme.faint, fontSize: 12, marginTop: 6 },
});
