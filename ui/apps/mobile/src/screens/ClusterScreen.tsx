// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { FlatList, StyleSheet, Text, View } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { theme } from '../theme';
import { useCluster, type Node } from '../lib/data';
import { Card, Empty, ErrorState, Loading, Pill, ScreenTitle } from '../components/ui';

const nodeTone = (s: string) => (s === 'online' ? 'good' : s === 'busy' ? 'warn' : 'neutral');

function NodeCard({ node }: { node: Node }) {
  return (
    <Card>
      <View style={styles.row}>
        <Text style={styles.name}>{node.hostname}</Text>
        <Pill tone={nodeTone(node.status)}>{node.status}</Pill>
      </View>
      <Text style={styles.meta}>
        {node.gpu ?? 'No GPU'}
        {node.vram ? ` · ${node.vram} GB VRAM` : ''}
      </Text>
    </Card>
  );
}

export function ClusterScreen() {
  const cluster = useCluster();

  return (
    <SafeAreaView style={styles.root} edges={['top']}>
      <ScreenTitle
        title="Cluster"
        right={cluster.data ? <Text style={styles.count}>{cluster.data.stats.total} nodes</Text> : null}
      />
      {cluster.isLoading && <Loading label="Loading cluster…" />}
      {cluster.isError && <ErrorState message={(cluster.error as Error)?.message ?? 'Error'} />}
      {cluster.data && (
        <FlatList
          data={cluster.data.nodes}
          keyExtractor={(n) => n.id || n.hostname}
          contentContainerStyle={{ paddingTop: 12 }}
          ListHeaderComponent={
            <View style={styles.stats}>
              <Stat label="Online" value={cluster.data.stats.online} tone={theme.good} />
              <Stat label="Busy" value={cluster.data.stats.busy} tone={theme.warn} />
              <Stat label="Nodes" value={cluster.data.stats.total} />
              <Stat label="VRAM GB" value={cluster.data.stats.vramGb} />
            </View>
          }
          renderItem={({ item }) => <NodeCard node={item} />}
          ListEmptyComponent={<Empty message="No nodes." />}
          refreshing={cluster.isFetching}
          onRefresh={() => cluster.refetch()}
        />
      )}
    </SafeAreaView>
  );
}

function Stat({ label, value, tone }: { label: string; value: number; tone?: string }) {
  return (
    <View style={styles.stat}>
      <Text style={[styles.statValue, tone ? { color: tone } : null]}>{value}</Text>
      <Text style={styles.statLabel}>{label}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: theme.bg },
  count: { color: theme.dim, fontSize: 13 },
  stats: { flexDirection: 'row', marginHorizontal: 16, marginBottom: 12, gap: 8 },
  stat: {
    flex: 1,
    backgroundColor: theme.card,
    borderColor: theme.border,
    borderWidth: StyleSheet.hairlineWidth,
    borderRadius: 10,
    paddingVertical: 12,
    alignItems: 'center',
  },
  statValue: { color: theme.text, fontSize: 20, fontWeight: '700' },
  statLabel: { color: theme.faint, fontSize: 10, textTransform: 'uppercase', letterSpacing: 0.5, marginTop: 2 },
  row: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 },
  name: { color: theme.text, fontSize: 15, fontWeight: '600' },
  meta: { color: theme.dim, fontSize: 12 },
});
