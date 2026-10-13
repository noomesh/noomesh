// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { StyleSheet, Text, View } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { useAuth } from '@metis/core';
import { theme } from '../theme';
import { GATEWAY_URL } from '../lib/config';
import { Button, Card, ScreenTitle } from '../components/ui';

export function SettingsScreen() {
  const { user, isOperator, logout } = useAuth();

  return (
    <SafeAreaView style={styles.root} edges={['top']}>
      <ScreenTitle title="Settings" />
      <View style={{ paddingTop: 12 }}>
        <Card>
          <Row label="Signed in as" value={user?.username ?? '—'} />
          <Row label="Scopes" value={(user?.scopes ?? []).join(', ') || '—'} />
          <Row label="Role" value={isOperator ? 'operator' : 'read-only'} />
        </Card>
        <Card>
          <Row label="Gateway" value={GATEWAY_URL || '(unset)'} />
        </Card>
        <View style={{ paddingHorizontal: 16, marginTop: 6 }}>
          <Button label="Sign out" variant="outline" onPress={() => logout()} />
        </View>
      </View>
    </SafeAreaView>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <View style={styles.row}>
      <Text style={styles.label}>{label}</Text>
      <Text style={styles.value} numberOfLines={1}>
        {value}
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: theme.bg },
  row: { flexDirection: 'row', justifyContent: 'space-between', paddingVertical: 6, gap: 12 },
  label: { color: theme.dim, fontSize: 13 },
  value: { color: theme.text, fontSize: 13, flexShrink: 1, textAlign: 'right' },
});
