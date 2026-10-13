// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useState } from 'react';
import { KeyboardAvoidingView, Platform, StyleSheet, Text, View } from 'react-native';
import { useAuth } from '@metis/core';
import { theme } from '../theme';
import { Button, Field } from '../components/ui';

export function LoginScreen() {
  const { login } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function onSubmit() {
    setError('');
    setBusy(true);
    try {
      await login(username.trim(), password);
    } catch (e) {
      setError((e as Error).message || 'Login failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <KeyboardAvoidingView style={styles.root} behavior={Platform.OS === 'ios' ? 'padding' : undefined}>
      <View style={styles.card}>
        <Text style={styles.brand}>METIS</Text>
        <Text style={styles.sub}>Sign in to your mesh.</Text>
        {!!error && <Text style={styles.error}>{error}</Text>}
        <Field
          placeholder="Username"
          autoCapitalize="none"
          autoCorrect={false}
          value={username}
          onChangeText={setUsername}
        />
        <Field placeholder="Password" secureTextEntry value={password} onChangeText={setPassword} />
        <Button label={busy ? 'Signing in…' : 'Sign In'} onPress={onSubmit} disabled={busy} />
      </View>
    </KeyboardAvoidingView>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: theme.bg, justifyContent: 'center', padding: 24 },
  card: {
    backgroundColor: theme.card,
    borderColor: theme.border,
    borderWidth: StyleSheet.hairlineWidth,
    borderRadius: 14,
    padding: 22,
    gap: 12,
  },
  brand: { color: theme.text, fontSize: 22, fontWeight: '800', letterSpacing: 2 },
  sub: { color: theme.dim, fontSize: 13, marginBottom: 4 },
  error: {
    color: theme.bad,
    fontSize: 13,
    backgroundColor: theme.bad + '1f',
    borderRadius: 8,
    padding: 10,
  },
});
