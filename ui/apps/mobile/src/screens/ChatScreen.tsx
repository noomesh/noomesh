// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useEffect, useRef, useState } from 'react';
import {
  FlatList,
  KeyboardAvoidingView,
  Platform,
  Pressable,
  StyleSheet,
  Text,
  View,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import type { ManagedSocket } from '@metis/api';
import { connect } from '../lib/client';
import { theme } from '../theme';
import { Field, ScreenTitle } from '../components/ui';

interface Turn {
  role: 'you' | 'noomesh';
  text: string;
  streaming?: boolean;
  error?: boolean;
}
type Status = 'connecting' | 'live' | 'closed' | 'auth';

const GREETING: Turn = { role: 'noomesh', text: 'Connected to the mesh. Ask me about the cluster, or anything.' };

export function ChatScreen() {
  const [messages, setMessages] = useState<Turn[]>([GREETING]);
  const [status, setStatus] = useState<Status>('connecting');
  const [draft, setDraft] = useState('');
  const [busy, setBusy] = useState(false);
  const busyRef = useRef(false);
  const sockRef = useRef<ManagedSocket | null>(null);
  const convId = useRef<string | null>(null);
  const listRef = useRef<FlatList<Turn>>(null);

  const mark = (v: boolean) => {
    busyRef.current = v;
    setBusy(v);
  };
  const patchLast = (fn: (t: Turn) => Partial<Turn>) =>
    setMessages((ms) => {
      if (!ms.length) return ms;
      const copy = ms.slice();
      const last = copy[copy.length - 1]!;
      copy[copy.length - 1] = { ...last, ...fn(last) };
      return copy;
    });

  useEffect(() => {
    const sock = connect('/ws/coordinator', {
      reconnectMs: 1000,
      onOpen: () => setStatus('live'),
      onClose: () => {
        setStatus('closed');
        if (busyRef.current) {
          patchLast(() => ({ streaming: false }));
          mark(false);
        }
      },
      onAuthFail: () => setStatus('auth'),
      onMessage: (data) => {
        const f = data as { type: string; text?: string; conversation_id?: string };
        switch (f.type) {
          case 'metadata':
            if (f.conversation_id) convId.current = f.conversation_id;
            break;
          case 'content':
            patchLast((l) => ({ text: l.text + (f.text ?? '') }));
            break;
          case 'content_clear':
            patchLast(() => ({ text: '' }));
            break;
          case 'done':
            patchLast(() => ({ streaming: false }));
            mark(false);
            break;
          case 'error':
            patchLast((l) => ({
              text: (l.text ? `${l.text}\n` : '') + `⚠ ${f.text ?? 'error'}`,
              streaming: false,
              error: true,
            }));
            mark(false);
            break;
        }
      },
    });
    sockRef.current = sock;
    return () => sock.close();
  }, []);

  useEffect(() => {
    listRef.current?.scrollToEnd({ animated: true });
  }, [messages]);

  const canSend = status === 'live' && !busy;

  function send() {
    const p = draft.trim();
    if (!p || busyRef.current) return;
    const sock = sockRef.current;
    if (!sock || sock.readyState !== WebSocket.OPEN) {
      setMessages((ms) => [
        ...ms,
        { role: 'you', text: p },
        { role: 'noomesh', text: '⚠ Not connected to the mesh — reconnecting.', error: true },
      ]);
      setDraft('');
      return;
    }
    const ok = sock.send({ prompt: p, conversation_id: convId.current, enable_thinking: false, model: null });
    if (!ok) return;
    mark(true);
    setMessages((ms) => [...ms, { role: 'you', text: p }, { role: 'noomesh', text: '', streaming: true }]);
    setDraft('');
  }

  return (
    <SafeAreaView style={styles.root} edges={['top']}>
      <ScreenTitle
        title="Chat"
        right={<Text style={[styles.status, status !== 'live' && { color: theme.dim }]}>{status}</Text>}
      />
      <KeyboardAvoidingView
        style={styles.flex}
        behavior={Platform.OS === 'ios' ? 'padding' : undefined}
        keyboardVerticalOffset={90}
      >
        <FlatList
          ref={listRef}
          data={messages}
          keyExtractor={(_, i) => String(i)}
          contentContainerStyle={styles.list}
          renderItem={({ item }) => (
            <View style={[styles.bubble, item.role === 'you' ? styles.you : styles.noomesh]}>
              <Text style={styles.who}>{item.role === 'you' ? 'You' : 'Noomesh'}</Text>
              <Text style={[styles.msg, item.error && { color: theme.bad }]}>
                {item.text}
                {item.streaming ? ' ▍' : ''}
              </Text>
            </View>
          )}
        />
        <View style={styles.composer}>
          <View style={styles.flex}>
            <Field
              placeholder="Message Noomesh…"
              value={draft}
              onChangeText={setDraft}
              onSubmitEditing={send}
              returnKeyType="send"
            />
          </View>
          <Pressable
            onPress={send}
            disabled={!canSend}
            style={({ pressed }) => [styles.sendBtn, (!canSend || pressed) && { opacity: 0.5 }]}
          >
            <Text style={styles.sendText}>➤</Text>
          </Pressable>
        </View>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: theme.bg },
  flex: { flex: 1 },
  status: { color: theme.good, fontSize: 12, fontWeight: '600' },
  list: { padding: 14, gap: 12 },
  bubble: { maxWidth: '88%', borderRadius: 12, padding: 10 },
  you: { alignSelf: 'flex-end', backgroundColor: theme.accent + '22', borderColor: theme.accent + '44', borderWidth: StyleSheet.hairlineWidth },
  noomesh: { alignSelf: 'flex-start', backgroundColor: theme.card, borderColor: theme.border, borderWidth: StyleSheet.hairlineWidth },
  who: { color: theme.faint, fontSize: 10, textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 3 },
  msg: { color: theme.text, fontSize: 15, lineHeight: 21 },
  composer: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    padding: 10,
    borderTopWidth: StyleSheet.hairlineWidth,
    borderTopColor: theme.border,
  },
  sendBtn: { backgroundColor: theme.accent, width: 44, height: 44, borderRadius: 10, alignItems: 'center', justifyContent: 'center' },
  sendText: { color: theme.accentText, fontSize: 16, fontWeight: '700' },
});
