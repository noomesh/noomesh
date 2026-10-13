// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useEffect, useState } from 'react';
import { ActivityIndicator, Text, View } from 'react-native';
import { StatusBar } from 'expo-status-bar';
import { SafeAreaProvider } from 'react-native-safe-area-context';
import { DarkTheme, NavigationContainer } from '@react-navigation/native';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import { MetisProvider, AuthProvider, useAuth } from '@metis/core';
import { client, authApi } from './src/lib/client';
import { hydrateToken } from './src/lib/secureStore';
import { sessionEvents } from './src/lib/sessionEvents';
import { theme } from './src/theme';
import { LoginScreen } from './src/screens/LoginScreen';
import { ChatScreen } from './src/screens/ChatScreen';
import { ClusterScreen } from './src/screens/ClusterScreen';
import { ProposalsScreen } from './src/screens/ProposalsScreen';
import { SettingsScreen } from './src/screens/SettingsScreen';

const Tab = createBottomTabNavigator();

const navTheme = {
  ...DarkTheme,
  colors: {
    ...DarkTheme.colors,
    background: theme.bg,
    card: theme.card,
    border: theme.border,
    primary: theme.accent,
    text: theme.text,
  },
};

const TAB_ICON: Record<string, string> = { Chat: '💬', Cluster: '▦', Proposals: '◈', Settings: '⚙' };

function Splash() {
  return (
    <View style={{ flex: 1, backgroundColor: theme.bg, alignItems: 'center', justifyContent: 'center' }}>
      <ActivityIndicator color={theme.accent} />
    </View>
  );
}

// Bridges the REST client's 401-refresh-failed signal to the auth layer.
function SessionWatcher() {
  const { refresh } = useAuth();
  useEffect(() => sessionEvents.onExpire(() => void refresh().catch(() => {})), [refresh]);
  return null;
}

function Gate() {
  const { ready, isLoggedIn } = useAuth();
  if (!ready) return <Splash />;
  if (!isLoggedIn) return <LoginScreen />;
  return (
    <Tab.Navigator
      screenOptions={({ route }) => ({
        headerShown: false,
        tabBarStyle: { backgroundColor: theme.card, borderTopColor: theme.border },
        tabBarActiveTintColor: theme.accent,
        tabBarInactiveTintColor: theme.dim,
        tabBarIcon: ({ color }) => <Text style={{ color, fontSize: 18 }}>{TAB_ICON[route.name] ?? '•'}</Text>,
      })}
    >
      <Tab.Screen name="Chat" component={ChatScreen} />
      <Tab.Screen name="Cluster" component={ClusterScreen} />
      <Tab.Screen name="Proposals" component={ProposalsScreen} />
      <Tab.Screen name="Settings" component={SettingsScreen} />
    </Tab.Navigator>
  );
}

export default function App() {
  const [hydrated, setHydrated] = useState(false);
  useEffect(() => {
    hydrateToken().finally(() => setHydrated(true));
  }, []);

  if (!hydrated) return <Splash />;

  return (
    <SafeAreaProvider>
      <MetisProvider client={client}>
        <AuthProvider authApi={authApi}>
          <SessionWatcher />
          <StatusBar style="light" />
          <NavigationContainer theme={navTheme}>
            <Gate />
          </NavigationContainer>
        </AuthProvider>
      </MetisProvider>
    </SafeAreaProvider>
  );
}
