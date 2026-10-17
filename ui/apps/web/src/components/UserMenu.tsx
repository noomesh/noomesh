// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useState } from 'react';
import { useAuth } from '@metis/core';
import { useTheme } from '@/lib/useTheme';
import { McpKeyDialog } from '@/features/account/McpKeyDialog';
import { VoiceDialog } from '@/features/chat/voice/VoiceDialog';
import { useVoiceControls } from '@/features/chat/voice/useVoice';
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
} from '@/components/ui/dropdown-menu';

const SunIcon = () => (
  <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.6">
    <circle cx="10" cy="10" r="4" />
    <path d="M10 1.5v2M10 16.5v2M1.5 10h2M16.5 10h2M4 4l1.5 1.5M14.5 14.5L16 16M16 4l-1.5 1.5M4 16l1.5-1.5" />
  </svg>
);
const MoonIcon = () => (
  <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.6">
    <path d="M16 11.5A6.5 6.5 0 0 1 8.5 4a6.5 6.5 0 1 0 7.5 7.5z" />
  </svg>
);
const KeyIcon = () => (
  <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.6">
    <circle cx="6.5" cy="10" r="3.5" />
    <path d="M10 10h7M14.5 10v3M17 10v2.5" />
  </svg>
);
const SignOutIcon = () => (
  <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.6">
    <path d="M12 6V4a1 1 0 0 0-1-1H4a1 1 0 0 0-1 1v12a1 1 0 0 0 1 1h7a1 1 0 0 0 1-1v-2M8 10h9M14 7l3 3-3 3" />
  </svg>
);

const SpeakerIcon = () => (
  <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.6">
    <path d="M3.5 8v4h3l4 3.5v-11L6.5 8z" />
    <path d="M13.5 7.5a3.5 3.5 0 0 1 0 5M15.5 5.5a6.5 6.5 0 0 1 0 9" />
  </svg>
);

/** Bottom-of-sidebar account button. The avatar/name opens a menu holding the
 *  theme toggle and sign-out (which used to sit loose in the footer). */
export function UserMenu() {
  const { user, isOperator, logout } = useAuth();
  const { dark, toggle } = useTheme();
  const [keyOpen, setKeyOpen] = useState(false);
  const [voiceOpen, setVoiceOpen] = useState(false);
  // Shares the chat's voice-status query; the picker shows only when
  // read-aloud is on for this install.
  const voice = useVoiceControls(false);
  const name = user?.username ?? 'guest';
  const role = isOperator ? ' · operator' : '';

  return (
    <>
    <McpKeyDialog open={keyOpen} onOpenChange={setKeyOpen} />
    <VoiceDialog open={voiceOpen} onOpenChange={setVoiceOpen} />
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button className="user-trigger" aria-label="Account menu">
          <span className="ava">{name.slice(0, 1).toUpperCase()}</span>
          <span className="uname">
            {name}
            {role}
          </span>
          <svg className="chev-up" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.6">
            <path d="M6 12l4-4 4 4" />
          </svg>
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent side="top" align="start" className="w-[184px]">
        <DropdownMenuLabel>
          {name}
          {role}
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem
          onSelect={(e) => {
            e.preventDefault(); // keep the menu open so the label updates live
            toggle();
          }}
        >
          {dark ? <SunIcon /> : <MoonIcon />}
          {dark ? 'Light mode' : 'Dark mode'}
        </DropdownMenuItem>
        {voice.speaker !== 'hidden' && (
          <DropdownMenuItem onSelect={() => setVoiceOpen(true)}>
            <SpeakerIcon />
            Read-aloud voice
          </DropdownMenuItem>
        )}
        {user && (
          <DropdownMenuItem onSelect={() => setKeyOpen(true)}>
            <KeyIcon />
            MCP key
          </DropdownMenuItem>
        )}
        {user && (
          <DropdownMenuItem onSelect={() => logout()}>
            <SignOutIcon />
            Sign out
          </DropdownMenuItem>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
    </>
  );
}
