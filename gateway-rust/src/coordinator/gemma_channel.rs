// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! gemma-4's reasoning-channel tokens, removed from a stream as it arrives.
//!
//! gemma-4 wraps its reasoning in `<|channel>thought … <channel|>`. vLLM
//! strips special tokens; ollama (mcmini, 2026-10-16) passes them through as
//! text, so every streamed thinking block opened with a literal
//! `<|channel>thought` in the dashboard's thinking panel. Only the persisted
//! reply looked right once the turn ended.
//!
//! In the `reasoning` field the tokens are just dropped: the field already
//! says it is reasoning. In `content` they become `<think>` / `</think>`, so
//! the tag parser already in the loop moves the reasoning out of the
//! answer. A token can be split across chunks, so a tail that could still
//! become a token is held back until the next chunk or [`finish`].
//!
//! [`finish`]: ChannelFilter::finish

const OPEN: &str = "<|channel>thought";
const OPEN_BARE: &str = "<|channel>";
const CLOSE: &str = "<channel|>";

pub(super) struct ChannelFilter {
    /// true: `content` (tokens become think tags); false: `reasoning` (dropped).
    to_tags: bool,
    held: String,
    /// The last token was an open: eat one newline that follows it.
    eat_newline: bool,
}

impl ChannelFilter {
    pub(super) fn reasoning() -> Self {
        Self { to_tags: false, held: String::new(), eat_newline: false }
    }

    pub(super) fn content() -> Self {
        Self { to_tags: true, held: String::new(), eat_newline: false }
    }

    /// Feed one chunk; returns the text that is safe to pass on now.
    pub(super) fn push(&mut self, chunk: &str) -> String {
        self.held.push_str(chunk);
        let mut out = String::new();
        loop {
            if self.eat_newline && !self.held.is_empty() {
                if self.held.starts_with('\n') {
                    self.held.remove(0);
                }
                self.eat_newline = false;
            }
            let Some(at) = self.held.find('<') else {
                out.push_str(&self.held);
                self.held.clear();
                break;
            };
            out.push_str(&self.held[..at]);
            self.held.drain(..at);
            // `held` starts with '<'. Longest token first: OPEN contains OPEN_BARE.
            if self.held.starts_with(OPEN) {
                self.held.drain(..OPEN.len());
                self.open(&mut out);
            } else if self.held.starts_with(OPEN_BARE) && !OPEN.starts_with(self.held.as_str()) {
                self.held.drain(..OPEN_BARE.len());
                self.open(&mut out);
            } else if self.held.starts_with(CLOSE) {
                self.held.drain(..CLOSE.len());
                if self.to_tags {
                    out.push_str("</think>");
                }
            } else if OPEN.starts_with(self.held.as_str()) || CLOSE.starts_with(self.held.as_str()) {
                // Could still become a token: wait for more.
                break;
            } else {
                out.push('<');
                self.held.remove(0);
            }
        }
        out
    }

    /// End of stream: whatever is held back was not a token after all.
    pub(super) fn finish(&mut self) -> String {
        let rest = std::mem::take(&mut self.held);
        if rest == OPEN_BARE {
            return if self.to_tags { "<think>".into() } else { String::new() };
        }
        rest
    }

    fn open(&mut self, out: &mut String) {
        if self.to_tags {
            out.push_str("<think>");
        }
        self.eat_newline = true;
    }
}

/// Drop the channel tokens from a whole, non-streamed reasoning string.
pub(super) fn drop_channel_tokens(text: &str) -> String {
    let mut f = ChannelFilter::reasoning();
    let mut out = f.push(text);
    out.push_str(&f.finish());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(mut f: ChannelFilter, chunks: &[&str]) -> String {
        let mut out: String = chunks.iter().map(|c| f.push(c)).collect();
        out.push_str(&f.finish());
        out
    }

    #[test]
    fn reasoning_loses_the_tokens() {
        let got = run(ChannelFilter::reasoning(), &["<|channel>thought\nThe user asks", " about ML.<channel|>"]);
        assert_eq!(got, "The user asks about ML.");
    }

    #[test]
    fn a_token_split_across_chunks_is_still_caught() {
        let got = run(ChannelFilter::reasoning(), &["<|cha", "nnel>tho", "ught", "\nplan", "<chan", "nel|>"]);
        assert_eq!(got, "plan");
    }

    #[test]
    fn content_tokens_become_think_tags() {
        let got = run(ChannelFilter::content(), &["<|channel>thought\nplanning", "<channel|>Machine learning is"]);
        assert_eq!(got, "<think>planning</think>Machine learning is");
    }

    #[test]
    fn ordinary_angle_brackets_pass_through() {
        let got = run(ChannelFilter::content(), &["if a <", " b and <think>x</think> <|", "x|> <c"]);
        assert_eq!(got, "if a < b and <think>x</think> <|x|> <c");
    }

    #[test]
    fn a_bare_open_without_thought_is_a_token() {
        assert_eq!(run(ChannelFilter::reasoning(), &["<|channel>", "final"]), "final");
        assert_eq!(drop_channel_tokens("<|channel>"), "");
    }

    #[test]
    fn whole_string_helper() {
        assert_eq!(drop_channel_tokens("<|channel>thought\nabc<channel|>"), "abc");
        assert_eq!(drop_channel_tokens("plain"), "plain");
    }
}
