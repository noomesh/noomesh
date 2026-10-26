#!/usr/bin/perl
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
#
# Output filter for the onboarding film: reads text on stdin, writes it with
# anything that identifies a real machine or person replaced by a generic,
# CONSISTENT stand-in (the same real value always becomes the same stand-in, so
# the film still reads as one coherent system):
#
#   node names, tailnet host names   my-box, noo-controller.x.ts.net  ->  node-1, node-2 ...
#   IPv4 addresses                   10.1.2.3                         ->  192.0.2.1 ...  (RFC 5737)
#   IPv6 addresses                   2a01:4f8::1                      ->  2001:db8::1 ... (RFC 3849)
#   MAC addresses                    aa:bb:cc:dd:ee:ff                ->  00:00:00:00:00:00
#   e-mail addresses                 person@mail.test                 ->  you@example.com
#   home directories                 /home/alice                      ->  /home/you
#   tokens, keys, passwords          ghp_..., noo-ent1..., password: x ->  ********
#
# Left alone on purpose: loopback and 0.0.0.0, versions (0.6.0), timestamps,
# image digests (sha256:<64 hex>), the public noomesh.ai addresses.
#
# Environment:
#   NOO_DEMO_HOSTNAME     this machine's name (the recorder sets it) -> a node-N
#   NOO_DEMO_MASK_NAMES   extra names to mask, space or comma separated
# The built-in list covers the fleet's own node names.
#
# It works line by line, so streamed output appears a line at a time. A
# pattern split across two lines (it cannot be, for the values above) is not
# caught: the recorder re-checks the raw and masked logs after rendering.
use strict;
use warnings;
$| = 1;

my (%host, %ip4, %ip6);
my ($hn, $i4, $i6) = (0, 0, 0);

my %seen;
my @names = grep { length && !$seen{$_}++ }
            map { lc } split /[\s,]+/, join(' ',
              ($ENV{NOO_DEMO_MASK_NAMES} // ''),
              ($ENV{NOO_DEMO_HOSTNAME} // ''),
              'host3 host8 host8 host9 host6 host2 host5 host8-ma');
@names = sort { length($b) <=> length($a) } @names;   # host8-ma before host8
my $namere = @names ? join('|', map { quotemeta } @names) : undef;

sub node  { my $k = lc shift; $host{$k} //= 'node-' . (++$hn) }
sub fake4 {
    my $k = shift;
    $ip4{$k} //= do { my $n = ++$i4; $n <= 254 ? "192.0.2.$n" : '198.51.100.' . ($n - 254) };
}
sub fake6 { my $k = lc shift; $ip6{$k} //= '2001:db8::' . sprintf('%x', ++$i6) }

# The machine being filmed is always node-1, whatever order names appear in.
node($ENV{NOO_DEMO_HOSTNAME}) if length($ENV{NOO_DEMO_HOSTNAME} // '');

# Masks one stretch of plain text (no colour codes inside it).
sub mask_text {
    my $l = shift;
    # tokens and opaque secrets
    $l =~ s/\bnoo-ent1\.[A-Za-z0-9._-]+/noo-ent1.********/g;
    $l =~ s/\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16})/********/g;
    $l =~ s/\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}/********/g;
    $l =~ s{(?<!sha256:)(?<![A-Za-z0-9+/_=-])((?=[A-Za-z0-9+/_=-]*\d)(?=[A-Za-z0-9+/_=-]*[A-Za-z])[A-Za-z0-9+/_=-]{40,})(?![A-Za-z0-9+/_=-])}{********}g;
    $l =~ s{(?<!sha256:)(?<![0-9a-fA-F])[0-9a-fA-F]{40,}(?![0-9a-fA-F])}{********}g;
    # node names, then tailnet host names
    $l =~ s{(?<![\w-])($namere)(?![\w-])}{node($1)}gie if defined $namere;
    $l =~ s{(?<![\w.-])((?:[\w-]+\.)+ts\.net)\b}{node(lc $1) . '.tailnet.ts.net'}gie;
    # addresses
    $l =~ s{(?<![\w:])((?:[0-9a-f]{2}:){5}[0-9a-f]{2})(?![\w:])}{00:00:00:00:00:00}gi;
    $l =~ s{(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w]|\.\d)}{
        my $a = $1; my @o = split /\./, $a;
        (grep { $_ > 255 } @o) || $o[0] == 127 || $a eq '0.0.0.0' || $a eq '255.255.255.255' ? $a : fake4($a)
    }ge;
    $l =~ s{(?<![\w:])((?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}|(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{0,4}|::[0-9a-f:]+)(?![\w:])}{
        my $a = $1;
        # keep clock times, loopback, and MAC-shaped strings (already masked just above)
        ($a =~ /^\d{1,2}(?::\d{2}){1,2}$/ || $a =~ /^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/i || $a eq '::1' || $a eq '::') ? $a : fake6($a)
    }gie;
    # people and places
    $l =~ s/\b[\w.+-]+@(?!noomesh\.ai\b)[\w-]+(?:\.[\w-]+)+/you\@example.com/g;
    $l =~ s{/(?:home|Users)/(?!you\b)[\w.-]+}{/home/you}g;
    return $l;
}

my $ESC = qr/\e\[[0-9;?]*[A-Za-z]/;
while (my $l = <STDIN>) {
    # "label: value" secrets, on the whole line so a colour code between the
    # label and the value cannot hide the value
    # (a value of one to three digits is a count, "Secrets: 9 present", not a secret;
    #  an upper-case name with underscores, "secrets …: NOO_NODE_AGENT_TOKEN", names one)
    $l =~ s/((?:pass(?:word|phrase)?|token|secret|api[_ -]?key|credential)s?\s*(?:is\s*)?[:=]\s*(?:$ESC)*)(?!\*{8})(?!\d{1,3}(?:[\s\e]|$))(?!(?-i)[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+(?:[\s\e]|$))([^\s\e]+)/$1********/gi;
    # everything else per stretch of text: a colour code ends a word, so a value
    # that follows one (ESC[1;32m10.0.0.1) is still masked
    my @p = split /($ESC)/, $l, -1;
    for (my $i = 0; $i < @p; $i += 2) { $p[$i] = mask_text($p[$i]) }
    print join '', @p;
}
