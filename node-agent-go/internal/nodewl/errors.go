// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package nodewl is the node agent's validator for the i300 contract: the
// add-on's node-workloads.json (`noo-addon-node-workloads/1`), the
// desired-config `node_workloads` entry the gateway derives from it, and a
// catalog model set's manifest (`noo-model-set/1`).
//
// The agent re-validates everything itself before it builds anything: it does
// not trust the gateway's validation, because the agent is the last place a
// bug can be caught. The CLI (noo-cli/src/addons/decls.rs) and the gateway
// (gateway-rust/src/addon_workloads.rs) each validate against the SAME
// fixtures, tests/fixtures/i300/, of which internal/nodewl/testdata/i300 is a
// byte-identical copy (tests/test_i300_fixture_parity.py). Every refusal has a
// stable Code; cases.json beside each fixture directory names the code a file
// must produce. Contract: docs/reference/node-workloads.md.
//
// There is no runtime wiring here: no Docker, no network, no clock.
package nodewl

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Error is a typed refusal. Code is stable and is what the fixtures pin;
// Detail is for a human and may change; Inner is the nested code of a
// decl_invalid.
type Error struct {
	Code   string
	Detail string
	Inner  string
	// passthrough: desired-config reports this code as itself instead of
	// folding it into desired_invalid (a null, a duplicate key).
	passthrough bool
}

func (e *Error) Error() string {
	s := e.Code
	if e.Inner != "" {
		s += "(" + e.Inner + ")"
	}
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	return s
}

func fail(code, format string, a ...any) error {
	return &Error{Code: code, Detail: fmt.Sprintf(format, a...)}
}

// CodeOf is the refusal code of err, or "" when err is not an *Error.
func CodeOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// Codes shared by every parser here.
const (
	CodeBadJSON      = "bad_json"      // not JSON, or data after the document
	CodeUnknownField = "unknown_field" // a field the format does not have
	CodeFieldType    = "field_type"    // a value of the wrong JSON type
	CodeFieldMissing = "field_missing" // a required field is absent
	CodeBadFormat    = "bad_format"    // `format` is not the one this parser reads
)

// CodeDuplicateKey: an object repeats a key, at any depth. Go keeps the last
// value and serde_json's derived structs refuse the repeat, so a document
// could otherwise be validated with one value and run with another (a parser
// differential). Every validator refuses it.
const CodeDuplicateKey = "duplicate_key"

// JSON null is refused on every field, with field_type, except the fields the
// contract names nullable (nullable.go; the table in node-workloads.md). Go's
// decoder treats null on a non-pointer field as a no-op that keeps the zero
// value (`"accel": {"gpu": null}` reads as gpu 0), while serde refuses it: a
// parser differential. Every validator refuses it.

// seg is one step of the path the walk is at: an object key, or an array
// index (idx true).
type seg struct {
	s   string
	idx bool
}

var ptrEscape = strings.NewReplacer("~", "~0", "/", "~1")

// matchesPointer reports whether path is the JSON pointer pat, where a `*`
// matches any one array index.
func matchesPointer(path []seg, pat string) bool {
	parts := strings.Split(strings.TrimPrefix(pat, "/"), "/")
	if len(parts) != len(path) {
		return false
	}
	for i, p := range parts {
		if p == "*" && path[i].idx {
			continue
		}
		if p != ptrEscape.Replace(path[i].s) || path[i].idx {
			return false
		}
	}
	return true
}

// checkTokens walks b token by token and refuses a repeated key in any object
// (duplicate_key) and a JSON null at any path not in nullable (field_type).
// Syntax errors are not its business: the typed decode that follows reports
// them as bad_json.
func checkTokens(b []byte, nullable []string) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	err := walkValue(dec, nil, nullable)
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return nil
}

func walkValue(dec *json.Decoder, path []seg, nullable []string) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok == nil {
		for _, p := range nullable {
			if matchesPointer(path, p) {
				return nil
			}
		}
		return &Error{Code: CodeFieldType, Detail: "JSON null at " + pointerOf(path) + " (null is refused except on fields the contract names nullable)", passthrough: true}
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch d {
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return err
			}
			k, _ := kt.(string)
			if seen[k] {
				return fail(CodeDuplicateKey, "key %q is repeated in an object", k)
			}
			seen[k] = true
			if err := walkValue(dec, append(path[:len(path):len(path)], seg{s: k}), nullable); err != nil {
				return err
			}
		}
	case '[':
		for i := 0; dec.More(); i++ {
			if err := walkValue(dec, append(path[:len(path):len(path)], seg{s: strconv.Itoa(i), idx: true}), nullable); err != nil {
				return err
			}
		}
	}
	_, err = dec.Token() // the closing delimiter
	return err
}

func pointerOf(path []seg) string {
	var sb strings.Builder
	for _, s := range path {
		sb.WriteString("/" + ptrEscape.Replace(s.s))
	}
	if sb.Len() == 0 {
		return "(root)"
	}
	return sb.String()
}

// decodeStrict walks b (duplicate keys, nulls outside nullable) and then
// decodes exactly one JSON value into v: unknown fields are refused and so is
// anything after the value. It is for a whole document; a part of a document
// already walked is decoded with decodeTyped.
func decodeStrict(b []byte, v any, nullable []string) error {
	if err := checkTokens(b, nullable); err != nil {
		return err
	}
	return decodeTyped(b, v)
}

// decodeTyped is the typed half of decodeStrict, for bytes already walked.
func decodeTyped(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var te *json.UnmarshalTypeError
		switch {
		case strings.HasPrefix(err.Error(), "json: unknown field"):
			return fail(CodeUnknownField, "%v", err)
		case errors.As(err, &te):
			return fail(CodeFieldType, "%v", err)
		default:
			return fail(CodeBadJSON, "%v", err)
		}
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return fail(CodeBadJSON, "data after the JSON document")
	}
	return nil
}

// requireKeys refuses an object that lacks one of keys. v is a value decoded
// into `any`; anything that is not an object is left to the typed decode.
func requireKeys(v any, where string, keys ...string) error {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	for _, k := range keys {
		if _, has := m[k]; !has {
			return fail(CodeFieldMissing, "%s: `%s` is required", where, k)
		}
	}
	return nil
}

// generic decodes b into an untyped tree for requireKeys. It cannot fail on
// bytes decodeStrict already accepted.
func generic(b []byte) any {
	var v any
	_ = json.Unmarshal(b, &v)
	return v
}

func field(v any, k string) any {
	if m, ok := v.(map[string]any); ok {
		return m[k]
	}
	return nil
}

func items(v any, k string) []any {
	a, _ := field(v, k).([]any)
	return a
}
