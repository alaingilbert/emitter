package security

import (
	"strings"
	"testing"

	"github.com/emitter-io/emitter/utils"
	"github.com/stretchr/testify/assert"
)

func BenchmarkParseChannelWithOptions(b *testing.B) {
	in := "xm54Sj0srWlSEctra-yU6ZA6Z2e6pp7c/a/roman/is/da/best/?opt1=true&opt2=false"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ParseChannel([]byte(in))
	}
}

func BenchmarkParseChannelStatic(b *testing.B) {
	in := "xm54Sj0srWlSEctra-yU6ZA6Z2e6pp7c/a/roman/is/da/best/"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ParseChannel([]byte(in))
	}
}

func buildQuery(strs ...string) []uint32 {
	qs := make([]uint32, 0)
	for _, str := range strs {
		qs = append(qs, utils.GetHash([]byte(str)))
	}
	return qs
}

func TestParseChannel(t *testing.T) {
	tests := []struct {
		k  string
		ch string
		o  []string
		t  uint8
		q  []uint32
	}{
		{k: "emitter", ch: "", t: ChannelStatic, q: buildQuery("")},
		{k: "emitter", ch: "+", t: ChannelWildcard, q: buildQuery("+")},
		{k: "emitter", ch: "#", t: ChannelWildcard, q: buildQuery("#")},
		{k: "emitter", ch: "/", t: ChannelStatic, q: buildQuery("", "")},
		{k: "emitter", ch: "///", t: ChannelStatic, q: buildQuery("", "", "", "")},
		{k: "emitter", ch: "/a", t: ChannelStatic, q: buildQuery("", "a")},
		{k: "emitter", ch: "a/", t: ChannelStatic, q: buildQuery("a", "")},
		{k: "emitter", ch: "a", t: ChannelStatic, q: buildQuery("a")},
		{k: "emitter", ch: "a/b/c", t: ChannelStatic, q: buildQuery("a", "b", "c")},
		{k: "emitter", ch: "test-channel", t: ChannelStatic, q: buildQuery("test-channel")},
		{k: "emitter", ch: "test-channel/+/and-more", t: ChannelWildcard, q: buildQuery("test-channel", "+", "and-more")},
		{k: "emitter", ch: "a/-/x", t: ChannelStatic, q: buildQuery("a", "-", "x")},
		{k: "emitter", ch: "a/b/c/d", t: ChannelStatic, q: buildQuery("a", "b", "c", "d")},
		{k: "emitter", ch: "a/b/c/+", t: ChannelWildcard, q: buildQuery("a", "b", "c", "+")},
		{k: "emitter", ch: "a/+/c/+", t: ChannelWildcard, q: buildQuery("a", "+", "c", "+")},
		{k: "emitter", ch: "b/+", t: ChannelWildcard, q: buildQuery("b", "+")},
		{k: "emitter", ch: "a/b/#", t: ChannelWildcard, q: buildQuery("a", "b", "#")},
		{k: "emitter", ch: "a/b/#", o: []string{"test=true"}, t: ChannelWildcard, q: buildQuery("a", "b", "#")},
		{k: "0TJnt4yZPL73zt35h1UTIFsYBLetyD_g", ch: "emitter", o: []string{"test=true", "something=7"}, t: ChannelStatic},
		{k: "emitter", ch: "a/b/c/d", o: []string{"test=true", "something=7"}, t: ChannelStatic},

		// Invalid channels
		{t: ChannelInvalid},
		{k: "emitter", ch: "a/@/x", t: ChannelInvalid},
		{k: "emitter", ch: "a/#/c", t: ChannelInvalid},
		{k: "emitter", ch: "*", t: ChannelInvalid},
		{k: "emitter", ch: "b/*+", t: ChannelInvalid},
		{k: "emitter", ch: "b/+a", t: ChannelInvalid},
		{k: "emitter", ch: "b/a+", t: ChannelInvalid},
		{k: "emitter", ch: "b/#a", t: ChannelInvalid},
		{k: "emitter", ch: "b/a#", t: ChannelInvalid},
		{k: "emitter", ch: "a/b/c/d", o: []string{"test=true", "something=7", "more=_"}, t: ChannelInvalid},
		{k: "emitter", ch: "a/b/c/d", o: []string{"test==true"}, t: ChannelInvalid},
		{k: "emitter", ch: "a/b/c/d", o: []string{"te_st==true"}, t: ChannelInvalid},
		{k: "emitter", ch: "a", o: []string{"=true"}, t: ChannelInvalid},
		{k: "emitter", ch: "a", o: []string{"test="}, t: ChannelInvalid},
	}

	for _, tc := range tests {
		// First we need to build the input to parse
		in := tc.k + "/" + tc.ch
		if len(tc.o) > 0 {
			in += "?"
			in += strings.Join(tc.o, "&")
		}

		// Parse the channel now
		out := ParseChannel([]byte(in))
		assert.Equal(t, tc.t, out.ChannelType, "input: "+in)
		if len(tc.q) > 0 {
			assert.Equal(t, tc.q, out.Query)
		}
		if tc.t != ChannelInvalid && out.ChannelType != ChannelInvalid {
			//assert.Equal(t, ChannelStatic, out.Type)
			assert.Equal(t, tc.k, string(out.Key), "input: "+in)
			assert.Equal(t, tc.ch, string(out.Channel), "input: "+in)

			// Check the options
			for _, opt := range tc.o {
				target := strings.Split(opt, "=")[0]

				found := false
				for _, kvp := range out.Options {
					if kvp.Key == target {
						found = true
						assert.Equal(t, strings.Split(opt, "=")[1], kvp.Value)
					}
				}

				assert.Equal(t, true, found, "unable to find key = "+target)
			}
		}
	}
}

func TestGetChannelTTL(t *testing.T) {
	tests := []struct {
		channel string
		ttl     uint32
		ok      bool
	}{
		{channel: "emitter/a/?ttl=42&abc=9", ttl: 42, ok: true},
		{channel: "emitter/a/?ttl=1200", ttl: 1200, ok: true},
		{channel: "emitter/a/?ttl=1200a", ok: false},
		{channel: "emitter/a/", ok: false},
	}

	for _, tc := range tests {
		channel := ParseChannel([]byte(tc.channel))
		ttl, hasValue := channel.TTL()

		assert.Equal(t, tc.ttl, ttl)
		assert.Equal(t, hasValue, tc.ok)
	}
}

func TestGetChannelLast(t *testing.T) {
	tests := []struct {
		channel string
		last    uint32
		ok      bool
	}{
		{channel: "emitter/a/?last=42&abc=9", last: 42, ok: true},
		{channel: "emitter/a/?last=1200", last: 1200, ok: true},
		{channel: "emitter/a/?last=1200a", ok: false},
		{channel: "emitter/a/", ok: false},
	}

	for _, tc := range tests {
		channel := ParseChannel([]byte(tc.channel))
		last, hasValue := channel.Last()

		assert.Equal(t, tc.last, last)
		assert.Equal(t, hasValue, tc.ok)
	}
}

func TestGetChannelTarget(t *testing.T) {
	tests := []struct {
		channel string
		target  uint32
	}{
		{channel: "emitter/a/?ttl=42&abc=9", target: 0xc103eab3},
	}

	for _, tc := range tests {
		channel := ParseChannel([]byte(tc.channel))
		target := channel.Target()

		assert.Equal(t, tc.target, target)
	}
}
