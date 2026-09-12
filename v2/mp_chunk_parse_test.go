package tdnsmp

import (
	"strings"
	"testing"
)

func TestParseAppPayload(t *testing.T) {
	cases := []struct {
		name, payload        string
		wantType, wantSender string
		wantZone, wantNonce  string
		wantErr              string
	}{
		{"modern sync", `{"MessageType":"sync","OriginatorID":"a.","YourIdentity":"b.","Zone":"z.","nonce":"n1"}`, "sync", "a.", "z.", "n1", ""},
		{"modern beat zone from Zones", `{"MessageType":"beat","MyIdentity":"a.","Zones":["z1.","z2."]}`, "beat", "a.", "z1.", "", ""},
		{"legacy confirm", `{"type":"confirm","sender_id":"a.","zone":"z."}`, "confirm", "a.", "z.", "", ""},
		{"legacy relocate no zone", `{"type":"relocate","sender_id":"a."}`, "relocate", "a.", "", "", ""},
		{"precedence originator over myidentity", `{"MessageType":"rfi","OriginatorID":"o.","MyIdentity":"m.","sender_id":"s."}`, "rfi", "o.", "", "", ""},
		{"both type tags equal", `{"MessageType":"ping","type":"ping","MyIdentity":"a."}`, "ping", "a.", "", "", ""},
		{"conflicting type tags", `{"MessageType":"sync","type":"update","OriginatorID":"a."}`, "", "", "", "", "conflicting message type"},
		{"conflicting zone tags", `{"MessageType":"sync","OriginatorID":"a.","Zone":"x.","zone":"y."}`, "", "", "", "", "conflicting zone"},
		{"no type", `{"OriginatorID":"a."}`, "", "", "", "", "no message type"},
		{"not json", `nope`, "", "", "", "", "failed to parse"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := parseAppPayload("d1", []byte(tc.payload), "127.0.0.1:0")
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if m.TypeToken != tc.wantType || m.Token() != tc.wantType {
				t.Errorf("type: %q, want %q", m.TypeToken, tc.wantType)
			}
			if m.SenderID != tc.wantSender || m.Zone != tc.wantZone || m.Nonce != tc.wantNonce || m.DistributionID != "d1" {
				t.Errorf("fields: sender=%q zone=%q nonce=%q dist=%q", m.SenderID, m.Zone, m.Nonce, m.DistributionID)
			}
			if string(m.Payload) != tc.payload {
				t.Error("payload not passed through verbatim")
			}
		})
	}
}
