package strongswan

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	"github.com/strongswan/govici/vici"
)

type fakeViciClient struct {
	sasErr         error
	sasMsgs        []*vici.Message
	crtsErr        error
	crtsMsgs       []*vici.Message
	closeTriggered int
}

func (fvc *fakeViciClient) StreamedCommandRequest(cmd string, event string, _ *vici.Message) ([]*vici.Message, error) {
	if cmd == "list-sas" && event == "list-sa" {
		return fvc.sasMsgs, fvc.sasErr
	} else if cmd == "list-certs" && event == "list-cert" {
		return fvc.crtsMsgs, fvc.crtsErr
	} else {
		return nil, errors.New("invalid command")
	}
}

func (fvc *fakeViciClient) Close() error {
	fvc.closeTriggered++
	return nil
}

func TestCollector_Metrics(t *testing.T) {
	tests := []struct {
		name               string
		viciClientErr      error
		sasMsgsModifierFn  func(msgs *vici.Message)
		crtsMsgsModifierFn func() []*vici.Message
		viciSasSessionErr  error
		viciCrtsSessionErr error
		metricName         string
		wantMetricsHelp    string
		wantMetricsType    string
		wantMetricsLabels  string
		wantMetricsValue   int
		wantMetricsCount   int
	}{
		{
			name:             "connection error ike count",
			viciClientErr:    errors.New("some error"),
			metricName:       "strongswan_ike_count",
			wantMetricsHelp:  "Number of known IKEs",
			wantMetricsType:  "gauge",
			wantMetricsValue: 0,
			wantMetricsCount: 2,
		},
		{
			name:             "connection error crt count",
			viciClientErr:    errors.New("some error"),
			metricName:       "strongswan_crt_count",
			wantMetricsHelp:  "Number of X509 certificates",
			wantMetricsType:  "gauge",
			wantMetricsValue: 0,
			wantMetricsCount: 2,
		},
		{
			name:              "session error ike count",
			viciSasSessionErr: errors.New("some error"),
			metricName:        "strongswan_ike_count",
			wantMetricsHelp:   "Number of known IKEs",
			wantMetricsType:   "gauge",
			wantMetricsValue:  0,
			wantMetricsCount:  2,
		},
		{
			name:               "session error crt count",
			viciCrtsSessionErr: errors.New("some error"),
			metricName:         "strongswan_crt_count",
			wantMetricsHelp:    "Number of X509 certificates",
			wantMetricsType:    "gauge",
			wantMetricsValue:   0,
			wantMetricsCount:   2,
		},
		{
			name:             "empty result ike count",
			metricName:       "strongswan_ike_count",
			wantMetricsHelp:  "Number of known IKEs",
			wantMetricsType:  "gauge",
			wantMetricsValue: 0,
			wantMetricsCount: 2,
		},
		{
			name:             "empty list crt count",
			metricName:       "strongswan_crt_count",
			wantMetricsHelp:  "Number of X509 certificates",
			wantMetricsType:  "gauge",
			wantMetricsValue: 0,
			wantMetricsCount: 2,
		},
		{
			name: "empty result crt count",
			crtsMsgsModifierFn: func() []*vici.Message {
				return []*vici.Message{vici.NewMessage()}
			},
			metricName:       "strongswan_crt_count",
			wantMetricsHelp:  "Number of X509 certificates",
			wantMetricsType:  "gauge",
			wantMetricsValue: 0,
			wantMetricsCount: 2,
		},
		{
			name: "error vici msgs ike count",
			sasMsgsModifierFn: func(msgs *vici.Message) {
				msgs.Set("success", "no")
				msgs.Set("errmsg", "some error")
			},
			metricName:       "strongswan_ike_count",
			wantMetricsHelp:  "Number of known IKEs",
			wantMetricsType:  "gauge",
			wantMetricsValue: 0,
			wantMetricsCount: 2,
		},
		{
			name: "error vici msgs crt count",
			crtsMsgsModifierFn: func() []*vici.Message {
				crtMsg := vici.NewMessage()
				crtMsg.Set("success", "no")
				crtMsg.Set("errmsg", "some error")
				return []*vici.Message{crtMsg}
			},
			metricName:       "strongswan_crt_count",
			wantMetricsHelp:  "Number of X509 certificates",
			wantMetricsType:  "gauge",
			wantMetricsValue: 0,
			wantMetricsCount: 2,
		},
		{
			name: "one ike count",
			sasMsgsModifierFn: func(msgs *vici.Message) {
				msgs.Set("ike-name", vici.NewMessage())
			},
			metricName:       "strongswan_ike_count",
			wantMetricsHelp:  "Number of known IKEs",
			wantMetricsType:  "gauge",
			wantMetricsValue: 1,
			wantMetricsCount: 15,
		},
		{
			name: "two ike count",
			sasMsgsModifierFn: func(msgs *vici.Message) {
				msgs.Set("ike-name1", vici.NewMessage())
				msgs.Set("ike-name2", vici.NewMessage())
			},
			metricName:       "strongswan_ike_count",
			wantMetricsHelp:  "Number of known IKEs",
			wantMetricsType:  "gauge",
			wantMetricsValue: 2,
			wantMetricsCount: 28,
		},
		{
			name: "ike version & name & uniqueid",
			sasMsgsModifierFn: func(msgs *vici.Message) {
				ikeMsg := vici.NewMessage()
				ikeMsg.Set("version", 5)
				ikeMsg.Set("uniqueid", "some-unique-id")
				msgs.Set("ike-name", ikeMsg)
			},
			metricName:        "strongswan_ike_version",
			wantMetricsHelp:   "Version of this IKE",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `ike_id="some-unique-id",ike_name="ike-name"`,
			wantMetricsValue:  5,
			wantMetricsCount:  15,
		},
		{
			name: "ike status",
			sasMsgsModifierFn: func(msgs *vici.Message) {
				ikeMsg := vici.NewMessage()
				ikeMsg.Set("state", "ESTABLISHED")
				ikeMsg.Set("uniqueid", "some-unique-id")
				msgs.Set("ike-name", ikeMsg)
			},
			metricName:        "strongswan_ike_status",
			wantMetricsHelp:   "Status of this IKE",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `ike_id="some-unique-id",ike_name="ike-name"`,
			wantMetricsValue:  1,
			wantMetricsCount:  15,
		},
		{
			name: "ike initiator",
			sasMsgsModifierFn: func(msgs *vici.Message) {
				ikeMsg := vici.NewMessage()
				ikeMsg.Set("initiator", "yes")
				ikeMsg.Set("uniqueid", "some-unique-id")
				msgs.Set("ike-name", ikeMsg)
			},
			metricName:        "strongswan_ike_initiator",
			wantMetricsHelp:   "Flag if the server is the initiator for this connection",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `ike_id="some-unique-id",ike_name="ike-name"`,
			wantMetricsValue:  1,
			wantMetricsCount:  15,
		},
		{
			name: "ike NAT local",
			sasMsgsModifierFn: func(msgs *vici.Message) {
				ikeMsg := vici.NewMessage()
				ikeMsg.Set("nat-local", "yes")
				ikeMsg.Set("uniqueid", "some-unique-id")
				msgs.Set("ike-name", ikeMsg)
			},
			metricName:        "strongswan_ike_nat_local",
			wantMetricsHelp:   "Flag if the local endpoint is behind nat",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `ike_id="some-unique-id",ike_name="ike-name"`,
			wantMetricsValue:  1,
			wantMetricsCount:  15,
		},
		{
			name: "ike NAT remote",
			sasMsgsModifierFn: func(msgs *vici.Message) {
				ikeMsg := vici.NewMessage()
				ikeMsg.Set("nat-remote", "yes")
				ikeMsg.Set("uniqueid", "some-unique-id")
				msgs.Set("ike-name", ikeMsg)
			},
			metricName:        "strongswan_ike_nat_remote",
			wantMetricsHelp:   "Flag if the remote server is behind nat",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `ike_id="some-unique-id",ike_name="ike-name"`,
			wantMetricsValue:  1,
			wantMetricsCount:  15,
		},
		{
			name: "ike NAT fake",
			sasMsgsModifierFn: func(msgs *vici.Message) {
				ikeMsg := vici.NewMessage()
				ikeMsg.Set("nat-fake", "yes")
				ikeMsg.Set("uniqueid", "some-unique-id")
				msgs.Set("ike-name", ikeMsg)
			},
			metricName:        "strongswan_ike_nat_fake",
			wantMetricsHelp:   "Flag if NAT situation has been faked as responder",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `ike_id="some-unique-id",ike_name="ike-name"`,
			wantMetricsValue:  1,
			wantMetricsCount:  15,
		},
		{
			name: "ike NAT any",
			sasMsgsModifierFn: func(msgs *vici.Message) {
				ikeMsg := vici.NewMessage()
				ikeMsg.Set("nat-any", "yes")
				ikeMsg.Set("uniqueid", "some-unique-id")
				msgs.Set("ike-name", ikeMsg)
			},
			metricName:        "strongswan_ike_nat_any",
			wantMetricsHelp:   "Flag if any endpoint is behind a NAT (also if faked)",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `ike_id="some-unique-id",ike_name="ike-name"`,
			wantMetricsValue:  1,
			wantMetricsCount:  15,
		},
		{
			name: "ike encryption key",
			sasMsgsModifierFn: func(msgs *vici.Message) {
				ikeMsg := vici.NewMessage()
				ikeMsg.Set("encr-keysize", "1024")
				ikeMsg.Set("encr-alg", "SHA-256")
				ikeMsg.Set("dh-group", "DH")
				ikeMsg.Set("uniqueid", "some-unique-id")
				msgs.Set("ike-name", ikeMsg)
			},
			metricName:        "strongswan_ike_encryption_key_size",
			wantMetricsHelp:   "Key size of the encryption algorithm",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `algorithm="SHA-256",dh_group="DH",ike_id="some-unique-id",ike_name="ike-name"`,
			wantMetricsValue:  1024,
			wantMetricsCount:  15,
		},
		{
			name: "ike integrity key",
			sasMsgsModifierFn: func(msgs *vici.Message) {
				ikeMsg := vici.NewMessage()
				ikeMsg.Set("integ-keysize", "1024")
				ikeMsg.Set("integ-alg", "SHA-256")
				ikeMsg.Set("dh-group", "DH")
				ikeMsg.Set("uniqueid", "some-unique-id")
				msgs.Set("ike-name", ikeMsg)
			},
			metricName:        "strongswan_ike_integrity_key_size",
			wantMetricsHelp:   "Key size of the integrity algorithm",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `algorithm="SHA-256",dh_group="DH",ike_id="some-unique-id",ike_name="ike-name"`,
			wantMetricsValue:  1024,
			wantMetricsCount:  15,
		},
		{
			name: "ike established",
			sasMsgsModifierFn: func(msgs *vici.Message) {
				ikeMsg := vici.NewMessage()
				ikeMsg.Set("established", "565")
				ikeMsg.Set("uniqueid", "some-unique-id")
				msgs.Set("ike-name", ikeMsg)
			},
			metricName:        "strongswan_ike_established_seconds",
			wantMetricsHelp:   "Seconds since the IKE was established",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `ike_id="some-unique-id",ike_name="ike-name"`,
			wantMetricsValue:  565,
			wantMetricsCount:  15,
		},
		{
			name: "ike rekey",
			sasMsgsModifierFn: func(msgs *vici.Message) {
				ikeMsg := vici.NewMessage()
				ikeMsg.Set("rekey-time", "12")
				ikeMsg.Set("uniqueid", "some-unique-id")
				msgs.Set("ike-name", ikeMsg)
			},
			metricName:        "strongswan_ike_rekey_seconds",
			wantMetricsHelp:   "Seconds until the IKE will be rekeyed",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `ike_id="some-unique-id",ike_name="ike-name"`,
			wantMetricsValue:  12,
			wantMetricsCount:  15,
		},
		{
			name: "ike reauth",
			sasMsgsModifierFn: func(msgs *vici.Message) {
				ikeMsg := vici.NewMessage()
				ikeMsg.Set("reauth-time", "15")
				ikeMsg.Set("uniqueid", "some-unique-id")
				msgs.Set("ike-name", ikeMsg)
			},
			metricName:        "strongswan_ike_reauth_seconds",
			wantMetricsHelp:   "Seconds until the IKE will be reauthed",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `ike_id="some-unique-id",ike_name="ike-name"`,
			wantMetricsValue:  15,
			wantMetricsCount:  15,
		},
		{
			name: "ike children",
			sasMsgsModifierFn: func(msgs *vici.Message) {
				childMsg1 := vici.NewMessage()
				childMsg1.Set("uniqueid", "child1-unique-id")
				childMsg2 := vici.NewMessage()
				childMsg2.Set("uniqueid", "child2-unique-id")
				msgsChildren := vici.NewMessage()
				msgsChildren.Set("child-1", childMsg1)
				msgsChildren.Set("child-2", childMsg2)
				ikeMsg := vici.NewMessage()
				ikeMsg.Set("child-sas", msgsChildren)
				ikeMsg.Set("uniqueid", "some-unique-id")
				msgs.Set("ike-name", ikeMsg)
			},
			metricName:        "strongswan_ike_children_size",
			wantMetricsHelp:   "Count of children of this IKE",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `ike_id="some-unique-id",ike_name="ike-name"`,
			wantMetricsValue:  2,
			wantMetricsCount:  41,
		},
		{
			name: "ignore certs other than X509",
			crtsMsgsModifierFn: func() []*vici.Message {
				crtMsg := vici.NewMessage()
				crtMsg.Set("type", "OCSP_RESPONSE")
				return []*vici.Message{crtMsg}
			},
			metricName:       "strongswan_crt_count",
			wantMetricsHelp:  "Number of X509 certificates",
			wantMetricsType:  "gauge",
			wantMetricsValue: 0,
			wantMetricsCount: 2,
		},
		{
			name: "ignore certs with data",
			crtsMsgsModifierFn: func() []*vici.Message {
				crtMsg1 := vici.NewMessage()
				crtMsg1.Set("type", "X509")
				crtMsg1.Set("data", "123")

				crtMsg2 := vici.NewMessage()
				crtMsg2.Set("type", "X509")
				crt, err := createSingleX509Crt()
				if err != nil {
					return []*vici.Message{}
				}
				crtMsg2.Set("data", string(crt))

				return []*vici.Message{crtMsg1, crtMsg2}
			},
			metricName:       "strongswan_crt_count",
			wantMetricsHelp:  "Number of X509 certificates",
			wantMetricsType:  "gauge",
			wantMetricsValue: 1,
			wantMetricsCount: 3,
		},
		{
			name: "one cert count",
			crtsMsgsModifierFn: func() []*vici.Message {
				crtMsg := vici.NewMessage()
				crtMsg.Set("type", "X509")

				crt, err := createSingleX509Crt()
				if err != nil {
					return []*vici.Message{}
				}

				crtMsg.Set("data", string(crt))
				return []*vici.Message{crtMsg}
			},
			metricName:       "strongswan_crt_count",
			wantMetricsHelp:  "Number of X509 certificates",
			wantMetricsType:  "gauge",
			wantMetricsValue: 1,
			wantMetricsCount: 3,
		},
		{
			name: "two cert count",
			crtsMsgsModifierFn: func() []*vici.Message {
				crt1, crt2, err := createDoubleX509Crt()
				if err != nil {
					return []*vici.Message{}
				}

				crtMsg1 := vici.NewMessage()
				crtMsg1.Set("type", "X509")
				crtMsg1.Set("data", string(crt1))

				crtMsg2 := vici.NewMessage()
				crtMsg2.Set("type", "X509")
				crtMsg2.Set("data", string(crt2))

				return []*vici.Message{crtMsg1, crtMsg2}
			},
			metricName:       "strongswan_crt_count",
			wantMetricsHelp:  "Number of X509 certificates",
			wantMetricsType:  "gauge",
			wantMetricsValue: 2,
			wantMetricsCount: 4,
		},
		{
			name: "cert valid",
			crtsMsgsModifierFn: func() []*vici.Message {
				crtMsg := vici.NewMessage()
				crtMsg.Set("type", "X509")

				crt, err := createSingleX509Crt()
				if err != nil {
					return []*vici.Message{}
				}

				crtMsg.Set("data", string(crt))
				return []*vici.Message{crtMsg}
			},
			metricName:        "strongswan_crt_valid",
			wantMetricsHelp:   "X509 certificate validity",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `not_after="2124-01-01T12:00:00Z",not_before="2024-01-01T12:00:00Z",subject="O=Org1"`,
			wantMetricsValue:  1,
			wantMetricsCount:  3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sasMmsgs := vici.NewMessage()
			if tt.sasMsgsModifierFn != nil {
				tt.sasMsgsModifierFn(sasMmsgs)
			}
			crtsMmsgs := []*vici.Message{}
			if tt.crtsMsgsModifierFn != nil {
				crtsMmsgs = tt.crtsMsgsModifierFn()
			}
			c := NewCollector(func() (ViciClient, error) {
				return &fakeViciClient{sasMsgs: []*vici.Message{sasMmsgs},
						sasErr:   tt.viciSasSessionErr,
						crtsMsgs: crtsMmsgs,
						crtsErr:  tt.viciCrtsSessionErr},
					tt.viciClientErr
			})

			cnt := testutil.CollectAndCount(c)
			require.Equal(t, tt.wantMetricsCount, cnt, "metrics count")

			wantMetricsContent := fmt.Sprintf(`# HELP %s %s
# TYPE %s %s
%s{%s} %d
`, tt.metricName, tt.wantMetricsHelp, tt.metricName, tt.wantMetricsType, tt.metricName, tt.wantMetricsLabels, tt.wantMetricsValue)
			if err := testutil.CollectAndCompare(c, strings.NewReader(wantMetricsContent), tt.metricName); err != nil {
				t.Errorf("unexpected collecting result of '%s':\n%s", tt.metricName, err)
			}
		})
	}
}

func TestCollector_MetricsSaChild(t *testing.T) {
	tests := []struct {
		name              string
		msgModifierFn     func(msg *vici.Message)
		metricName        string
		wantMetricsHelp   string
		wantMetricsType   string
		wantMetricsLabels string
		wantMetricsValue  int
	}{
		{
			name: "sa status",
			msgModifierFn: func(msg *vici.Message) {
				msg.Set("state", "INSTALLED")
				msg.Set("local-ts", []string{"local-ts-1", "local-ts-2"})
				msg.Set("remote-ts", []string{"remote-ts-1", "remote-ts-2"})
			},
			metricName:        "strongswan_sa_status",
			wantMetricsHelp:   "Status of this child sa",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `child_id="sa-unique-id",child_name="sa-name",ike_id="some-unique-id",ike_name="ike-name",local_ts="local-ts-1;local-ts-2",remote_ts="remote-ts-1;remote-ts-2"`,
			wantMetricsValue:  0,
		},
		{
			name: "sa encapsulation",
			msgModifierFn: func(msg *vici.Message) {
				msg.Set("encap", "yes")
			},
			metricName:        "strongswan_sa_encap",
			wantMetricsHelp:   "Forced Encapsulation in UDP Packets",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `child_id="sa-unique-id",child_name="sa-name",ike_id="some-unique-id",ike_name="ike-name"`,
			wantMetricsValue:  1,
		},
		{
			name: "sa encryption key",
			msgModifierFn: func(msg *vici.Message) {
				msg.Set("encr-keysize", "1024")
				msg.Set("encr-alg", "SHA-256")
				msg.Set("dh-group", "DH")
			},
			metricName:        "strongswan_sa_encryption_key_size",
			wantMetricsHelp:   "Key size of the encryption algorithm",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `algorithm="SHA-256",child_id="sa-unique-id",child_name="sa-name",dh_group="DH",ike_id="some-unique-id",ike_name="ike-name"`,
			wantMetricsValue:  1024,
		},
		{
			name: "sa integrity key",
			msgModifierFn: func(msg *vici.Message) {
				msg.Set("integ-keysize", "1024")
				msg.Set("integ-alg", "SHA-256")
				msg.Set("dh-group", "DH")
			},
			metricName:        "strongswan_sa_integrity_key_size",
			wantMetricsHelp:   "Key size of the integrity algorithm",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `algorithm="SHA-256",child_id="sa-unique-id",child_name="sa-name",dh_group="DH",ike_id="some-unique-id",ike_name="ike-name"`,
			wantMetricsValue:  1024,
		},
		{
			name: "sa bytes in",
			msgModifierFn: func(msg *vici.Message) {
				msg.Set("bytes-in", 125)
				msg.Set("local-ts", []string{"local-ts-1", "local-ts-2"})
				msg.Set("remote-ts", []string{"remote-ts-1", "remote-ts-2"})
			},
			metricName:        "strongswan_sa_inbound_bytes",
			wantMetricsHelp:   "Number of input bytes processed",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `child_id="sa-unique-id",child_name="sa-name",ike_id="some-unique-id",ike_name="ike-name",local_ts="local-ts-1;local-ts-2",remote_ts="remote-ts-1;remote-ts-2"`,
			wantMetricsValue:  125,
		},
		{
			name: "sa packets in",
			msgModifierFn: func(msg *vici.Message) {
				msg.Set("packets-in", 125)
				msg.Set("local-ts", []string{"local-ts-1", "local-ts-2"})
				msg.Set("remote-ts", []string{"remote-ts-1", "remote-ts-2"})
			},
			metricName:        "strongswan_sa_inbound_packets",
			wantMetricsHelp:   "Number of input packets processed",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `child_id="sa-unique-id",child_name="sa-name",ike_id="some-unique-id",ike_name="ike-name",local_ts="local-ts-1;local-ts-2",remote_ts="remote-ts-1;remote-ts-2"`,
			wantMetricsValue:  125,
		},
		{
			name: "sa last in seconds",
			msgModifierFn: func(msg *vici.Message) {
				msg.Set("use-in", 60)
				msg.Set("local-ts", []string{"local-ts-1", "local-ts-2"})
				msg.Set("remote-ts", []string{"remote-ts-1", "remote-ts-2"})
			},
			metricName:        "strongswan_sa_last_inbound_seconds",
			wantMetricsHelp:   "Number of seconds since the last inbound packet was received",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `child_id="sa-unique-id",child_name="sa-name",ike_id="some-unique-id",ike_name="ike-name",local_ts="local-ts-1;local-ts-2",remote_ts="remote-ts-1;remote-ts-2"`,
			wantMetricsValue:  60,
		},
		{
			name: "sa bytes out",
			msgModifierFn: func(msg *vici.Message) {
				msg.Set("bytes-out", 125)
				msg.Set("local-ts", []string{"local-ts-1", "local-ts-2"})
				msg.Set("remote-ts", []string{"remote-ts-1", "remote-ts-2"})
			},
			metricName:        "strongswan_sa_outbound_bytes",
			wantMetricsHelp:   "Number of output bytes processed",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `child_id="sa-unique-id",child_name="sa-name",ike_id="some-unique-id",ike_name="ike-name",local_ts="local-ts-1;local-ts-2",remote_ts="remote-ts-1;remote-ts-2"`,
			wantMetricsValue:  125,
		},
		{
			name: "sa packets out",
			msgModifierFn: func(msg *vici.Message) {
				msg.Set("packets-out", 125)
				msg.Set("local-ts", []string{"local-ts-1", "local-ts-2"})
				msg.Set("remote-ts", []string{"remote-ts-1", "remote-ts-2"})
			},
			metricName:        "strongswan_sa_outbound_packets",
			wantMetricsHelp:   "Number of output packets processed",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `child_id="sa-unique-id",child_name="sa-name",ike_id="some-unique-id",ike_name="ike-name",local_ts="local-ts-1;local-ts-2",remote_ts="remote-ts-1;remote-ts-2"`,
			wantMetricsValue:  125,
		},
		{
			name: "sa last out seconds",
			msgModifierFn: func(msg *vici.Message) {
				msg.Set("use-out", 60)
				msg.Set("local-ts", []string{"local-ts-1", "local-ts-2"})
				msg.Set("remote-ts", []string{"remote-ts-1", "remote-ts-2"})
			},
			metricName:        "strongswan_sa_last_outbound_seconds",
			wantMetricsHelp:   "Number of seconds since the last outbound packet was sent",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `child_id="sa-unique-id",child_name="sa-name",ike_id="some-unique-id",ike_name="ike-name",local_ts="local-ts-1;local-ts-2",remote_ts="remote-ts-1;remote-ts-2"`,
			wantMetricsValue:  60,
		},
		{
			name: "sa last established seconds",
			msgModifierFn: func(msg *vici.Message) {
				msg.Set("install-time", 32)
			},
			metricName:        "strongswan_sa_established_seconds",
			wantMetricsHelp:   "Seconds since the child SA was established",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `child_id="sa-unique-id",child_name="sa-name",ike_id="some-unique-id",ike_name="ike-name"`,
			wantMetricsValue:  32,
		},
		{
			name: "sa last rekey seconds",
			msgModifierFn: func(msg *vici.Message) {
				msg.Set("rekey-time", 33)
			},
			metricName:        "strongswan_sa_rekey_seconds",
			wantMetricsHelp:   "Seconds until the child SA will be rekeyed",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `child_id="sa-unique-id",child_name="sa-name",ike_id="some-unique-id",ike_name="ike-name"`,
			wantMetricsValue:  33,
		},
		{
			name: "sa lifetime seconds",
			msgModifierFn: func(msg *vici.Message) {
				msg.Set("life-time", 34)
			},
			metricName:        "strongswan_sa_lifetime_seconds",
			wantMetricsHelp:   "Seconds until the lifetime expires",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `child_id="sa-unique-id",child_name="sa-name",ike_id="some-unique-id",ike_name="ike-name"`,
			wantMetricsValue:  34,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			saMsg := vici.NewMessage()
			saMsg.Set("name", "sa-name")
			saMsg.Set("uniqueid", "sa-unique-id")
			if tt.msgModifierFn != nil {
				tt.msgModifierFn(saMsg)
			}
			ikeMsg := vici.NewMessage()
			ikeMsg.Set("child-sas", map[string]any{"child-sa-name": saMsg})
			ikeMsg.Set("uniqueid", "some-unique-id")
			msgs := vici.NewMessage()
			msgs.Set("ike-name", ikeMsg)
			c := NewCollector(func() (ViciClient, error) {
				return &fakeViciClient{sasMsgs: []*vici.Message{msgs}}, nil
			})

			cnt := testutil.CollectAndCount(c)
			require.Equal(t, 28, cnt, "metrics count")

			wantMetricsContent := fmt.Sprintf(`# HELP %s %s
# TYPE %s %s
%s{%s} %d
`, tt.metricName, tt.wantMetricsHelp, tt.metricName, tt.wantMetricsType, tt.metricName, tt.wantMetricsLabels, tt.wantMetricsValue)
			if err := testutil.CollectAndCompare(c, strings.NewReader(wantMetricsContent), tt.metricName); err != nil {
				t.Errorf("unexpected collecting result of child '%s':\n%s", tt.metricName, err)
			}
		})
	}
}

func createSingleX509Crt() ([]byte, error) {
	tz, err := time.LoadLocation("UTC")
	if err != nil {
		return nil, err
	}

	return createX509Crt(
		pkix.Name{Organization: []string{"Org1"}},
		time.Date(2024, 1, 1, 12, 0, 0, 0, tz),
		time.Date(2124, 1, 1, 12, 0, 0, 0, tz),
	)
}

func createDoubleX509Crt() ([]byte, []byte, error) {
	tz, err := time.LoadLocation("UTC")
	if err != nil {
		return nil, nil, err
	}

	notBefore := time.Date(2024, 1, 1, 12, 0, 0, 0, tz)
	notAfter := time.Date(2124, 1, 1, 12, 0, 0, 0, tz)

	crt1, err := createX509Crt(
		pkix.Name{Organization: []string{"Org1"}},
		notBefore, notAfter,
	)
	if err != nil {
		return nil, nil, err
	}

	crt2, err := createX509Crt(
		pkix.Name{Organization: []string{"Org2"}},
		notBefore, notAfter,
	)
	if err != nil {
		return nil, nil, err
	}

	return crt1, crt2, nil
}

func createX509Crt(subject pkix.Name, notBefore, notAfter time.Time) ([]byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      subject,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}

	return x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
}
