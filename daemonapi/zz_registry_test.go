// SPDX-License-Identifier: AGPL-3.0-or-later

package daemonapi

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/pilot-protocol/common/crypto"
	"github.com/pilot-protocol/common/protocol"
	registry "github.com/pilot-protocol/common/registry/client"
)

// fakePlugin is a minimal Plugin implementation for registry tests.
type fakePlugin struct {
	name       string
	initCount  int
	stopCount  int
	initErr    error
	shutErr    error
	gotDaemon  Daemon
}

func (p *fakePlugin) Name() string             { return p.name }
func (p *fakePlugin) Init(d Daemon) error      { p.initCount++; p.gotDaemon = d; return p.initErr }
func (p *fakePlugin) Shutdown(context.Context) error { p.stopCount++; return p.shutErr }

// fakeDaemon is the smallest Daemon implementation that compiles —
// every method panics. Tests don't call any method; they only use it
// to verify that registry plumbing flows Daemon through Init.
type fakeDaemon struct{}

func (fakeDaemon) Start() error                                  { panic("not implemented") }
func (fakeDaemon) Stop() error                                   { panic("not implemented") }
func (fakeDaemon) NodeID() uint32                                { return 42 }
func (fakeDaemon) Identity() *crypto.Identity                    { return nil }
func (fakeDaemon) IdentityPath() string                          { return "" }
func (fakeDaemon) Sign([]byte) []byte                            { return nil }
func (fakeDaemon) AdminToken() string                            { return "" }
func (fakeDaemon) TrustAutoApprove() bool                        { return false }
func (fakeDaemon) Addr() protocol.Addr                           { return protocol.Addr{} }
func (fakeDaemon) DialConnection(protocol.Addr, uint16) (Connection, error) { panic("not implemented") }
func (fakeDaemon) DialConnectionContext(context.Context, protocol.Addr, uint16) (Connection, error) { panic("not implemented") }
func (fakeDaemon) SendData(Connection, []byte) error             { panic("not implemented") }
func (fakeDaemon) SendDatagram(protocol.Addr, uint16, []byte) error { panic("not implemented") }
func (fakeDaemon) CloseConnection(Connection)                    { panic("not implemented") }
func (fakeDaemon) NewConnReadWriter(Connection) ConnReadWriter   { panic("not implemented") }
func (fakeDaemon) Ports() PortAllocator                          { return nil }
func (fakeDaemon) Tunnels() TunnelRegistry                       { return nil }
func (fakeDaemon) RegistryClient() *registry.Client              { return nil }
func (fakeDaemon) RegConnListNodes(uint16, string) (map[string]any, error) { panic("not implemented") }
func (fakeDaemon) SetMemberTags(uint16, []string)                {}
func (fakeDaemon) PublishEvent(string, map[string]any)           {}
func (fakeDaemon) Bus() EventBus                                 { return nil }
func (fakeDaemon) GetTrustChecker() TrustChecker                 { return nil }
func (fakeDaemon) RegisterTrustChecker(TrustChecker)             {}
func (fakeDaemon) HandshakeService() HandshakeService            { return nil }
func (fakeDaemon) RegisterHandshakeService(HandshakeService)     {}
func (fakeDaemon) TrustedPeers() []HandshakeTrustRecord          { return nil }
func (fakeDaemon) HandshakeRevokeTrust(uint32) error             { return nil }
func (fakeDaemon) HandshakeSendRequest(uint32, string) error     { return nil }
func (fakeDaemon) RegisterPolicyManager(PolicyManager)           {}
func (fakeDaemon) SetWebhookURL(string)                          {}
func (fakeDaemon) RegisterWebhookManager(WebhookManager)         {}

// Compile-time check that fakeDaemon satisfies Daemon — also a
// sanity check that the interface compiles together.
var _ Daemon = fakeDaemon{}

// Compile-time check Ed25519 keys still type-check through Identity
// (catching accidental import-path regressions).
var _ ed25519.PublicKey = ed25519.PublicKey(nil)

func TestRegisterAndLoadAll(t *testing.T) {
	resetRegistry()
	defer resetRegistry()

	p1 := &fakePlugin{name: "alpha"}
	p2 := &fakePlugin{name: "beta"}
	RegisterPlugin("alpha", func() Plugin { return p1 })
	RegisterPlugin("beta", func() Plugin { return p2 })

	if got := Registered(); len(got) != 2 || got[0] != "alpha" || got[1] != "beta" {
		t.Fatalf("Registered = %v, want [alpha beta]", got)
	}

	d := fakeDaemon{}
	loaded, err := LoadAll(d)
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("loaded %d plugins, want 2", len(loaded))
	}
	if p1.initCount != 1 || p2.initCount != 1 {
		t.Errorf("Init counts: alpha=%d beta=%d, want 1 each", p1.initCount, p2.initCount)
	}
	if p1.gotDaemon != d || p2.gotDaemon != d {
		t.Error("plugins did not receive the daemon")
	}
}

func TestRegisterDuplicatePanics(t *testing.T) {
	resetRegistry()
	defer resetRegistry()
	RegisterPlugin("dup", func() Plugin { return &fakePlugin{name: "dup"} })

	defer func() {
		if recover() == nil {
			t.Error("expected panic on duplicate registration")
		}
	}()
	RegisterPlugin("dup", func() Plugin { return &fakePlugin{name: "dup2"} })
}

func TestLoadAllStopsOnFirstError(t *testing.T) {
	resetRegistry()
	defer resetRegistry()
	good := &fakePlugin{name: "good"}
	bad := &fakePlugin{name: "tango", initErr: errors.New("boom")}
	RegisterPlugin("good", func() Plugin { return good })
	RegisterPlugin("tango", func() Plugin { return bad })

	loaded, err := LoadAll(fakeDaemon{})
	if err == nil {
		t.Fatal("expected error from failing Init")
	}
	if len(loaded) != 1 || loaded[0].Name() != "good" {
		t.Errorf("partial-load result = %v, want [good]", loaded)
	}
}

func TestShutdownAllReverseOrder(t *testing.T) {
	resetRegistry()
	defer resetRegistry()
	var order []string
	RegisterPlugin("first", func() Plugin {
		return &orderedPlugin{n: "first", order: &order}
	})
	RegisterPlugin("second", func() Plugin {
		return &orderedPlugin{n: "second", order: &order}
	})
	RegisterPlugin("third", func() Plugin {
		return &orderedPlugin{n: "third", order: &order}
	})
	loaded, err := LoadAll(fakeDaemon{})
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if err := ShutdownAll(context.Background(), loaded); err != nil {
		t.Fatalf("ShutdownAll: %v", err)
	}
	if len(order) != 3 || order[0] != "third" || order[1] != "second" || order[2] != "first" {
		t.Errorf("shutdown order = %v, want [third second first]", order)
	}
}

type orderedPlugin struct {
	n     string
	order *[]string
}

func (p *orderedPlugin) Name() string                  { return p.n }
func (p *orderedPlugin) Init(Daemon) error             { return nil }
func (p *orderedPlugin) Shutdown(context.Context) error { *p.order = append(*p.order, p.n); return nil }
