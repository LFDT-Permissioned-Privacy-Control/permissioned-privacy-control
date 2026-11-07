package executionfacts_test

import (
	"testing"

	"privacy-proxy/internal/executionfacts"
)

func TestLifecycleMissingCreationContextUsesOnlyUnanimousImmediateChildren(t *testing.T) {
	root := frame("CALL", alice, proxy, "0x7")
	creation := frame("CREATE", proxy, lib, "0x0")
	delete(creation, "to")
	creation["error"] = "execution reverted"
	child := frame("DELEGATECALL", lib, other, "0x0")
	creation["calls"] = []any{child}
	root["calls"] = []any{creation}
	raw := encode(t, root)
	tree, err := executionfacts.Parse(raw, expected(), executionfacts.GethLifecycleWithLogsProfile(), executionfacts.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	r := tree.Records()
	if r[1].To.Known || !r[1].ContextFromChildren || r[1].StorageAddress != addr(lib) || r[2].StorageAddress != addr(lib) || r[2].CallerAddress != addr(proxy) || !r[2].AncestorFailed {
		t.Fatal("raw destination/context/delegated caller/failed ancestor changed", r)
	}
	legacy, err := executionfacts.Parse(raw, expected(), executionfacts.GethCallTracerWithLogsProfile(), executionfacts.DefaultLimits())
	if err != nil || legacy.Records()[1].StorageAddress.Known || !legacy.Requirements().UnresolvedExecutionContext {
		t.Fatal("legacy profile acquired a new recovery behavior", err)
	}
	creation["calls"] = []any{child, frame("CALL", other, proxy, "0x0")}
	if _, err := executionfacts.Parse(encode(t, root), expected(), executionfacts.GethLifecycleWithLogsProfile(), executionfacts.DefaultLimits()); err == nil {
		t.Fatal("conflicting direct children manufactured creation context")
	}
	delete(creation, "calls")
	tree, err = executionfacts.Parse(encode(t, root), expected(), executionfacts.GethLifecycleWithLogsProfile(), executionfacts.DefaultLimits())
	if err != nil || tree.Records()[1].StorageAddress.Known || !tree.Requirements().UnresolvedExecutionContext {
		t.Fatal("childless failed leaf was not kept honestly unresolved", err)
	}
}
