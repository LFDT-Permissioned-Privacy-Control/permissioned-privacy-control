package policybundle

import (
	"fmt"
	"strconv"
	"strings"
)

// Check array dimensions and tuple expansion before the ABI library constructs
// reflect types. The ABI library remains the semantic authority. Metadata we
// do not interpret is retained in canonical JSON and its digest.
func checkABIBudget(value any, limits Limits) error {
	entries, ok := value.([]any)
	if !ok {
		return fmt.Errorf("abi must be an explicit array")
	}
	if len(entries) > limits.MaxABIEntries {
		return fmt.Errorf("ABI entry budget exceeded")
	}
	count := len(entries)
	for _, entry := range entries {
		object, ok := entry.(map[string]any)
		if !ok {
			return fmt.Errorf("invalid ABI entry")
		}
		for _, name := range []string{"inputs", "outputs"} {
			if args, present := object[name]; present {
				if _, err := abiArgumentsLayout(args, 0, &count, limits); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// An ABI dynamic value occupies one encoded head word, but its reflected Go
// type can still contain arbitrarily large fixed arrays. Track both before
// asking the ABI library to construct either type. Expansion units conservatively
// bound materialized primitive/slice/string fields, including tuple children.
type abiLayout struct {
	head, expansion int
	dynamic         bool
}

func abiArgumentsLayout(value any, depth int, count *int, limits Limits) (abiLayout, error) {
	args, ok := value.([]any)
	if !ok {
		return abiLayout{}, fmt.Errorf("ABI arguments must be arrays")
	}
	var layout abiLayout
	for _, arg := range args {
		if *count >= limits.MaxABIEntries {
			return abiLayout{}, fmt.Errorf("ABI entry/argument budget exceeded")
		}
		*count = *count + 1
		object, ok := arg.(map[string]any)
		if !ok {
			return abiLayout{}, fmt.Errorf("invalid ABI argument")
		}
		child, err := abiArgumentLayout(object, depth, count, limits)
		if err != nil {
			return abiLayout{}, err
		}
		if child.head > limits.MaxExpandedABIHeadSlots-layout.head || child.expansion > limits.MaxExpandedABIHeadSlots-layout.expansion {
			return abiLayout{}, fmt.Errorf("ABI head/type expansion budget exceeded")
		}
		layout.head += child.head
		layout.expansion += child.expansion
		layout.dynamic = layout.dynamic || child.dynamic
	}
	return layout, nil
}

func abiArgumentLayout(arg map[string]any, depth int, count *int, limits Limits) (abiLayout, error) {
	typ, ok := arg["type"].(string)
	if !ok || depth >= limits.MaxABITypeDepth {
		return abiLayout{}, fmt.Errorf("invalid ABI type or type-depth budget exceeded")
	}
	base, suffix, _ := strings.Cut(typ, "[")
	if suffix != "" {
		suffix = "[" + suffix
	}
	arrayDepth := strings.Count(suffix, "[")
	if arrayDepth >= limits.MaxABITypeDepth-depth {
		return abiLayout{}, fmt.Errorf("ABI type-depth budget exceeded")
	}
	layout := abiLayout{head: 1, expansion: 1, dynamic: base == "string" || base == "bytes"}
	if base == "tuple" {
		var err error
		// An array of tuples wraps every component. Its dimensions count
		// along the same path as the tuple and the component's own suffix.
		layout, err = abiArgumentsLayout(arg["components"], depth+arrayDepth+1, count, limits)
		if err != nil {
			return abiLayout{}, err
		}
	}
	for suffix != "" {
		depth++
		if depth >= limits.MaxABITypeDepth || suffix[0] != '[' {
			return abiLayout{}, fmt.Errorf("invalid ABI array or type-depth budget exceeded")
		}
		end := strings.IndexByte(suffix, ']')
		if end < 0 {
			return abiLayout{}, fmt.Errorf("invalid ABI array")
		}
		dimension := suffix[1:end]
		suffix = suffix[end+1:]
		if dimension == "" {
			// Slice indirection bounds this enclosing reflected layout. The
			// element layout was already checked before reaching this suffix.
			layout.dynamic = true
			layout.head, layout.expansion = 1, 1
			continue
		}
		for _, c := range dimension {
			if c < '0' || c > '9' {
				return abiLayout{}, fmt.Errorf("invalid ABI array dimension")
			}
		}
		n, err := strconv.ParseUint(dimension, 10, 64)
		if err != nil || n > uint64(limits.MaxExpandedABIHeadSlots) || (layout.expansion > 0 && n > uint64(limits.MaxExpandedABIHeadSlots/layout.expansion)) || (!layout.dynamic && layout.head > 0 && n > uint64(limits.MaxExpandedABIHeadSlots/layout.head)) {
			return abiLayout{}, fmt.Errorf("ABI expanded array/type budget exceeded")
		}
		layout.expansion *= int(n)
		if !layout.dynamic {
			layout.head *= int(n)
		}
	}
	if layout.dynamic {
		layout.head = 1
	}
	return layout, nil
}
