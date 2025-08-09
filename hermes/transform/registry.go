package transform

import (
	"fmt"
	"reflect"
	"sync"
)

// Transformer runs on concrete T. No context; matches builder.WireWithTransformer.
type Transformer[T any] func(T) (T, error)

var (
	mu  sync.RWMutex
	reg = map[string]map[string]any{} // datatype -> name -> Transformer[T] (stored as any)
)

// Register binds a named transformer for a specific datatype namespace.
func Register[T any](datatype, name string, fn Transformer[T]) {
	if datatype == "" || name == "" || fn == nil {
		panic("transform: datatype, name, fn required")
	}
	mu.Lock()
	defer mu.Unlock()
	m, ok := reg[datatype]
	if !ok {
		m = make(map[string]any)
		reg[datatype] = m
	}
	if _, dup := m[name]; dup {
		panic("transform: duplicate " + datatype + "/" + name)
	}
	m[name] = fn
}

// Resolve returns the concrete transformers for T in the order requested.
func Resolve[T any](datatype string, names []string) ([]Transformer[T], error) {
	mu.RLock()
	defer mu.RUnlock()
	m, ok := reg[datatype]
	if !ok {
		return nil, fmt.Errorf("transform: no registry for %q", datatype)
	}
	out := make([]Transformer[T], 0, len(names))
	for _, n := range names {
		raw, ok := m[n]
		if !ok {
			return nil, fmt.Errorf("transform: %q not found in %q", n, datatype)
		}
		fn, ok := raw.(Transformer[T])
		if !ok {
			return nil, fmt.Errorf("transform: type mismatch for %q in %q", n, datatype)
		}
		out = append(out, fn)
	}
	return out, nil
}

// ApplyDynamic applies named transformers in-order to a value of the correct concrete type.
// v must be the exact T (not *T). Returns the new T as interface{}.
func ApplyDynamic(datatype string, v any, names []string) (any, error) {
	mu.RLock()
	defer mu.RUnlock()
	m, ok := reg[datatype]
	if !ok {
		return nil, fmt.Errorf("transform: no registry for %q", datatype)
	}
	cur := v
	for _, n := range names {
		raw, ok := m[n]
		if !ok {
			return nil, fmt.Errorf("transform: %q not found in %q", n, datatype)
		}
		fn := reflect.ValueOf(raw)
		if fn.Kind() != reflect.Func || fn.Type().NumIn() != 1 || fn.Type().NumOut() != 2 {
			return nil, fmt.Errorf("transform: invalid function shape for %q/%q", datatype, n)
		}
		in := reflect.ValueOf(cur)
		if !in.IsValid() || in.Type() != fn.Type().In(0) {
			return nil, fmt.Errorf("transform: type mismatch for %q/%q", datatype, n)
		}
		out := fn.Call([]reflect.Value{in})
		if !out[1].IsNil() {
			return nil, out[1].Interface().(error)
		}
		cur = out[0].Interface()
	}
	return cur, nil
}
