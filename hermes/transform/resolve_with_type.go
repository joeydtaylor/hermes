// transform/resolve_with_type.go
package transform

import (
	"fmt"
	"reflect"
)

// ResolveWithType returns adapters (any->any) plus the concrete element type T
// expected by all transformers for the given datatype. All transforms must have
// signature: func(T) (T, error) with the SAME T.
func ResolveWithType(datatype string, names []string) ([]func(any) (any, error), reflect.Type, error) {
	mu.RLock()
	defer mu.RUnlock()

	m, ok := reg[datatype]
	if !ok {
		return nil, nil, fmt.Errorf("transform: no registry for %q", datatype)
	}

	var elemType reflect.Type
	out := make([]func(any) (any, error), 0, len(names))

	for idx, n := range names {
		raw, ok := m[n]
		if !ok || raw == nil {
			return nil, nil, fmt.Errorf("transform: %q not found in %q", n, datatype)
		}

		fnVal := reflect.ValueOf(raw)
		fnTyp := fnVal.Type()
		if fnTyp.Kind() != reflect.Func || fnTyp.NumIn() != 1 || fnTyp.NumOut() != 2 || fnTyp.Out(1) != reflect.TypeOf((*error)(nil)).Elem() {
			return nil, nil, fmt.Errorf("transform: %q has unexpected signature", n)
		}
		inTyp := fnTyp.In(0)
		outTyp := fnTyp.Out(0)
		if outTyp != inTyp {
			return nil, nil, fmt.Errorf("transform: %q must return the same type it accepts", n)
		}

		if idx == 0 {
			elemType = inTyp
		} else if inTyp != elemType {
			return nil, nil, fmt.Errorf("transform: %q type %v mismatches chain %v", n, inTyp, elemType)
		}

		adapt := func(v any) (any, error) {
			arg := reflect.ValueOf(v)
			if !arg.IsValid() || !arg.Type().AssignableTo(elemType) {
				if !arg.IsValid() {
					arg = reflect.Zero(elemType)
				} else if arg.Type().ConvertibleTo(elemType) {
					arg = arg.Convert(elemType)
				} else {
					return v, fmt.Errorf("transform: value type %v not assignable to %v", arg.Type(), elemType)
				}
			}
			res := fnVal.Call([]reflect.Value{arg})
			outv := res[0].Interface()
			if e, _ := res[1].Interface().(error); e != nil {
				return outv, e
			}
			return outv, nil
		}
		out = append(out, adapt)
	}

	if elemType == nil {
		return out, nil, fmt.Errorf("transform: empty chain")
	}
	return out, elemType, nil
}
