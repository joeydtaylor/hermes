// hermes/types_registry.go
package hermes

import (
	"fmt"
	"reflect"

	"github.com/joeydtaylor/hermes/hermes/codec"
)

type typeBinding struct {
	name  string
	codec codec.Codec
	zero  func() any
}

var typeReg = make(map[string]typeBinding)

// Register a concrete type to a symbolic name with a codec.
func RegisterType[T any](name string, c codec.Codec) error {
	if name == "" || c == nil {
		return fmt.Errorf("type name and codec required")
	}
	if _, ok := typeReg[name]; ok {
		return fmt.Errorf("type %q already registered", name)
	}
	typeReg[name] = typeBinding{
		name:  name,
		codec: c,
		zero:  func() any { var x T; return &x },
	}
	return nil
}

func MustRegisterType[T any](name string, c codec.Codec) {
	if err := RegisterType[T](name, c); err != nil {
		panic(err)
	}
}

func getTypeBinding(name string) (typeBinding, bool) {
	b, ok := typeReg[name]
	return b, ok
}

// ValidateAndCanonicalize asserts bytes decode into the registered type,
// then re-encodes canonically via the codec (round-trip).
func ValidateAndCanonicalize(typeName string, data []byte) (contentType string, out []byte, err error) {
	b, ok := getTypeBinding(typeName)
	if !ok {
		return "", nil, fmt.Errorf("unregistered type %q", typeName)
	}
	dst := b.zero() // pointer to T
	if err := b.codec.Unmarshal(data, dst); err != nil {
		return "", nil, fmt.Errorf("payload type %q invalid: %w", typeName, err)
	}
	rv := reflect.ValueOf(dst)
	if rv.Kind() != reflect.Ptr || rv.IsNil() {
		return "", nil, fmt.Errorf("internal: zero() did not return pointer")
	}
	raw, err := b.codec.Marshal(rv.Elem().Interface())
	if err != nil {
		return "", nil, fmt.Errorf("re-encode: %w", err)
	}
	return b.codec.ContentType(), raw, nil
}

// add to file:

// GetTypeBinding exposes a safe view for internal packages.
func GetTypeBinding(name string) (struct {
	Name  string
	Codec codec.Codec
	Zero  func() any
}, bool) {
	b, ok := getTypeBinding(name)
	if !ok {
		return struct {
			Name  string
			Codec codec.Codec
			Zero  func() any
		}{}, false
	}
	return struct {
		Name  string
		Codec codec.Codec
		Zero  func() any
	}{Name: b.name, Codec: b.codec, Zero: b.zero}, true
}

// FindTypeNameForValue helps transformer wrappers assert the registered type of T.
func FindTypeNameForValue[T any]() (string, bool) {
	// We can only map from registered names -> types; iterate once.
	for n, b := range typeReg {
		// Compare types by creating a zero T and comparing its type to the registry’s zero.
		var t T
		if reflect.TypeOf(b.zero()).Elem() == reflect.TypeOf(&t).Elem() {
			return n, true
		}
	}
	return "", false
}
