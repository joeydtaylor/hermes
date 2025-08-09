// codec/jsoncodec.go
package codec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

type Codec interface {
	Marshal(v any) ([]byte, error)
	Unmarshal(data []byte, v any) error
	ContentType() string
}

type jsonStrict struct{}

var JSONStrict Codec = jsonStrict{}

func (jsonStrict) Marshal(v any) ([]byte, error) {
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func (jsonStrict) Unmarshal(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("json decode: %w", err)
	}
	// Probe for trailing data (must be EOF)
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return fmt.Errorf("json trailing content")
	}
	return nil
}

func (jsonStrict) ContentType() string { return "application/json" }
