package adapter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"unicode/utf8"
)

func decodeJSON(raw []byte) (any, error) {
	if !utf8.Valid(raw) {
		return nil, fmt.Errorf("invalid UTF-8")
	}
	// encoding/json replaces unpaired UTF-16 surrogates. Reject that ambiguity
	// before token decoding, while preserving valid surrogate pairs.
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			break
		}
		if raw[i] != 'u' || i+4 >= len(raw) {
			continue
		}
		code, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if err != nil {
			continue
		}
		i += 4
		if code >= 0xDC00 && code <= 0xDFFF {
			return nil, fmt.Errorf("unpaired surrogate")
		}
		if code >= 0xD800 && code <= 0xDBFF {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return nil, fmt.Errorf("unpaired surrogate")
			}
			low, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
			if err != nil || low < 0xDC00 || low > 0xDFFF {
				return nil, fmt.Errorf("unpaired surrogate")
			}
			i += 6
		}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	value, err := jsonValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing JSON data")
	}
	return value, nil
}

func jsonValue(dec *json.Decoder, depth int) (any, error) {
	if depth > 256 {
		return nil, fmt.Errorf("JSON nesting exceeds inspection limit")
	}
	token, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch token {
	case json.Delim('{'):
		result := make(map[string]any)
		for dec.More() {
			key, err := dec.Token()
			if err != nil {
				return nil, err
			}
			name, ok := key.(string)
			if !ok {
				return nil, fmt.Errorf("invalid object key")
			}
			if _, ok := result[name]; ok {
				return nil, fmt.Errorf("duplicate object key")
			}
			value, err := jsonValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			result[name] = value
		}
		_, err := dec.Token()
		return result, err
	case json.Delim('['):
		result := []any{}
		for dec.More() {
			value, err := jsonValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			result = append(result, value)
		}
		_, err := dec.Token()
		return result, err
	default:
		if _, ok := token.(json.Delim); ok {
			return nil, fmt.Errorf("unexpected delimiter")
		}
		return token, nil
	}
}
