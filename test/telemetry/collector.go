// Package telemetry reads the upstream Collector's OTLP JSON file exporter.
// It is shared only by component and kind acceptance fixtures.
package telemetry

import (
	"bytes"
	"encoding/json"
	"fmt"
)

const CollectorImage = "otel/opentelemetry-collector-contrib:0.120.0@sha256:85ac41c2db88d0df9bd6145e608a3cb023f5d8443868adbfbbf66efb51087917"

type Span struct {
	TraceID, ID, ParentID, Service, Name string
	Attributes                           map[string]string
}

// Read ignores only an incomplete final line while the exporter is writing.
func Read(raw []byte) ([]Span, error) {
	var spans []Span
	lines := bytes.Split(raw, []byte{'\n'})
	for i, line := range lines {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var export struct {
			ResourceSpans []struct {
				Resource   struct{ Attributes []attribute }
				ScopeSpans []struct {
					Spans []struct {
						TraceID, SpanID, ParentSpanID, Name string
						Attributes                          []attribute
					}
				}
			}
		}
		if err := json.Unmarshal(line, &export); err != nil {
			if i == len(lines)-1 {
				break
			}
			return nil, fmt.Errorf("invalid Collector OTLP record: %w", err)
		}
		for _, resource := range export.ResourceSpans {
			service := ""
			for _, a := range resource.Resource.Attributes {
				if a.Key == "service.name" {
					service = a.Value.StringValue
				}
			}
			for _, scope := range resource.ScopeSpans {
				for _, span := range scope.Spans {
					s := Span{TraceID: span.TraceID, ID: span.SpanID, ParentID: span.ParentSpanID, Service: service, Name: span.Name, Attributes: map[string]string{}}
					for _, a := range span.Attributes {
						s.Attributes[a.Key] = a.Value.StringValue
					}
					spans = append(spans, s)
				}
			}
		}
	}
	return spans, nil
}

// Descends follows exported parents, not merely equality of trace IDs.
func Descends(spans []Span, child Span, ancestor string) bool {
	for range len(spans) + 1 {
		if child.ParentID == ancestor {
			return true
		}
		found := false
		for _, s := range spans {
			if s.TraceID == child.TraceID && s.ID == child.ParentID {
				child = s
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return false
}

type attribute struct {
	Key   string
	Value struct{ StringValue string }
}
