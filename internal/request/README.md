# Request adaptation boundary

This directory is reserved for future HTTP/gRPC input normalization and payload decoding. The scaffold currently uses the official OPA-Envoy plugin directly and does not implement the Wiki's full normalization contract.

Add implementation and adjacent `*_test.go` files when a concrete gap arises. Output types should come from `egress-gateway-policy`; do not duplicate public DTOs or baseline rules here.
