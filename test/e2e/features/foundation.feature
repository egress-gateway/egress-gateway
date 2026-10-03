@foundation
Feature: Gateway composition consumes the networking foundation
  Exact TCP and resolver exceptions apply to the entire Pod.
  Connectivity here does not claim the later governance acceptance.

  Scenario: Actual preparation preserves the restricted runtime envelope
    Given the workload has a startup-prepared inspection trust bundle
    Then Gateway preparation preserves IPv6 closure and direct network confinement

  Scenario: CNI agent restarts retain foundation and Gateway behavior
    Given the foundation and Istio CNI agents have restarted
    Then Gateway preparation preserves IPv6 closure and direct network confinement
    When the workload sends its first HTTPS request without trace context to a newly selected hostname
    Then the origin responds successfully
    And both proxies and the origin record the request identifier
