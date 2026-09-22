@https
Feature: Transparent HTTPS inspection with real Istio identity
  The application sends ordinary curl requests without trace context.

  Scenario: The first request to a new hostname traverses all three TLS hops
    Given the workload has a startup-prepared inspection trust bundle
    When the workload sends its first HTTPS request without trace context to a newly selected hostname
    Then the origin responds successfully
    And both proxies and the origin record the request identifier
    And the proxy hop uses live Istio mutual TLS
    And the Collector receives a workload-rooted trace linking both proxies
    And the client verifies the inspection certificate and egress verifies origin TLS
    And the application cannot access private proxy management
    And Istio telemetry records successful proxy traffic
