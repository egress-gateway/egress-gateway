@connectivity
Feature: Transparent HTTP connectivity through the gateway image
  The workload starts with prepared trust and sends ordinary requests without trace context.
  Both gateway roles and the origin must provide correlated evidence.

  Scenario Outline: Independent requests traverse both proxies
    Given the workload has a startup-prepared inspection trust bundle
    When the workload sends an HTTP request without trace context to "<path>"
    Then the origin responds successfully
    And both proxies and the origin record the request identifier
    And the proxy hop uses live Istio mutual TLS
    And the Collector receives a workload-rooted trace linking both proxies

    Examples:
      | path    |
      | /first  |
      | /second |
