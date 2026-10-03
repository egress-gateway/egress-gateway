@governance
Feature: Independent authorization in the deployed Istio request path
  The same HTTPS origin and path receive different decisions based on complete content.
  Every denial has a responsible proxy record and healthy upstream non-delivery evidence.

  Scenario Outline: Authorize or reject complete request content
    When the workload exercises the governed "<case>" request

    Examples:
      | case            |
      | safe            |
      | workload-deny   |
      | egress-deny     |
      | spoof           |
      | invalid-json    |
      | missing-body    |
      | encoded         |
      | oversized       |
      | http-alternate  |

  Scenario: Authorization response mutation cannot change the forwarding target
    When the deployed mutation-only authorization fixture tries to change the target
