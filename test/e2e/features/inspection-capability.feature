@inspection
Feature: Inspection implementation prerequisite
  Configuration parsing is only a prerequisite, not an HTTPS handshake proof.
  The complete suite must fail while the image lacks the selected capability.

  Scenario: The image contains the required upstream certificate selector
    Then the image accepts the on-demand certificate configuration
