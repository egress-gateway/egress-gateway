@governance
Feature: Required components fail closed and recover
  Real process and Pod state identifies each injected failure.
  Healthy origins receive no denied request; recovery restores allow and deny controls.

  Scenario Outline: Observe failure and recovery of a required component
    Then the deployed "<component>" failure remains closed and recovers governance

    Examples:
      | component    |
      | opa-workload |
      | opa-egress   |
      | gateway      |
      | startup      |
