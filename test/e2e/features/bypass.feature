@governance
Feature: Restricted execution has no direct network fallback
  Identifiable TCP, UDP, DNS and real QUIC attempts are paired with healthy receivers.
  Executed capture/rejection or source-endpoint Calico counters attribute each denial.

  Scenario Outline: Direct traffic stays confined across execution stages
    Then restricted "<stage>" execution cannot reach forbidden protocol receivers

    Examples:
      | stage    |
      | business |
      | init     |
      | absent   |

  Scenario: Allowed gateway ports cannot replace either authorization boundary
    Then direct gateway entrypoints reject local bypass and unverified clients
