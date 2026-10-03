@shared
Feature: Shared policy decisions govern the actual mesh path
  Scenario Outline: HTTP selectors preserve the public value semantics
    When shared HTTP selection "<case>" is enforced
    Examples:
      | case |
      | selectors |
      | http-selectors |
      | empty-values |
      | repeated-in |
      | repeated-header-in-deny |
      | repeated-query-in-deny |
      | pointer-null |
      | repeated-header-notin |
      | repeated-query-notin |
      | missing-header-in |
      | missing-header-exists |
      | missing-query-in |
      | missing-query-exists |
      | missing-notin |
      | null-notin |
      | payload-notin |
      | payload-null |
      | payload-missing |
      | pointer-missing |
      | duplicate-json |
      | trailing-json |

  @shared-host
  Scenario Outline: Both roles apply host denials
    When shared host denial is enforced by "<role>"
    Examples:
      | role |
      | workload |
      | egress |

  @shared-rpc
  Scenario Outline: RPC uses real protobuf, metadata, carrier and frame checks
    When shared RPC selection "<case>" is enforced
    Examples:
      | case |
      | safe |
      | egress-deny |
      | workload-deny |
      | default-field |
      | metadata-empty |
      | metadata-repeated-in |
      | metadata-repeated-notin |
      | metadata-missing-in |
      | metadata-missing-exists |
      | metadata-missing-notin |
      | http-carrier |
      | spoof |
      | stream |
      | wire-valid |
      | unsupported-codec |
      | spoof-content-type |
      | framed-default |
      | truncated-header |
      | truncated-payload |
      | extra-frame |
      | compressed-flag |
      | encoding |
      | malformed-protobuf |
      | missing-frame |
      | body-limit |
      | oversized |

  Scenario Outline: Unusable static dependencies stop startup
    When shared startup rejects "<case>"
    Examples:
      | case |
      | missing-bundle |
      | invalid-bundle |
      | missing-descriptor |
      | wrong-digest |
      | wrong-method |
      | missing-import |

  Scenario: Explicit empty policies keep the independent peer boundary
    When valid empty shared policies preserve independent admission
