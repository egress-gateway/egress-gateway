# Identity adaptation boundary

This directory is reserved for necessary adaptation that extracts identity from trusted connection context. Identity infrastructure owns certificate issuance and rotation; the controller owns ServiceAccount/Profile binding.

The local example has neither mTLS nor proof of ServiceAccount identity and cannot demonstrate identity isolation. Application-controlled headers and localhost within a shared Pod are not identity trust boundaries.
