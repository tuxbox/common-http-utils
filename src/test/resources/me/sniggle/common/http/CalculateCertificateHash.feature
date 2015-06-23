Feature: Calculate Fingerprint for a given SSL certificate

  Scenario Outline: github.com certificate check

    Given I have the certificate for github.com in <FORMAT>
    When I calculate the fingerprint for the given certificate
    Then I expect the fingerprint to match <EXPECTED_FINGERPRINT>

    Examples:
      | FORMAT | EXPECTED_FINGERPRINT                                                                            |
      | DER    | 58:87:52:44:D8:60:12:B0:FB:D5:F6:C0:6E:F1:6E:FC:A2:0E:15:8D:58:E9:6E:6F:76:CE:DA:66:60:B5:9B:C2 |
      | PEM    | 58:87:52:44:D8:60:12:B0:FB:D5:F6:C0:6E:F1:6E:FC:A2:0E:15:8D:58:E9:6E:6F:76:CE:DA:66:60:B5:9B:C2 |