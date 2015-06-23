Feature: Calculate Fingerprint for a given SSL certificate

  Scenario Outline: github.com certificate check

    Given I have the certificate for <HOSTNAME> in <FORMAT>
    When I calculate the fingerprint for the given certificate
    Then I expect the fingerprint to match <EXPECTED_FINGERPRINT>

    Examples:
      | HOSTNAME        | FORMAT | EXPECTED_FINGERPRINT                                                                            |
      | github.com      | DER    | 58:87:52:44:D8:60:12:B0:FB:D5:F6:C0:6E:F1:6E:FC:A2:0E:15:8D:58:E9:6E:6F:76:CE:DA:66:60:B5:9B:C2 |
      | github.com      | PEM    | 58:87:52:44:D8:60:12:B0:FB:D5:F6:C0:6E:F1:6E:FC:A2:0E:15:8D:58:E9:6E:6F:76:CE:DA:66:60:B5:9B:C2 |
      | www.mozilla.org | DER    | B7:55:C8:F1:BD:B8:B8:DF:9B:3E:82:A3:86:54:4D:45:36:F5:AC:5F:D1:B8:99:5B:77:47:EC:FB:4B:4D:B5:27 |
      | www.mozilla.org | PEM    | B7:55:C8:F1:BD:B8:B8:DF:9B:3E:82:A3:86:54:4D:45:36:F5:AC:5F:D1:B8:99:5B:77:47:EC:FB:4B:4D:B5:27 |