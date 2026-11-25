import unittest
from aws_vpc_sg_auditor import audit_security_groups


class ToolkitTests(unittest.TestCase):
    def test_detects_public_ssh_and_missing_description(self) -> None:
        groups = [
            {
                "GroupId": "sg-111",
                "GroupName": "open-ssh",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    }
                ],
            }
        ]
        res = audit_security_groups(groups)
        self.assertEqual(res["overall_status"], "CRIT")
        reasons = [f["reason"] for f in res["findings"]]
        self.assertTrue(any("22 (SSH)" in r for r in reasons))
        self.assertTrue(any("missing Description" in r for r in reasons))

    def test_clean_https_with_description(self) -> None:
        groups = [
            {
                "GroupId": "sg-222",
                "GroupName": "web-only",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 443,
                        "ToPort": 443,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "HTTPS ingress"}],
                    }
                ],
            }
        ]
        res = audit_security_groups(groups)
        self.assertEqual(res["overall_status"], "OK")
        self.assertEqual(res["findings_count"], 0)


if __name__ == "__main__":
    unittest.main()
