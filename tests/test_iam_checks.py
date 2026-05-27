from botocore.exceptions import ClientError

import app.checks.iam as iam_checks


ACCOUNT_ID = "123456789012"


def client_error(code: str, operation_name: str = "IamOperation") -> ClientError:
    return ClientError(
        {
            "Error": {
                "Code": code,
                "Message": f"{operation_name} failed",
            }
        },
        operation_name,
    )


class FakeSession:
    def __init__(self, client):
        self._client = client

    def client(self, service_name: str):
        assert service_name == "iam"
        return self._client


class FakeIamClient:
    def __init__(
        self, *, account_mfa_enabled=1, password_policy=None, summary_error=None, policy_error=None
    ):
        self.account_mfa_enabled = account_mfa_enabled
        self.password_policy = password_policy or compliant_password_policy()
        self.summary_error = summary_error
        self.policy_error = policy_error

    def get_account_summary(self):
        if self.summary_error:
            raise self.summary_error

        return {"SummaryMap": {"AccountMFAEnabled": self.account_mfa_enabled}}

    def get_account_password_policy(self):
        if self.policy_error:
            raise self.policy_error

        return {"PasswordPolicy": self.password_policy}


def compliant_password_policy() -> dict:
    return {
        "MinimumPasswordLength": 14,
        "RequireUppercaseCharacters": True,
        "RequireLowercaseCharacters": True,
        "RequireNumbers": True,
        "RequireSymbols": True,
        "MaxPasswordAge": 90,
        "PasswordReusePrevention": 24,
        "AllowUsersToChangePassword": True,
    }


def run_iam_check(client):
    return iam_checks.run(
        FakeSession(client),
        account_id=ACCOUNT_ID,
        region=None,
    )


def test_root_mfa_disabled_emits_root_mfa_disabled_finding():
    findings = run_iam_check(FakeIamClient(account_mfa_enabled=0))

    assert len(findings) == 1
    finding = findings[0]

    assert finding.check_id == iam_checks.ROOT_MFA_CHECK_ID
    assert finding.region == "global"
    assert finding.resource_id == "root"
    assert finding.severity == "high"
    assert finding.status == "failed"
    assert finding.evidence["account_mfa_enabled"] is False


def test_root_mfa_enabled_emits_no_root_mfa_finding():
    findings = run_iam_check(FakeIamClient(account_mfa_enabled=1))

    assert all(finding.check_id != iam_checks.ROOT_MFA_CHECK_ID for finding in findings)


def test_missing_password_policy_emits_missing_password_policy_finding():
    findings = run_iam_check(
        FakeIamClient(policy_error=client_error("NoSuchEntity", "GetAccountPasswordPolicy"))
    )

    assert len(findings) == 1
    finding = findings[0]

    assert finding.check_id == iam_checks.PASSWORD_POLICY_MISSING_CHECK_ID
    assert finding.region == "global"
    assert finding.resource_id == "account-password-policy"
    assert finding.severity == "high"
    assert finding.status == "failed"
    assert finding.evidence["policy_present"] is False
    assert finding.evidence["failed_requirements"] == ["password_policy_not_configured"]


def test_weak_password_policy_emits_weak_password_policy_finding():
    weak_policy = {
        "MinimumPasswordLength": 8,
        "RequireUppercaseCharacters": False,
        "RequireLowercaseCharacters": True,
        "RequireNumbers": False,
        "RequireSymbols": False,
        "MaxPasswordAge": 120,
        "PasswordReusePrevention": 5,
        "AllowUsersToChangePassword": False,
    }

    findings = run_iam_check(FakeIamClient(password_policy=weak_policy))

    assert len(findings) == 1
    finding = findings[0]

    assert finding.check_id == iam_checks.PASSWORD_POLICY_WEAK_CHECK_ID
    assert finding.region == "global"
    assert finding.resource_id == "account-password-policy"
    assert finding.severity == "medium"
    assert finding.status == "failed"
    assert finding.evidence["minimum_password_length"] == 8
    assert "minimum_password_length_less_than_14" in finding.evidence["failed_requirements"]
    assert "numbers_not_required" in finding.evidence["failed_requirements"]


def test_compliant_password_policy_emits_no_password_policy_finding():
    findings = run_iam_check(FakeIamClient(password_policy=compliant_password_policy()))

    assert all(
        finding.check_id
        not in {
            iam_checks.PASSWORD_POLICY_MISSING_CHECK_ID,
            iam_checks.PASSWORD_POLICY_WEAK_CHECK_ID,
        }
        for finding in findings
    )


def test_iam_api_failure_emits_informational_error_finding():
    findings = run_iam_check(
        FakeIamClient(
            summary_error=client_error("AccessDenied", "GetAccountSummary"),
            policy_error=client_error("AccessDenied", "GetAccountPasswordPolicy"),
        )
    )

    assert len(findings) == 2
    assert {finding.check_id for finding in findings} == {
        iam_checks.ROOT_MFA_CHECK_ID,
        iam_checks.PASSWORD_POLICY_WEAK_CHECK_ID,
    }
    assert all(finding.region == "global" for finding in findings)
    assert all(finding.severity == "informational" for finding in findings)
    assert all(finding.status == "error" for finding in findings)
    assert all(finding.evidence["error_type"] == "ClientError" for finding in findings)
