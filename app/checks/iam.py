from botocore.exceptions import BotoCoreError, ClientError

from app.models import Finding, generate_finding_id
from app.reporting import format_timestamp, utc_now

ROOT_MFA_CHECK_ID = "IAM_ROOT_MFA_DISABLED"

PASSWORD_POLICY_MISSING_CHECK_ID = "IAM_PASSWORD_POLICY_MISSING"
PASSWORD_POLICY_WEAK_CHECK_ID = "IAM_PASSWORD_POLICY_WEAK"

GLOBAL_REGION = "global"

PASSWORD_POLICY_THRESHOLDS = {
    "minimum_password_length": 14,
    "max_password_age": 90,
    "password_reuse_prevention": 24,
}


def run(session, account_id: str, region: str | None) -> list[Finding]:
    iam_client = session.client("iam")
    findings: list[Finding] = []

    findings.extend(_check_root_mfa(iam_client, account_id))
    findings.extend(_check_password_policy(iam_client, account_id))

    return findings


def _check_root_mfa(iam_client, account_id: str) -> list[Finding]:
    try:
        response = iam_client.get_account_summary()
        summary = response.get("SummaryMap", {})

        account_mfa_enabled = bool(summary.get("AccountMFAEnabled", 0))

        if account_mfa_enabled:
            return []

        return [
            Finding(
                finding_id=generate_finding_id(
                    account_id=account_id,
                    region=GLOBAL_REGION,
                    service="iam",
                    check_id=ROOT_MFA_CHECK_ID,
                    resource_id="root",
                ),
                check_id=ROOT_MFA_CHECK_ID,
                account_id=account_id,
                region=GLOBAL_REGION,
                service="iam",
                resource_type="account-root-user",
                resource_id="root",
                severity="high",
                status="failed",
                title="AWS root user MFA is not enabled",
                description=(
                    "The AWS account root user does not have multi-factor "
                    "authentication enabled. Root-user compromise can allow "
                    "full account takeover."
                ),
                remediation=(
                    "Enable MFA for the AWS account root user. Prefer a hardware "
                    "or phishing-resistant MFA method where available, and avoid "
                    "routine root-user use after MFA is configured."
                ),
                evidence={
                    "api_source": "iam.get_account_summary",
                    "account_mfa_enabled": account_mfa_enabled,
                },
                observed_at=format_timestamp(utc_now()),
            )
        ]

    except (BotoCoreError, ClientError, KeyError, TypeError) as exc:
        return [
            _build_error_finding(
                account_id=account_id,
                check_id=ROOT_MFA_CHECK_ID,
                resource_type="account-root-user",
                resource_id="root",
                title="Unable to evaluate AWS root user MFA status",
                description=("The scanner could not determine whether root-user MFA is enabled."),
                remediation=(
                    "Verify the scanner role has permission to call "
                    "iam:GetAccountSummary, then rerun the scan."
                ),
                error=exc,
            )
        ]


def _check_password_policy(iam_client, account_id: str) -> list[Finding]:
    try:
        response = iam_client.get_account_password_policy()
        policy = response.get("PasswordPolicy", {})

        evidence = _build_password_policy_evidence(policy)

        if not evidence["failed_requirements"]:
            return []

        return [
            _build_weak_password_policy_finding(
                account_id=account_id,
                evidence=evidence,
            )
        ]

    except ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code")

        if error_code == "NoSuchEntity":
            return [
                _build_missing_password_policy_finding(
                    account_id=account_id,
                )
            ]

        return [
            _build_error_finding(
                account_id=account_id,
                check_id=PASSWORD_POLICY_WEAK_CHECK_ID,
                resource_type="account-password-policy",
                resource_id="account-password-policy",
                title="Unable to evaluate IAM password policy",
                description=("The scanner could not retrieve the account IAM password policy."),
                remediation=(
                    "Verify the scanner role has permission to call "
                    "iam:GetAccountPasswordPolicy, then rerun the scan."
                ),
                error=exc,
            )
        ]

    except (BotoCoreError, KeyError, TypeError) as exc:
        return [
            _build_error_finding(
                account_id=account_id,
                check_id=PASSWORD_POLICY_WEAK_CHECK_ID,
                resource_type="account-password-policy",
                resource_id="account-password-policy",
                title="Unable to evaluate IAM password policy",
                description=("The scanner could not retrieve the account IAM password policy."),
                remediation=(
                    "Verify the scanner role has permission to call "
                    "iam:GetAccountPasswordPolicy, then rerun the scan."
                ),
                error=exc,
            )
        ]


def _build_password_policy_evidence(policy: dict) -> dict:
    minimum_password_length = policy.get("MinimumPasswordLength")

    require_uppercase = bool(policy.get("RequireUppercaseCharacters", False))

    require_lowercase = bool(policy.get("RequireLowercaseCharacters", False))

    require_numbers = bool(policy.get("RequireNumbers", False))

    require_symbols = bool(policy.get("RequireSymbols", False))

    max_password_age = policy.get("MaxPasswordAge")

    password_reuse_prevention = policy.get("PasswordReusePrevention")

    allow_users_to_change_password = bool(policy.get("AllowUsersToChangePassword", False))

    failed_requirements = []

    if (
        minimum_password_length is None
        or minimum_password_length < PASSWORD_POLICY_THRESHOLDS["minimum_password_length"]
    ):
        failed_requirements.append("minimum_password_length_less_than_14")

    if not require_uppercase:
        failed_requirements.append("uppercase_not_required")

    if not require_lowercase:
        failed_requirements.append("lowercase_not_required")

    if not require_numbers:
        failed_requirements.append("numbers_not_required")

    if not require_symbols:
        failed_requirements.append("symbols_not_required")

    if max_password_age is None:
        failed_requirements.append("max_password_age_not_configured")

    elif max_password_age > PASSWORD_POLICY_THRESHOLDS["max_password_age"]:
        failed_requirements.append("max_password_age_greater_than_90")

    if password_reuse_prevention is None:
        failed_requirements.append("password_reuse_prevention_not_configured")

    elif password_reuse_prevention < PASSWORD_POLICY_THRESHOLDS["password_reuse_prevention"]:
        failed_requirements.append("password_reuse_prevention_less_than_24")

    if not allow_users_to_change_password:
        failed_requirements.append("users_cannot_change_password")

    return {
        "api_source": "iam.get_account_password_policy",
        "policy_present": True,
        "minimum_password_length": minimum_password_length,
        "require_uppercase_characters": require_uppercase,
        "require_lowercase_characters": require_lowercase,
        "require_numbers": require_numbers,
        "require_symbols": require_symbols,
        "max_password_age": max_password_age,
        "password_reuse_prevention": password_reuse_prevention,
        "allow_users_to_change_password": allow_users_to_change_password,
        "failed_requirements": failed_requirements,
    }


def _build_missing_password_policy_finding(
    account_id: str,
) -> Finding:
    return Finding(
        finding_id=generate_finding_id(
            account_id=account_id,
            region=GLOBAL_REGION,
            service="iam",
            check_id=PASSWORD_POLICY_MISSING_CHECK_ID,
            resource_id="account-password-policy",
        ),
        check_id=PASSWORD_POLICY_MISSING_CHECK_ID,
        account_id=account_id,
        region=GLOBAL_REGION,
        service="iam",
        resource_type="account-password-policy",
        resource_id="account-password-policy",
        severity="high",
        status="failed",
        title="IAM account password policy is not configured",
        description=("The AWS account does not have an IAM password policy configured."),
        remediation=(
            "Configure an IAM account password policy requiring at least 14 "
            "characters, uppercase letters, lowercase letters, numbers, "
            "symbols, password expiration of 90 days or less, and prevention "
            "of reuse for at least 24 previous passwords."
        ),
        evidence={
            "api_source": "iam.get_account_password_policy",
            "policy_present": False,
            "failed_requirements": ["password_policy_not_configured"],
        },
        observed_at=format_timestamp(utc_now()),
    )


def _build_weak_password_policy_finding(
    account_id: str,
    evidence: dict,
) -> Finding:
    return Finding(
        finding_id=generate_finding_id(
            account_id=account_id,
            region=GLOBAL_REGION,
            service="iam",
            check_id=PASSWORD_POLICY_WEAK_CHECK_ID,
            resource_id="account-password-policy",
        ),
        check_id=PASSWORD_POLICY_WEAK_CHECK_ID,
        account_id=account_id,
        region=GLOBAL_REGION,
        service="iam",
        resource_type="account-password-policy",
        resource_id="account-password-policy",
        severity="medium",
        status="failed",
        title="IAM account password policy is weak",
        description=(
            "The AWS account IAM password policy exists but does not meet "
            "the scanner's minimum password policy requirements."
        ),
        remediation=(
            "Configure an IAM account password policy requiring at least 14 "
            "characters, uppercase letters, lowercase letters, numbers, "
            "symbols, password expiration of 90 days or less, and prevention "
            "of reuse for at least 24 previous passwords."
        ),
        evidence=evidence,
        observed_at=format_timestamp(utc_now()),
    )


def _build_error_finding(
    *,
    account_id: str,
    check_id: str,
    resource_type: str,
    resource_id: str,
    title: str,
    description: str,
    remediation: str,
    error: Exception,
) -> Finding:
    return Finding(
        finding_id=generate_finding_id(
            account_id=account_id,
            region=GLOBAL_REGION,
            service="iam",
            check_id=check_id,
            resource_id=resource_id,
        ),
        check_id=check_id,
        account_id=account_id,
        region=GLOBAL_REGION,
        service="iam",
        resource_type=resource_type,
        resource_id=resource_id,
        severity="informational",
        status="error",
        title=title,
        description=description,
        remediation=remediation,
        evidence={
            "error_type": type(error).__name__,
            "error_message": str(error),
        },
        observed_at=format_timestamp(utc_now()),
    )
