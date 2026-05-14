from app.aws_session import create_scan_context


def main() -> None:
    context = create_scan_context()
    
    print("AWS Security Posture Scanner MVP")
    print(f"Account ID: {context.account_id}")
    print(f"Regions: {', '.join(context.regions)}")
    print(f"Findings: {len(context.findings)}")


if __name__ == "__main__":
    main()