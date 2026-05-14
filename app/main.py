from app.runner import run_scan


def main() -> None:
    context = run_scan()

    print("AWS Security Posture Scanner MVP")
    print(f"Account ID: {context.account_id}")
    print(f"Regions: {', '.join(context.regions)}")
    print(f"Findings: {len(context.findings)}")


if __name__ == "__main__":
    main()
