from app.config import settings


def main() -> None:
    print("AWS Security Posture Scanner MVP")
    print(f"AWS Region: {settings.aws_region}")


if __name__ == "__main__":
    main()