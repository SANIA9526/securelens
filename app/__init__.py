"""SecureLens — AI-assisted code security reviewer."""

try:  # load ANTHROPIC_API_KEY etc. from a local .env if present
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # pragma: no cover
    pass

__version__ = "1.0.0"
