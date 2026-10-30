#!/usr/bin/env python
"""
WebAudit 360 — Management & Unified Server Entrypoint
Creator & Lead Architect: Harsh Patel

Usage:
    python manage.py runserver          # Starts full-stack frontend & backend server
    python manage.py                    # Default: runserver
    python manage.py test               # Runs automated test suite
    python manage.py migrate            # Applies database migrations
"""

import sys
import os
import argparse
import uvicorn

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)


def print_banner(host: str, port: int):
    url = f"http://{host}:{port}"
    print(r"""
========================================================================
  WebAudit 360 — Production Full-Stack Website Intelligence Platform
  Created & Lead Architect: Harsh Patel
========================================================================
  Unified Full-Stack Server:  {url}/
  Dashboard:                  {url}/dashboard.html
  Start New Audit:            {url}/new-audit.html
  Interactive API (Swagger):  {url}/docs
  System Health Diagnostic:   {url}/health
========================================================================
  Frontend and Backend are running simultaneously in a single command.
  Press Ctrl+C to terminate the server.
""".format(url=url))


def runserver(host: str = "127.0.0.1", port: int = 8000, reload: bool = True):
    print_banner(host, port)
    uvicorn.run(
        "backend.app.main:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info"
    )


def run_tests():
    import pytest
    print("\nRunning WebAudit 360 automated test suite...\n")
    exit_code = pytest.main(["-v", "tests"])
    sys.exit(exit_code)


def run_migrations():
    from alembic.config import Config
    from alembic import command
    print("\nApplying database migrations...\n")
    alembic_cfg = Config("alembic.ini")
    command.upgrade(alembic_cfg, "head")
    print("Database migrations applied successfully.\n")


def main():
    parser = argparse.ArgumentParser(description="WebAudit 360 CLI Manager")
    parser.add_argument("command", nargs="?", default="runserver",
                        choices=["runserver", "test", "migrate", "help"],
                        help="Command to execute (default: runserver)")
    parser.add_argument("--host", default="127.0.0.1", help="Server host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Server port (default: 8000)")
    parser.add_argument("--no-reload", action="store_true", help="Disable auto-reload")

    args = parser.parse_args()

    if args.command == "runserver":
        runserver(host=args.host, port=args.port, reload=not args.no_reload)
    elif args.command == "test":
        run_tests()
    elif args.command == "migrate":
        run_migrations()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

