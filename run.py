#!/usr/bin/env python
"""
WebAudit 360 — Direct Server Runner
Creator & Lead Architect: Harsh Patel

Usage:
    python run.py
"""

import sys
import os

# Delegate to manage.py runserver
from manage import runserver

if __name__ == "__main__":
    runserver()

