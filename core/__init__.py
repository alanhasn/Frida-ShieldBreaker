"""Core orchestration package for Frida-ShieldBreaker.

Contains the Python-side engine: device/session management, IPC
plumbing, and logging. All Frida/Gum instrumentation logic lives in
`agents/` (JavaScript) and is loaded, never reimplemented, here.
"""
