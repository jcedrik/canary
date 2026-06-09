# Vulnerable example app

This Flask app is **intentionally insecure**. It exists so you can see what
`canary` flags. Do not deploy it or copy its patterns.

Run the scanner against it:

```bash
canary examples/vulnerable_app/
```

You should see one CRITICAL, one HIGH, and one MEDIUM finding.
