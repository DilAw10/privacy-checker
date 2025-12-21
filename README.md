# privacy-checker
Privacy Scanner 2026 - Project


## Deploying to Render

To ensure Playwright screenshots work in Render deployments, make sure browsers are installed during the build step. The `render.yaml` should run the Playwright installer as part of the `buildCommand`:

```yaml
buildCommand: "python -m pip install -r requirements.txt && python -m playwright install --with-deps"
```

This installs Python dependencies and downloads Playwright browser binaries so the deployed service can capture rendered screenshots reliably.
