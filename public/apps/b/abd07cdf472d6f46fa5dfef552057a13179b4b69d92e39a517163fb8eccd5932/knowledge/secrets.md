---
type: TinyCloud Secrets
title: Secrets
description: Secret references used by the app.
tinycloud:
  app: com.example.notes
  service: secrets
  profile: tinycloud.app.v1
  sensitivity: secret-reference
  containsSecretValue: false
---

# Secrets

## Model API Key

Name: `model-api-key`

Purpose: Optional provider key used by the summary worker.

Consumers:

- `agent.summarizer`

Agent notes:

- Never write plaintext secret values into this bundle.
- If missing, disable summaries instead of blocking note editing.
