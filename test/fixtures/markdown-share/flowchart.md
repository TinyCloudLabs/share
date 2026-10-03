# Release flow

The diagram below must render with visible labels and styled nodes.

```mermaid
flowchart LR
  draft[Draft notes] --> review{Peer review}
  review -->|approved| publish([Publish share])
  review -->|changes| draft
  publish --> archive[(Archive copy)]
```

Text after the diagram stays readable.
