# Small diagram

A small diagram keeps its natural size on the card.

```mermaid
stateDiagram-v2
  [*] --> Idle
  Idle --> Rendering : open
  Rendering --> Shown : done
  Shown --> [*]
```
