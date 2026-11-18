# BearJug

AveDeus is an SSH deception sensor network; AITO is its intelligence layer.

Core feature: **Deceptive Access**. Attackers who guess a synthetic credential
are let in to a fully simulated server, and everything they do afterwards is
recorded. They never reach a real machine.

- [Deceptive Access design](docs/design/deceptive-access.md)
- [Implementation roadmap](docs/roadmap.md)

Defining engineering rule: make the deception as convincing as possible to the
attacker, while making the real infrastructure as inaccessible as possible to
them.
