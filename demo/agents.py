from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agent_warrant.chain import ChainLink, delegate, prove_leaf
from agent_warrant.identity import encode_public_key, generate_keypair
from agent_warrant.task_root import TaskRoot
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from executor.protocol import Request, request_digest


@dataclass
class Agent:
    """An untrusted agent: it holds a delegation chain and its own key, and nothing else. It builds requests and
    leaf possession proofs; it holds no secret and no credential."""

    name: str
    key: Ed25519PrivateKey = field(default_factory=generate_keypair)
    root: TaskRoot | None = None
    links: tuple[ChainLink, ...] = ()

    @property
    def public_key(self) -> str:
        return encode_public_key(self.key.public_key())

    @property
    def leaf(self) -> TaskRoot | ChainLink:
        return self.links[-1] if self.links else self.root

    def delegate_to(self, child: Agent, *, scope: dict[str, Any], budget: int, ttl: int, now: int) -> ChainLink:
        link = delegate(
            self.root, self.leaf, self.key, child_subject=child.public_key, scope=scope, budget=budget, ttl=ttl, now=now
        )
        child.root = self.root
        child.links = (*self.links, link)
        return link

    def request(
        self,
        *,
        audience: str,
        now: int,
        tool: str,
        resource: str,
        args: dict[str, Any],
        nonce: str,
        trace_id: str | None = None,
        host: str | None = None,
    ) -> Request:
        proof = prove_leaf(
            self.leaf, self.key, now, audience=audience, request_digest=request_digest(tool, resource, args, nonce)
        )
        return Request(
            task_root=self.root.encode(),
            links=tuple(link.encode() for link in self.links),
            leaf_proof=proof.encode(),
            tool=tool,
            resource=resource,
            args=args,
            nonce=nonce,
            trace_id=trace_id,
            host=host,
        )
