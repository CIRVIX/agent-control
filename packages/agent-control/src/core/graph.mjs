/**
 * The multi-agent relationship graph.
 *
 * delegation.mjs already records every edge — each grant is "issuer delegated
 * this scope to subject" — but only ever answers one question: may THIS call
 * proceed. That is the right question at execution time and the wrong one
 * afterwards, when somebody is trying to find out how an agent nobody
 * provisioned for production ended up able to reach it.
 *
 * This module answers the second kind of question. It reads the broker's
 * inventory and nothing else, so it cannot disagree with enforcement about who
 * delegated what — there is one source of edges.
 *
 * TENANCY IS A CONSTRUCTOR ARGUMENT, NOT A FILTER YOU REMEMBER TO APPLY
 * --------------------------------------------------------------------
 * buildGraph() takes the tenant and drops everything else before any query
 * runs. A graph is exactly the shape of an answer to "what can reach
 * production", so a traversal that wanders into another tenant's edges does
 * not leak a row — it leaks the topology of someone else's estate, which is
 * worse and harder to notice. Filtering at construction means no query can
 * forget to do it, and the tests assert a cross-tenant edge is absent from the
 * graph rather than merely excluded from the result.
 *
 * NOT A GRAPH DATABASE
 * --------------------
 * Adjacency maps over an array that is already in memory. These estates are
 * tens to low thousands of edges; a traversal over that is microseconds, and
 * introducing a graph store would add an operational dependency to answer
 * questions a Map already answers.
 */

import { scopePermits, intersectScopes } from "./delegation.mjs";

/**
 * Builds a directed graph from a broker inventory.
 *
 * Revoked and expired grants are excluded by default: an edge that cannot
 * authorise anything is not a path, and including it would make every query
 * over-report. `includeInactive` keeps them for forensics, where "who COULD
 * have reached this last Tuesday" is the actual question.
 */
export function buildGraph(inventory = [], { tenant = undefined, includeInactive = false, now = Date.now() } = {}) {
  const scoped = inventory.filter((g) => {
    if (tenant !== undefined && g.tenant !== tenant) return false;
    if (includeInactive) return true;
    if (g.revoked) return false;
    if (g.expiresAt && Date.parse(g.expiresAt) <= now) return false;
    return true;
  });

  const nodes = new Map();
  const node = (id) => {
    if (!id) return null;
    if (!nodes.has(id)) nodes.set(id, { id, tenant: tenant === undefined ? null : tenant, roots: 0, out: [], in: [] });
    return nodes.get(id);
  };

  const edges = [];
  for (const g of scoped) {
    const subject = node(g.subject);
    if (!subject) continue;
    if (g.issuer === null) {
      // A root grant is authority the platform handed the agent directly. It
      // is a property of the node, not an edge from nobody.
      subject.roots += 1;
      subject.rootScope = subject.rootScope ? intersectScopes(subject.rootScope, g.scope) : g.scope;
      continue;
    }
    const issuer = node(g.issuer);
    const edge = {
      id: g.id, from: g.issuer, to: g.subject, scope: g.scope,
      depth: g.depth, revoked: Boolean(g.revoked), expiresAt: g.expiresAt ?? null,
    };
    edges.push(edge);
    issuer.out.push(edge);
    subject.in.push(edge);
  }

  return { tenant: tenant === undefined ? null : tenant, nodes, edges };
}

/**
 * Everything `from` can reach, and by which path.
 *
 * Breadth-first so the first path found to a node is the shortest one, which
 * is the path a reader wants to see. Scope is intersected along the way: an
 * agent two delegations deep holds the intersection of both, never the union,
 * which is the same rule enforcement applies.
 */
export function reach(graph, from, { maxDepth = 8 } = {}) {
  const start = graph.nodes.get(from);
  if (!start) return [];

  const seen = new Set([from]);
  const out = [];
  let frontier = [{ id: from, path: [], scope: start.rootScope ?? null }];

  for (let depth = 0; depth < maxDepth && frontier.length; depth++) {
    const next = [];
    for (const cur of frontier) {
      const node = graph.nodes.get(cur.id);
      if (!node) continue;
      for (const edge of node.out) {
        if (seen.has(edge.to)) continue;
        seen.add(edge.to);
        const scope = cur.scope ? intersectScopes(cur.scope, edge.scope) : edge.scope;
        const entry = { agent: edge.to, depth: depth + 1, path: [...cur.path, edge.id], via: [...cur.path, edge.id].length, scope };
        out.push(entry);
        next.push({ id: edge.to, path: entry.path, scope });
      }
    }
    frontier = next;
  }
  return out;
}

/**
 * The scope actually held at the end of a specific path.
 *
 * Intersected edge by edge, starting from the origin's root authority, which
 * is the same narrowing enforcement applies.
 */
export function scopeAlong(graph, origin, path) {
  let scope = graph.nodes.get(origin)?.rootScope ?? null;
  for (const edgeId of path) {
    const edge = graph.edges.find((e) => e.id === edgeId);
    if (!edge) return null;
    scope = scope ? intersectScopes(scope, edge.scope) : edge.scope;
  }
  return scope;
}

/**
 * Which agents can reach this action/resource, directly or by delegation.
 *
 * WHY THIS ENUMERATES EVERY PATH RATHER THAN USING reach()
 * -------------------------------------------------------
 * reach() is breadth-first with one `seen` set, so an agent is claimed by
 * whichever path arrives first — the SHORTEST one. For "how do I get there"
 * that is the right answer. For "can this agent reach production" it is
 * actively wrong, because the shortest path is not the most permissive one.
 *
 * The estate in the tests has exactly this shape: deployer is reachable at
 * depth 2 through researcher (fs.read only) and through coder (which carries
 * deploy.production). Breadth-first found the researcher path first, computed
 * a scope without deploy.production, and concluded deployer could not reach
 * production. It can. A security query that under-reports is worse than one
 * that is slow, so this walks every path and asks whether ANY of them still
 * permits the call after all its narrowings.
 */
export function whoCanReach(graph, { action, resource }) {
  const hits = [];
  for (const [id, node] of graph.nodes) {
    if (node.rootScope && scopePermits(node.rootScope, { action, resource })) {
      hits.push({ agent: id, via: "root", depth: 0, path: [] });
      continue;
    }
    let best = null;
    for (const [origin, originNode] of graph.nodes) {
      if (origin === id || !originNode.rootScope) continue;
      for (const path of paths(graph, origin, id)) {
        const scope = scopeAlong(graph, origin, path);
        if (!scope || !scopePermits(scope, { action, resource })) continue;
        /* Report the shortest permitting path, not merely the first found —
           it is the one someone has to go and revoke. */
        if (!best || path.length < best.path.length) best = { agent: id, via: origin, depth: path.length, path };
      }
    }
    if (best) hits.push(best);
  }
  return hits;
}

/**
 * Delegation paths from `from` to `to`.
 *
 * All of them, not the shortest. Two routes to the same authority is exactly
 * the finding worth surfacing — revoking one and believing the path is closed
 * is how an estate keeps a capability nobody thinks it has.
 */
export function paths(graph, from, to, { maxDepth = 8 } = {}) {
  const found = [];
  const walk = (cur, trail, visited) => {
    if (trail.length > maxDepth) return;
    if (cur === to && trail.length) { found.push([...trail]); return; }
    const node = graph.nodes.get(cur);
    if (!node) return;
    for (const edge of node.out) {
      if (visited.has(edge.to)) continue;      // no cycles
      visited.add(edge.to);
      walk(edge.to, [...trail, edge.id], visited);
      visited.delete(edge.to);
    }
  };
  walk(from, [], new Set([from]));
  return found;
}

/**
 * Agents that share a capability, grouped by the capability.
 *
 * "Which agents share a sensitive capability" — the shared-credential
 * question. Only capabilities held by more than one agent are returned;
 * a capability with a single holder is not a sharing risk and would bury
 * the ones that are.
 */
export function sharedCapability(graph) {
  const holders = new Map();
  const note = (cap, agent) => {
    if (!holders.has(cap)) holders.set(cap, new Set());
    holders.get(cap).add(agent);
  };
  /* A scope is {actions, resources}, NOT a flat list of capability strings.
     Iterating the scope object directly yielded nothing and, worse, passing a
     flat array anywhere near normalizeScope() turns it into ["*"] on BOTH
     axes — absent means unconstrained — so an array-shaped scope reads as
     unlimited authority. Actions are the axis that names a capability. */
  const actionsOf = (scope) => (Array.isArray(scope?.actions) ? scope.actions : []);
  for (const [id, node] of graph.nodes) {
    for (const cap of actionsOf(node.rootScope)) note(String(cap), id);
  }
  for (const e of graph.edges) for (const cap of actionsOf(e.scope)) note(String(cap), e.to);

  return [...holders.entries()]
    .filter(([, set]) => set.size > 1)
    .map(([capability, set]) => ({ capability, agents: [...set].sort() }))
    .sort((a, b) => b.agents.length - a.agents.length || a.capability.localeCompare(b.capability));
}

/** Who delegated authority to this agent, nearest first. */
export function delegatedBy(graph, agent) {
  const node = graph.nodes.get(agent);
  if (!node) return [];
  return node.in.map((e) => ({ from: e.from, grant: e.id, scope: e.scope, depth: e.depth }));
}

/**
 * Graphviz export, for the CLI and for anyone who wants a picture.
 *
 * Machine-readable is `summary()`; this is the human one. Root authority is
 * drawn as a node attribute rather than an edge from a phantom node, because
 * inventing a "platform" node would put something in the picture that does not
 * exist in the model.
 */
export function toDot(graph, { title = "cirvix agents" } = {}) {
  const esc = (s) => String(s).replace(/"/g, '\\"');
  const lines = [`digraph "${esc(title)}" {`, "  rankdir=LR;", '  node [shape=box, style=rounded, fontname="monospace"];'];
  for (const [id, node] of graph.nodes) {
    const rooted = node.roots > 0;
    lines.push(`  "${esc(id)}" [label="${esc(id)}${rooted ? "\\n(root authority)" : ""}"${rooted ? ', peripheries=2' : ""}];`);
  }
  for (const e of graph.edges) {
    const label = (e.scope?.actions ?? []).join(", ");
    lines.push(`  "${esc(e.from)}" -> "${esc(e.to)}" [label="${esc(label)}"${e.revoked ? ", style=dashed" : ""}];`);
  }
  lines.push("}");
  return lines.join("\n");
}

/** A compact machine-readable view for the API and the dashboard. */
export function summary(graph) {
  return {
    tenant: graph.tenant,
    agents: [...graph.nodes.values()].map((n) => ({
      id: n.id, rootAuthority: n.roots > 0, delegationsIn: n.in.length, delegationsOut: n.out.length,
    })),
    edges: graph.edges.map((e) => ({ from: e.from, to: e.to, grant: e.id, scope: e.scope, revoked: e.revoked })),
    shared: sharedCapability(graph),
  };
}
