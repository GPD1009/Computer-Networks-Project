"""
Multi-agent Q-routing (Boyan & Littman) for the campus fabric.

Every switch is an agent x holding a table Q_x[d][y] = estimated time (ms) to
deliver a packet to destination switch d when forwarding via neighbour y.
After forwarding to y, agent x receives y's own best estimate
t = min_z Q_y[d][z] and the measured link cost c(x, y) and updates

    Q_x[d][y] <- Q_x[d][y] + alpha * (c(x, y) + t - Q_x[d][y])

The agents are trained continuously *inside the digital twin*: link costs
come from the live telemetry (propagation + queueing delay derived from the
utilisation the controller measures), so learned routes adapt to congestion
and failures before traffic is steered onto them.
"""
import random


class QRouting(object):
    def __init__(self, alpha=0.5, epsilon=0.25, min_epsilon=0.05, seed=7):
        self.alpha = alpha
        self.epsilon = epsilon
        self.min_epsilon = min_epsilon
        self.Q = {}
        self.rng = random.Random(seed)
        self.episodes = 0
        self.last_error = None

    def _q(self, x, d, y, default=10.0):
        return self.Q.setdefault(x, {}).setdefault(d, {}).setdefault(y, default)

    def value(self, g, x, d):
        if x == d:
            return 0.0
        vals = [self._q(x, d, y) for y in g.neighbors(x)]
        return min(vals) if vals else 1e6

    def train(self, g, episodes=1500, cost_key="lat"):
        nodes = list(g.nodes)
        if len(nodes) < 2:
            return
        err = 0.0
        n = 0
        for _ in range(episodes):
            s, d = self.rng.sample(nodes, 2)
            x = s
            for _step in range(2 * len(nodes)):
                nbrs = list(g.neighbors(x))
                if not nbrs:
                    break
                if self.rng.random() < self.epsilon:
                    y = self.rng.choice(nbrs)
                else:
                    y = min(nbrs, key=lambda z: self._q(x, d, z))
                c = g[x][y][cost_key]
                t = 0.0 if y == d else self.value(g, y, d)
                q = self._q(x, d, y)
                delta = c + t - q
                self.Q[x][d][y] = q + self.alpha * delta
                err += abs(delta)
                n += 1
                if y == d:
                    break
                x = y
        self.episodes += episodes
        self.epsilon = max(self.min_epsilon, self.epsilon * 0.97)
        self.last_error = err / n if n else None
        # forget neighbours that no longer exist (failed links)
        for x, dests in self.Q.items():
            if x not in g:
                continue
            live = set(g.neighbors(x))
            for d in dests.values():
                for y in list(d):
                    if y not in live:
                        del d[y]

    def path(self, g, src, dst):
        """Greedy path following each agent's best next hop (loop-free)."""
        if src == dst:
            return [src]
        path, visited, x = [src], {src}, src
        while x != dst:
            cands = [y for y in g.neighbors(x) if y not in visited]
            if not cands:
                return None
            y = min(cands, key=lambda z: self._q(x, dst, z))
            path.append(y)
            visited.add(y)
            x = y
            if len(path) > len(g) + 1:
                return None
        return path

    def table(self, node):
        out = {}
        for d, nb in sorted(self.Q.get(node, {}).items()):
            out[d] = {y: round(v, 2) for y, v in sorted(nb.items(), key=lambda kv: kv[1])}
        return out

    def stats(self):
        return {"episodes": self.episodes, "epsilon": round(self.epsilon, 3),
                "mean_td_error_ms": round(self.last_error, 3) if self.last_error is not None else None,
                "agents": len(self.Q)}
