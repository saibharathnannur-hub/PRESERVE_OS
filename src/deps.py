"""
deps.py -- dependency detection between managed processes (Objective 6).

Why groups
----------
When processes depend on each other, evicting or killing one of them destroys
the others' work too: a consumer whose producer is gone reads EOF and stops.
So a dependent set must be scored, checkpointed and restored as **one unit**.

Evidence for an edge (read-only procfs, nothing is inferred from labels)
------------------------------------------------------------------------
* **parent/child**: field 4 (``ppid``) of ``/proc/<child>/stat`` names the
  parent.
* **shared pipe / socket**: ``readlink /proc/<pid>/fd/<n>`` gives
  ``pipe:[<inode>]`` or ``socket:[<inode>]``. Two processes that hold the
  same inode are connected through that kernel object. pipefs and sockfs
  inode numbers are unique system-wide, so equal inodes mean the same object.

Each :class:`Edge` records the proof (the ppid field or the inode and the fd
numbers on both sides) so the log shows *why* two processes were grouped.
Connected components of the edge graph (union-find) are the groups; a process
with no edges is a group of one, which is how single-process scenarios
behave exactly as before.

Capturability (CRIU dumps a whole tree from its root pid)
---------------------------------------------------------
``criu dump -t ROOT`` takes ROOT and *all* of its descendants. A group can
therefore be captured only if

1. it is exactly one subtree: one member whose parent is outside the group
   (the root), and the root's full set of live descendants, found by scanning
   every ``/proc/<pid>/stat``, equals the group (no member outside the tree,
   no unmanaged descendant that the dump would take with it); and
2. none of its pipes or sockets is also held by a process outside the group.
   Such a link could not be restored, and the outside process would see its
   partner vanish. This needs every process's fd table, so any process whose
   fds cannot be read makes isolation unprovable, and the group is refused.

Standalone use (read-only)::

    python3 src/deps.py --pid 1234 --pid 1235
"""
from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

LINK_KINDS = ("pipe", "socket")


@dataclass(frozen=True)
class Edge:
    a: int
    b: int
    kind: str   # "parent/child" | "pipe" | "socket"
    proof: str  # the procfs evidence

    @property
    def key(self) -> tuple:
        return (min(self.a, self.b), max(self.a, self.b), self.kind, self.proof.split(" ")[0])

    def describe(self) -> str:
        return f"{self.kind} edge {self.a} <-> {self.b}: {self.proof}"


@dataclass
class Group:
    members: list[int]
    edges: list[Edge] = field(default_factory=list)

    @property
    def size(self) -> int:
        return len(self.members)


def read_ppid(pid: int) -> int | None:
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return None
    fields = stat[stat.rindex(")") + 2:].split()
    return int(fields[1]) if fields[0] not in ("Z", "X", "x") else None


def fd_links(pid: int) -> dict[tuple[str, int], list[int]] | None:
    """{(kind, inode): [fd, ...]} for every pipe/socket ``pid`` holds; None if unreadable."""
    out: dict[tuple[str, int], list[int]] = {}
    base = f"/proc/{pid}/fd"
    try:
        names = os.listdir(base)
    except (FileNotFoundError, ProcessLookupError):
        return {}
    except PermissionError:
        return None
    for name in names:
        try:
            target = os.readlink(f"{base}/{name}")
        except OSError:
            continue
        for kind in LINK_KINDS:
            if target.startswith(f"{kind}:["):
                out.setdefault((kind, int(target[len(kind) + 2:-1])), []).append(int(name))
    return out


def all_pids() -> list[int]:
    return [int(n) for n in os.listdir("/proc") if n.isdigit()]


def find_edges(pids: list[int]) -> list[Edge]:
    """Edges among ``pids`` only (parent/child and shared pipe/socket inodes)."""
    pidset = set(pids)
    edges: list[Edge] = []
    for p in pids:
        pp = read_ppid(p)
        if pp in pidset:
            edges.append(Edge(pp, p, "parent/child", f"/proc/{p}/stat ppid={pp}"))
    holders: dict[tuple[str, int], list[tuple[int, list[int]]]] = {}
    for p in pids:
        for link, fds in (fd_links(p) or {}).items():
            holders.setdefault(link, []).append((p, fds))
    for (kind, inode), hs in sorted(holders.items()):
        for i in range(len(hs)):
            for j in range(i + 1, len(hs)):
                (pa, fa), (pb, fb) = hs[i], hs[j]
                edges.append(Edge(pa, pb, kind, f"{kind}:[{inode}] held by {pa} fd {fa} and {pb} fd {fb}"))
    return edges


def build_groups(pids: list[int]) -> list[Group]:
    """Connected components of the edge graph over ``pids`` (union-find)."""
    edges = find_edges(pids)
    parent = {p: p for p in pids}

    def root(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for e in edges:
        parent[root(e.a)] = root(e.b)
    comps: dict[int, Group] = {}
    for p in sorted(pids):
        comps.setdefault(root(p), Group([])).members.append(p)
    for e in edges:
        comps[root(e.a)].edges.append(e)
    return list(comps.values())


def capturable(group: Group) -> tuple[bool, int | None, str]:
    """(ok, root_pid, reason): can ``criu dump -t root`` take exactly this group?"""
    members = set(group.members)
    ppids = {p: read_ppid(p) for p in members}
    dead = [p for p, pp in ppids.items() if pp is None]
    if dead:
        return False, None, f"member(s) {sorted(dead)} not alive"
    roots = [p for p, pp in ppids.items() if pp not in members]
    if len(roots) != 1:
        return False, None, (f"not one subtree: {len(roots)} members have a parent outside the group "
                             f"{sorted(roots)} (CRIU dumps one tree from one root pid)")
    root_pid = roots[0]

    # Whole-system scan: the root's real descendants, and who else holds our inodes.
    children: dict[int, list[int]] = {}
    outside_links: dict[tuple[str, int], list[int]] = {}
    ours: dict[tuple[str, int], int] = {}
    for p in members:
        for link in (fd_links(p) or {}):
            ours[link] = p
    unreadable: list[int] = []
    for p in all_pids():
        pp = read_ppid(p)
        if pp is not None:
            children.setdefault(pp, []).append(p)
        if p in members or p == os.getpid():
            continue
        links = fd_links(p)
        if links is None:
            unreadable.append(p)
            continue
        for link in links:
            if link in ours:
                outside_links.setdefault(link, []).append(p)

    tree, todo = set(), [root_pid]
    while todo:
        p = todo.pop()
        if p not in tree:
            tree.add(p)
            todo.extend(children.get(p, []))
    if tree != members:
        extra, missing = sorted(tree - members), sorted(members - tree)
        return False, root_pid, (f"not exactly one subtree of root {root_pid}: dump would also take "
                                 f"{extra or 'nothing'}, would miss {missing or 'nothing'}")
    if outside_links:
        (kind, inode), who = next(iter(sorted(outside_links.items())))
        return False, root_pid, (f"{kind}:[{inode}] of member {ours[(kind, inode)]} is also held by "
                                 f"outside pid(s) {who}; that link could not be restored")
    if unreadable:
        return False, root_pid, (f"isolation unprovable: fd tables of {len(unreadable)} process(es) "
                                 f"unreadable (e.g. {unreadable[:5]}); not root?")
    return True, root_pid, (f"one subtree rooted at {root_pid} ({len(members)} members), no pipe/socket "
                            f"shared with any of {len(all_pids())} other processes")


def _main() -> int:
    ap = argparse.ArgumentParser(description="Show dependency edges and groups among PIDs (read-only).")
    ap.add_argument("--pid", type=int, action="append", required=True)
    args = ap.parse_args()
    for g in build_groups(args.pid):
        print(f"group {g.members}")
        for e in g.edges:
            print(f"  {e.describe()}")
        if g.size > 1:
            ok, root, why = capturable(g)
            print(f"  capturable={ok} root={root}: {why}")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
