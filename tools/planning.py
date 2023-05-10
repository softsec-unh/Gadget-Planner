import collections
from functools import total_ordering
import copy
import psutil
import gc
import hy
from plan import Plan
from gadget import *

expansions = 0
max_queue = 0
branches = []

targets = {
    'execve': {'rax': 57,
               'rdi': 160256,
               'rsi': Pointer(0),
               'rdx': Pointer(0)
               },
}

def heappush(queue, x):
    i = 0
    while i < len(queue) and queue[i] < x:
        i += 1
    if i < len(queue) and queue[i].duplicates(x):
        return
    queue.insert(i, x)

def heappop(queue):
    return queue.pop(0)

def extend(queue, gen):  # TODO restore heap property better
    for x in gen:
        # if not any([x.duplicates(r) for r in queue]):
        heappush(queue, x)

def mk_initial_plan(project, target, solver):
    return Plan(target, solver)  # (mk_initial_gadget(project, target))

def search_ours(p, library, queue, solver, limit=None):
    i = 32
    while len(queue) != 0:
        print("Considering", len(queue), "possible plans.")
        print("The most prominent plan has", len(queue[0].stn.matrix), "time points")
        print(queue[0])
        plan = heappop(queue)
        if plan.is_goal(): return plan
        children = plan.get_children(library, solver)
        extend(queue, (c for c in children if not c.duplicates(plan)))
        if len(queue) > i:
            print("De-duplicating queue. (", i, ")")
            nq = []
            # Keep shorter plans preferentially. Not because
            # they're 'better', but because then the STNs/constraints
            # will be faster to solve.
            queue.sort(key=lambda l: len(l.stn.matrix))
            while len(queue) != 0:
                p = heappop(queue)
                if not any([p.duplicates(r) for r in nq]):
                    heappush(nq, p)
            queue = nq
            i = len(queue) * 2 # Amortising
            print("Queue now", len(queue), "items")

def forever(x):
    while True:
        yield x
        x += 1

def search_id(project, library, q, solver, limit=None):
    [root] = q
    for bound in forever(2):
        print(f"Searching to {bound}")
        incomplete = False
        backpoints = []
        backpoints.append(root.get_children(library, solver))
        while backpoints:
            point = backpoints.pop()
            if point == []:
                continue
            nxt = point.pop()
            backpoints.append(point)
            if nxt.is_goal():
                return nxt
            children = nxt.get_children(library, solver)
            children.sort()
            if nxt.weighted_depth() < bound:
                backpoints.append(children)
            else:
                incomplete = True

        if not incomplete:
            return None

def plan(project, library, limit=None):
    # TODO plan on each individually, make synthetic gadgets
    name = 0
    res = 0
    for name, target in targets.items():
        dummy = project.factory.blank_state()
        solver = dummy.solver
        q = [mk_initial_plan(project, target, solver)]
        # res = search_ours(project, library, q, solver)
        res = search_id(project, library, q, solver, limit=limit)
        if res is not None:
            break
    return name, res
