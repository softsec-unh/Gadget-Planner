import hy
import stn
from gadget import Pointer
from claripy.ast.bv import BV
from util import run_trace
from collections import defaultdict

# TODO fill in
def interferes(a, b):
    return False

def get_interferers(i, links):
    return [l for l in links if interferes(i, l)]

class Instance(object):
    # Gadget is a pointer to the gadget involved
    # Goals is a (reg -> value) mapping
    # Fulfullments points off to other instances that fulfill a pre-requisite
    # st and et are timepoints
    __slots__ = ('goals', 'gadget', 'fulfillments', 'time', 'fulfills', 'why')

    def __init__(self, goals, gadget, time):
        self.goals = goals
        self.gadget = gadget
        self.time = time
        self.fulfillments = {}
        self.fulfills = None
        self.why = None

    def copy(self):
        i = Instance(self.goals, self.gadget, self.time)
        i.fulfillments = dict(self.fulfillments)
        i.why = self.why
        i.fulfills = self.fulfills
        return i

    def fulfill_preq(self, preq, other):
        self.fulfillments[preq] = other
        other.fulfills = self
        other.why = preq

    def remaining_preqs(self):
        #if self.gadget == 'Win':
        has = set(self.goals.keys())
        #else:
        #    has = set(map(lambda x: x[0], self.gadget.deps))
        return has.difference(set(self.fulfillments.keys()))

    def __repr__(self):
        return f"Instance: { {k:v for k, v in self.goals.items() if k in self.remaining_preqs()} }"

    def update_vars(self, repls):
        for k in self.goals.keys():
            if self.goals[k] in repls.keys():
                self.goals[k] = repls[self.goals[k]]

    def has_cycle(self):
        "Determines if any of the items in the open list are part of the fulfillment chain."
        for k, v in self.goals.items():
            next, why = self.fulfills, self.why
            while next is not None:
                if k == why:
                    b = next.goals[k] if k in next.goals.keys() else None
                    if type(b) == BV or type(v) == BV:
                        # TODO handle this
                        pass
                    else:
                        if b == v:
                            return True
                next, why = next.fulfills, next.why
        return False

STACK_OFFSET = 0

class Plan(object):
    # open_list is a list of instances that aren't solved yet
    # causal_links is a list of (st, et, reg) where reg can't be touched
    # debug_gadgets is a list of all gadgets involved in the plan
    # All collected constraints so far.
    __slots__ = ('open_list', 'causal_links', 'solved', 'parents', 'solver', 'gadgets', 'depth')

    def __init__(self, starting_goals, solver):
        self.open_list = [Instance(starting_goals, "Win", 0)]
        self.solved = []
        self.causal_links = []
        self.parents = []
        self.gadgets = []
        self.solver = solver
        self.depth = 0

    def is_goal(self):
        return len(self.open_list) == 0

    def copy(self):
        other = Plan(None, self.solver.copy())
        other.solver.state = self.solver.state
        other.open_list = [i.copy() for i in self.open_list]
        other.causal_links = self.causal_links[:]
        other.solved = self.solved[:]
        other.parents = self.parents[:]
        other.gadgets = self.gadgets[:]
        other.depth = self.depth + 1
        return other

    def __repr__(self):
        return f"\nPlan object:\n  open: {self.open_list}\n  constraints: {[x for x in self.solver.constraints if not x.is_true()]}"

    def weighted_depth(self, weight=10):
        return weight * sum(len(x.remaining_preqs()) for x in self.open_list) + len(self.gadgets)

    def __lt__(self, other):
        #if len(self.solver.constraints) < len(other.solver.constraints):
        #    return True
        #if len(self.solver.constraints) > len(other.solver.constraints):
        #    return False
        x = 1000 * sum(len(x.remaining_preqs()) for x in self.open_list) + self.depth
        y = 1000 * sum(len(x.remaining_preqs()) for x in other.open_list) + other.depth
        if x == y:
            x = len(self.solver.constraints)
            y = len(self.solver.constraints)
            if x != y:
                return x < y
            x = 0
            y = 0
            for o in self.open_list:
                for a, b in o.goals.items():
                    if type(b) != Pointer and type(b) != BV:
                        x += b
                    elif type(b) == BV:
                        try:
                            x += self.solver.min(b) + 1
                        except:
                            pass
            for o in other.open_list:
                for a, b in o.goals.items():
                    if type(b) != Pointer and type(b) != BV:
                        y += b
                    elif type(b) == BV:
                        try:
                            y += self.solver.min(b) + 1
                        except:
                            pass
            if x == y:
                return len(self.solved) < len(other.solved)
            else:
                return x < y
        else:
            return x < y

    def duplicates(self, other):
        if True:
            return False
        if len(self.open_list) < len(other.open_list):
            return False
        x = defaultdict(int)
        y = defaultdict(int)
        for i in range(len(self.open_list)):
            for p in self.open_list[i].remaining_preqs():
                if type(self.open_list[i].goals[p]) == BV:
                    # Probabalistically finding duplicates
                    # Note: this isn't strictly correct. This will say
                    # that some things duplicate each other when
                    # they actually don't.
                    #x[p] += self.solver.min(self.open_list[i].goals[p])
                    return False
                elif type(self.open_list[i].goals[p]) == Pointer:
                    x[p] += STACK_OFFSET + 0xcafeface # TODO make this the stack map
                else:
                    x[p] += self.open_list[i].goals[p]
        for i in range(len(other.open_list)):
            for p in other.open_list[i].remaining_preqs():
                if type(other.open_list[i].goals[p]) == BV:
                    #y[p] += other.solver.min(other.open_list[i].goals[p])
                    return False
                elif type(other.open_list[i].goals[p]) == Pointer:
                    y[p] += STACK_OFFSET + 0xcafeface
                else:
                    y[p] += other.open_list[i].goals[p]
        return x == y

    def get_children(self, library, solver):
        global STACK_OFFSET
        # To make this work properly, STACK_MAP should be set to
        # the symbolic value representing the initial stack pointer.
        # (I think - we need to take special care to make sure that
        # the initial stack pointer never gets unified. Maybe there's
        # a better way?)
        STACK_MAP = 0xcafeface
        if self.is_goal():
            return []
        next = self.open_list[0] # :: Instance
        reg = list(next.remaining_preqs())[0] # :: reg
        target_value = next.goals[reg] # :: a claripy value

        children = []
        for gadget in library[reg]:
            # poststate :: a claripy value
            poststate = gadget.post[reg]
            if type(target_value) == Pointer:
                STACK_OFFSET += 1 # To ensure uniqueness
                target_value = STACK_MAP + STACK_OFFSET
            # There is a way for the post condition to produce the target value
            conds = [poststate == target_value]
            if solver.satisfiable(conds):
                children += self.add_gadget(gadget, reg, target_value)
        return children

        # for next in self.open_list:
        #     for reg in next.remaining_preqs():
        #         target_value = next.goals[reg] # :: a claripy value
        #         for gadget in cfi_filter(library[reg], self.gadgets[-1].before.regs.ip) if len(self.gadgets) != 0 else library[reg]:
        #             # poststate :: a claripy value
        #             poststate = gadget.post[reg]
        #             if type(target_value) == Pointer:
        #                 STACK_OFFSET += 1 # To ensure uniqueness
        #                 target_value = STACK_MAP + STACK_OFFSET
        #                 # There is a way for the post condition to produce the target value
        #             conds = [poststate == target_value]
        #             if solver.satisfiable(conds):
        #                 children += self.add_gadget(gadget, reg, target_value)
        # return children

    # Note: Returns a list bc promotion/demotion
    def add_gadget(self, gadget, reg, needed_post_value):
        plan = self.copy()
        plan.parents.append(self)
        plan.gadgets.append(gadget)

        plan.causal_links.append((len(plan.gadgets) - 1, len(plan.gadgets), reg))

        if type(needed_post_value) == BV:
            solns = plan.solver.eval_upto(needed_post_value, 2)
            if len(solns) == 0:
                return []
            elif len(solns) == 1:
                needed_post_value = solns[0]
            else:
                # TODO How do we handle this case correctly? Need to propagate
                # constraints back to state from plan?
                # This is a hacky work around:
                needed_post_value = plan.solver.min(needed_post_value)

        state = gadget.after.copy()
        state.solver.add(needed_post_value == getattr(state.regs, reg))

        if not state.solver.satisfiable():
            return []

        #
        # Evaluate the prev value's variable in the context of state.solver
        #

        # breakpoint()

        replacements = dict()
        for eno, (o, s) in gadget.after.project.arch.registers.items():
            if eno == 'ip':
                continue
            replacements[eno] = plan.solver.BVS('plan_var', s*8)

        newdeps = gadget.depmap[reg]
        newgoals = dict() # TODO add gadget deps
        if 'ip' in newdeps:
            # What the hell? Should that be happening?
            breakpoint()
        for nreg in newdeps:
            if nreg not in dir(gadget.before.regs):
                continue # TODO this is just straight up incorrect. How can we fix this?
            solutions = state.solver.eval_upto(getattr(gadget.before.regs, nreg), 2)
            #do_hacky_pruning = False
            #tmps = [4] #[x for x in solutions if x < needed_post_value]
            if len(solutions) == 0:
                return []
            elif len(solutions) == 1:
                newgoals[nreg] = solutions[0]
            ## TO DO this is a bit of a hack to prefer simpler solutions
            #elif len(tmps) == 1 and do_hacky_pruning:
            #    newgoals[reg] = tmps[0]
            else:
                slv = getattr(gadget.before.regs, nreg)
                m = state.solver.min(slv)
                if len(plan.gadgets) > 32: # If the plan is too deep already, give up on being fully symbolic. This is also a hack.
                    newgoals[nreg] = m
                    continue
                try:
                    om = state.solver.min(slv, extra_constraints=[m != slv])
                    if (om - m) > 16: # This is a hacky solution to helping constraint-collapse
                        # This contributes to preventing loops
                        newgoals[nreg] = m
                        continue
                except:
                    pass

                afvalue = getattr(state.regs, nreg)
                for k, v in replacements.items():
                    r = getattr(gadget.before.regs, k)
                    if r.symbolic:
                        afvalue = afvalue.replace(getattr(gadget.before.regs, k), v)
                plan.solver.add(needed_post_value == afvalue)
                try:
                    if len(plan.solver.eval_upto(replacements[nreg], 2)) == 1:
                        newgoals[reg] = plan.solver.eval(replacements[nreg])
                    else:
                        newgoals[reg] = replacements[nreg]
                except:
                    newgoals[reg] = replacements[nreg] # TODO is this the right thing to do?

        plan.solver.simplify()

        if not plan.solver.satisfiable():
            return []

        newinst = Instance(newgoals, gadget, "NO LONGER USING TIMEPOINTS")
        plan.open_list[0].fulfill_preq(reg, newinst)

        if newinst.has_cycle():
            return []

        plan.open_list.append(newinst)
        plan.open_list.sort(key=lambda l: len(l.remaining_preqs()))
        plan.solved += [x for x in plan.open_list if len(x.remaining_preqs()) == 0]
        plan.open_list = [x for x in plan.open_list if len(x.remaining_preqs()) != 0]

        tr = [plan]

        return [t for t in tr if not any(t.duplicates(x) for x in t.parents)]

    def display(self):
        points = self.stn.find_order()
        print("")
        for timePoint in points:
            print(f"At time point {timePoint}:")
            for (st, et, protected) in self.causal_links:
                if timePoint == st:
                    print(f"  A causal link protecting {protected} starts.")
                if timePoint == et:
                    print(f"  A causal link protecting {protected} ends.")
            for inst in self.solved:
                if timePoint == inst.time:
                    print("  We execute the following gadget:")
                    if type(inst.gadget) == str:
                        print("-- Execute the vulnerability and succeed --")
                    else:
                        inst.gadget.before.block().pp()
                        #breakpoint()
                        if inst.fulfills is not None:
                            print(f"  To set {inst.why} to {inst.fulfills.goals[inst.why]}")
                        else:
                            breakpoint()
