import angr
from util import *

regs = ['rax', 'rdi', 'rsi', 'rdx', 'rbx']

class Plan(object):

    def __init__(self, target, solver):
        if solver is None:
            return
        self.constraints = []
        self.gadgets = []
        self.regs = {}
        self.care = []
        for r in regs:
            self.regs[r] = solver.BVS(r + "_initial", 64)
        for r in target.keys():
            self.care.append(r)
            self.constraints.append(self.regs[r] == target[r]) # TODO handle memory

    def is_goal(self):
        return len(self.care) == 0

    def __lt__(self, other):
        return len(self.care) < len(other.care)

    def copy(self):
        other = Plan({}, None)
        other.constraints = self.constraints[:]
        other.gadgets = self.gadgets[:]
        other.regs = {k:v for k, v in self.regs.items()}
        other.care = self.care[:]
        return other

    def get_children(self, library, solver, project):
        reg = self.care[0]
        tr = []
        for g in library[reg]:
            new = add_gadget(self.copy(), g, solver, project)
            if new is not None:
                # Calculating a new care
                new.care.remove(reg)
                new.care.append(g.depmap[reg])
                new.care = [x for x in regs if x in new.care]
                tr.append(new)
        return tr

def add_gadget(plan, gadget, solver, project):
    bc = project.factory.blank_state(addr=gadget.addrs[0])
    bc.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
    bc.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
    nrs = {}
    for r in regs:
        nrs[r] = solver.BVS(f"{r}_int_{len(plan.gadgets)}_care_", 64)
        plan.constraints.append(getattr(bc.regs, r) == nrs[r])

    after = run_trace(bc, project, gadget.addrs, project.arch.registers.keys())

    for r in regs:
        plan.constraints.append(getattr(after.regs, r) == plan.regs[r])
    plan.constraints += after.simplify()

    plan.regs = nrs
    plan.gadgets.append(gadget)

    if solver.satisfiable(plan.constraints):
        return plan
    else:
        return None

