
import collections
import angr

Pointer = collections.namedtuple("Pointer", "to")

class Gadget(collections.namedtuple('Gadget', 'addrs before after deps post depmap registers_changed')):
    __slots__ = ()

class Synthetic():
    def __init__(self, wrapped):
        self.wrapped = wrapped
    def __getattr__(self, name):
        return getattr(self.wrapped, name)

def mk_initial_gadget(project, target):
    # TODO consolidate with similar logic in main.py
    before = project.factory.blank_state()
    before.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
    before.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)

    # Force registers to be initialized
    for reg in project.arch.registers.keys():
        temp = getattr(before.regs, reg)

    target_goals = []
    # Just registers for now
    for key, value in target.items():
        if type(value) == Pointer:
            target_goals.append((key, before.mem[getattr(before.regs, key)] == value.to))
        else:
            target_goals.append((key, getattr(before.regs, key) == value))

    return Gadget([], before, before, target_goals, [])
