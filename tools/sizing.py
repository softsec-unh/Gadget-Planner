
from sys import getsizeof

def total_size(object):
    "The approximate memory footprint of an object and it's contents."

    total = 0
    seen = set()
    queue = [object]
    while len(queue) != 0:
        item = queue.pop()
        if id(item) in seen:
            continue
        seen.add(id(item))
        for i in (getattr(item, n) for n in dir(item)):
            if len(queue) > 1000:
                break
            queue.append(i)
        total += getsizeof(item, 24)

    return total

