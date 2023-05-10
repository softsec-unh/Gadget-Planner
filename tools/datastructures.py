class PriorityQueue():
    def __init__(self):
        self.data = []
        self.len = 0

    def get(self):
        if self.len == 0:
            return None
        self.len -= 1
        item = self.data[0]
        self.move_up(0)
        return item

    def move_up(self, index):
        if self.leaf(index):
            self.data[index] = None
            return # We're done
        a, b = self.get_child_indexes(index)
        if self.data[a] < self.data[b]:
            self.data[index] = self.data[a]
            self.move_up(a)
        else:
            self.data[index] = self.data[b]
            self.move_up(b)
