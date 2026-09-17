class SidManager:
    def __init__(self, start_sid=1000001):
        self.next_sid = start_sid

    def get_sid(self):
        sid = self.next_sid
        self.next_sid += 1
        return sid
