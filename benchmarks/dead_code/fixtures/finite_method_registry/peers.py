class PeerBase:
    def render(self, result):
        raise NotImplementedError


class Peer(PeerBase):
    def render_a(self, value):
        return value
