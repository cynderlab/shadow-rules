from src.sid_manager import SidManager


class TestSidManager:
    def test_new_state_assigns_start_sid(self):
        mgr = SidManager(start_sid=5000)
        assert mgr.get_sid() == 5000

    def test_sequential_sids(self):
        mgr = SidManager(start_sid=5000)
        mgr.get_sid()
        assert mgr.get_sid() == 5001

    def test_no_repeated_sids(self):
        mgr = SidManager(start_sid=5000)
        sids = [mgr.get_sid() for _ in range(100)]
        assert len(sids) == len(set(sids))
