from src.features import FEATURE_NAMES, feature_window, flow_features
from src.flows import PacketRecord


def rec(ts, d, payload):
    return PacketRecord(ts, d, payload + 66, payload)


def sample(extra=()):
    return [rec(0.0, 1, 517), rec(0.1, -1, 1200), rec(0.2, -1, 800),
            rec(0.3, 1, 90), rec(0.4, -1, 1400), rec(0.5, -1, 1400),
            rec(0.6, 1, 60), rec(0.7, -1, 300)] + list(extra)


def test_window_skips_client_hello():
    w = feature_window(sample(), 3)
    assert [r.payload for r in w] == [1200, 800, 90]


def test_features_have_all_names_and_expected_values():
    f = flow_features(sample(), 3)
    assert set(f) == set(FEATURE_NAMES)
    assert f["n_pkts"] == 3 and f["n_c2s"] == 1 and f["n_s2c"] == 2
    assert f["bytes_s2c"] == 2000 and f["bytes_c2s"] == 90
    assert f["first_s2c_size"] == 1200
    assert abs(f["window_duration"] - 0.2) < 1e-9


def test_no_future_information():
    """Changing packets after the first N must not change the features."""
    a = flow_features(sample(), 4)
    b = flow_features(sample(extra=[rec(9.0, -1, 5), rec(9.5, 1, 7)])[:8], 4)
    c = flow_features(
        sample()[:7] + [rec(50.0, -1, 1), rec(60.0, 1, 2)], 4)
    assert a == b == c


def test_unanswered_flow_has_no_window():
    assert flow_features([rec(0.0, 1, 517), rec(0.1, 1, 300)], 5) is None
    assert flow_features([], 5) is None
