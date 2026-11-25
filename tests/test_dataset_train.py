import random

import pandas as pd

from src import build_dataset, train_model
from src.features import FEATURE_NAMES
from tests.helpers import tcp_flow_data, write_capture


def make_capture(path, cls, session, rng):
    """Fake capture with class-specific behavior, noise and shared sites."""
    pkts, t = [], 1000.0 + session * 100
    port = 40000
    shape = {  # server sizes, client sizes, gap
        "youtube": (lambda: [rng.randint(1200, 1450) for _ in range(12)],
                    lambda: [rng.randint(60, 120) for _ in range(6)], 0.002),
        "whatsapp": (lambda: [rng.randint(80, 300) for _ in range(12)],
                     lambda: [rng.randint(80, 300) for _ in range(12)], 0.05),
        "browsing": (lambda: [rng.randint(300, 900) for _ in range(12)],
                     lambda: [rng.randint(200, 500) for _ in range(6)], 0.01),
    }[cls]
    names = {"youtube": lambda i: f"rr{i}.googlevideo.com",
             "whatsapp": lambda i: f"media{i}.whatsapp.net",
             "browsing": lambda i: f"site{i}.example.org"}[cls]
    for i in range(25):
        port += 1
        pkts += tcp_flow_data("10.7.0.2", port, f"20.0.{i}.1", 443, names(i),
                              shape[0](), shape[1](), shape[2], t)
        t += 1
    for i in range(3):                      # background and shared websites
        port += 1
        pkts += tcp_flow_data("10.7.0.2", port, "30.0.0.1", 443,
                              "ecs.office.com", [500] * 5, [100] * 3, 0.01, t)
        port += 1
        pkts += tcp_flow_data("10.7.0.2", port, "30.0.1.1", 443,
                              "fonts.gstatic.com", [700] * 5, [100] * 3, 0.01, t)
        t += 1
    write_capture(path, pkts)


def test_build_dataset_and_train(tmp_path):
    rng = random.Random(1)
    data = tmp_path / "data"
    data.mkdir()
    for cls in ("youtube", "whatsapp", "browsing"):
        for s in (1, 2, 3):
            make_capture(data / f"{cls}_B_0{s}.pcap", cls, s, rng)
    make_capture(data / "dload_B_01.pcap", "youtube", 1, rng)     # unused class
    make_capture(data / "test_00_B.pcap", "youtube", 1, rng)      # skipped

    res = tmp_path / "res"
    out = build_dataset.build([str(data)], "config/labels.yaml", str(res))
    assert out["reasons"]["ignored_background"] == 27      # 9 files x 3 flows
    assert out["reasons"]["shared_between_classes"] == 27  # fonts.gstatic.com
    assert set(out["shared"]) == {"gstatic.com"}
    assert out["per_class"] == {"youtube": 75, "whatsapp": 75, "browsing": 75}
    df = pd.read_csv(res / "dataset_n10.csv")
    assert set(df["label"]) == {"youtube", "whatsapp", "browsing"}
    assert len(df) == 225
    assert "sni" in df.columns and "sni" not in FEATURE_NAMES
    assert (res / "labeling_summary.csv").exists()
    assert (res / "dataset_n5.csv").exists() and (res / "dataset_n20.csv").exists()

    r = train_model.run(10, str(res), str(tmp_path / "models"))
    assert r["table"].loc["Random Forest", "macro_f1"] > 0.9
    assert r["table"].loc["Majority guess", "macro_f1"] < 0.5
    for name in ("model_comparison_n10.csv", "model_comparison_n10.png",
                 "confusion_matrix_n10.png", "confusion_matrix_n10.csv",
                 "classification_report_n10.txt",
                 "preliminary_comparison_n10.csv"):
        assert (res / name).exists(), name
    assert (tmp_path / "models" / "best_model_n10.joblib").exists()
