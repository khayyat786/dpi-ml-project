from src.rules import ALLOW, BLOCK, THROTTLE, RuleEngine


def make():
    return RuleEngine(ALLOW, {"doubleclick.net": BLOCK,
                              "googlevideo.com": THROTTLE,
                              "ads.googlevideo.com": BLOCK})


def test_exact_and_subdomain_match():
    e = make()
    assert e.match("doubleclick.net") == (BLOCK, "doubleclick.net")
    assert e.match("googleads.g.doubleclick.net")[0] == BLOCK
    assert e.match("rr2.googlevideo.com")[0] == THROTTLE


def test_no_partial_word_match():
    assert make().match("notdoubleclick.net")[0] == ALLOW


def test_most_specific_rule_wins():
    assert make().match("ads.googlevideo.com")[0] == BLOCK


def test_unknown_and_missing_sni_use_default():
    e = make()
    assert e.match("wikipedia.org") == (ALLOW, "")
    assert e.match(None) == (ALLOW, "")


def test_yaml_file(tmp_path):
    f = tmp_path / "r.yaml"
    f.write_text("default_action: ALLOW\nrules:\n  - action: BLOCK\n"
                 "    domains: [bad.com]\n")
    assert RuleEngine.from_yaml(f).match("x.bad.com")[0] == BLOCK
