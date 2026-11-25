from src.labeling import (is_ignored, parse_capture_name, select_labeled,
                          site_key)

CFG = {"ignore_domains": ["microsoft.com", "avcdn.net"]}


def test_site_key():
    assert site_key("rr2---sn-abc.googlevideo.com") == "googlevideo.com"
    assert site_key("www.nust.edu.pk") == "nust.edu.pk"
    assert site_key("static.files.bbci.co.uk") == "bbci.co.uk"
    assert site_key("dawn.com") == "dawn.com"


def test_parse_capture_name():
    assert parse_capture_name("data/x/youtube_B_02.pcapng") == {
        "prefix": "youtube", "network": "B", "session": 2}
    assert parse_capture_name("dload_B_01.pcapng")["prefix"] == "dload"


def test_ignored_background():
    assert is_ignored("v20.events.data.microsoft.com", CFG["ignore_domains"])
    assert not is_ignored("notmicrosoft.com", CFG["ignore_domains"])


def test_select_labeled_rules():
    items = [
        {"label_class": "youtube", "sni": "rr1.googlevideo.com"},
        {"label_class": "youtube", "sni": "fonts.gstatic.com"},
        {"label_class": "browsing", "sni": "static.gstatic.com"},   # shared site
        {"label_class": "browsing", "sni": "dawn.com"},
        {"label_class": "whatsapp", "sni": "ecs.microsoft.com"},    # background
    ]
    kept, reasons, shared = select_labeled(items, CFG)
    assert sorted(i["sni"] for i in kept) == ["dawn.com", "rr1.googlevideo.com"]
    assert reasons["ignored_background"] == 1
    assert reasons["shared_between_classes"] == 2
    assert set(shared) == {"gstatic.com"}
