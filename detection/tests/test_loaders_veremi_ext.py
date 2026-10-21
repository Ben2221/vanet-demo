"""VeReMi Extension (Mendeley release): one CSV row per message, "class" 0-19, no receiver."""
import csv

from detection.loaders import VEREMI_EXT_CLASSES, keep_sender, load

HEADER = ("type,sendTime,sender,senderPseudo,messageID,class,posx,posy,posz,posx_n,posy_n,posz_n,"
          "spdx,spdy,spdz,spdx_n,spdy_n,spdz_n,aclx,acly,aclz,aclx_n,acly_n,aclz_n,hedx,hedy,hedz,"
          "hedx_n,hedy_n,hedz_n").split(",")


def _row(sender, cls, t, x):
    v = dict.fromkeys(HEADER, "0.0")
    v.update(type="4", sendTime=str(t), sender=str(sender), senderPseudo=f"10{sender}", messageID=str(int(t * 10)),
             **{"class": str(cls)}, posx=str(x), posy="50.0", spdx="10.0", spdy="0.0", hedx="1.0", hedy="0.0")
    return v


def test_veremi_extension_rows(tmp_path):
    f = tmp_path / "mix.csv"
    with f.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=HEADER)
        w.writeheader()
        w.writerow(_row(7, 0, 1.0, 100.0))
        w.writerow(_row(8, 16, 1.0, 200.0))
    a, b = load(f)
    assert a["attack"] == "honest" and a["label"] == 0
    assert b["attack"] == "grid_sybil" and b["label"] == 1
    assert a["rsu_x"] is None and a["rsu_y"] is None          # no receiver in the data: no fake (0, 0)
    assert round(a["heading"]) == 90 and a["speed"] == 10.0 and a["pid"] == "107"
    assert len(VEREMI_EXT_CLASSES) == 20


def test_sample_keeps_whole_vehicles():
    kept = {s for s in range(2000) if keep_sender(s, 0.1)}
    assert 120 < len(kept) < 280
    assert all(keep_sender(s, 0.1) for s in kept)              # deterministic
