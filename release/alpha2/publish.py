"""Finish the verified alpha.2 draft; never modify an already published release."""
import hashlib
import json
import os
from pathlib import Path
from urllib.request import Request, urlopen

BASE = "https://api.github.com/repos/blasterfish7/murus_igneus"
TOKEN = os.environ["GH_TOKEN"]
RELEASE_ID = 418093921
SOURCE = "e749f34fb5ab5e497197241e8c1879a62555cbe4"

def request(url, method="GET", data=None, binary=False):
    headers = {"Authorization": "Bearer " + TOKEN, "Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28"}
    if data is not None:
        headers["Content-Type"] = "application/octet-stream" if binary else "application/json"
        if not binary:
            data = json.dumps(data).encode()
    with urlopen(Request(url, data=data, headers=headers, method=method), timeout=120) as response:
        body = response.read()
        return json.loads(body) if body else None

r = request(f"{BASE}/releases/{RELEASE_ID}")
assert r["draft"] and r["prerelease"] and r["tag_name"] == "v0.3.0-alpha.2"
tag = request(f"{BASE}/git/ref/tags/v0.3.0-alpha.2")
assert tag["object"]["type"] == "commit" and tag["object"]["sha"] == SOURCE
assets = {a["name"]: a for a in r["assets"]}
iso_name = "murus-igneus-0.3.0-alpha.2-devuan-amd64.iso"
old_deb = "murus-igneus_0.3.0.alpha.2_all.deb"
deb_name = "murus-igneus_0.3.0-alpha.2_all.deb"
guide_name = "MURUS-IGNEUS-ALPHA2-LEGGIMI.txt"
sum_name = "murus-igneus-0.3.0-alpha.2.sha256"
iso_sha = "fa3ee325e358401563e5350588b0cdec84833855f1de1310a849888b953b74ba"
deb_sha = "52f16678adac14d34db2b48ffb8c94de020073f63d8021af8605be0aff21d9f3"
actual_deb = old_deb if old_deb in assets else deb_name
assert set(assets) == {iso_name, actual_deb, guide_name, sum_name}
for name, size, digest in [(iso_name, 472274944, iso_sha), (actual_deb, 60312, deb_sha)]:
    assert assets[name]["state"] == "uploaded"
    assert assets[name]["size"] == size and assets[name]["digest"] == "sha256:" + digest
if actual_deb != deb_name:
    request(assets[actual_deb]["url"], "PATCH", {"name": deb_name})

guide = Path("release/alpha2/" + guide_name).read_bytes()
checksums = f"{iso_sha}  {iso_name}\n{deb_sha}  {deb_name}\n".encode()
for name, content in [(guide_name, guide), (sum_name, checksums)]:
    request(assets[name]["url"], "DELETE")
    upload = r["upload_url"].split("{")[0] + "?name=" + name
    result = request(upload, "POST", content, binary=True)
    assert result["name"] == name and result["state"] == "uploaded"
    assert result["digest"] == "sha256:" + hashlib.sha256(content).hexdigest()

r = request(f"{BASE}/releases/{RELEASE_ID}")
expected = {iso_name: iso_sha, deb_name: deb_sha,
            guide_name: hashlib.sha256(guide).hexdigest(),
            sum_name: hashlib.sha256(checksums).hexdigest()}
assert len(r["assets"]) == 4
for asset in r["assets"]:
    assert asset["state"] == "uploaded"
    assert asset["digest"] == "sha256:" + expected[asset["name"]]
published = request(f"{BASE}/releases/{RELEASE_ID}", "PATCH",
                    {"draft": False, "prerelease": True, "make_latest": "false",
                     "target_commitish": SOURCE})
assert not published["draft"] and published["prerelease"] and published["published_at"]
print(json.dumps({"url": published["html_url"], "published_at": published["published_at"],
                  "assets": [a["name"] for a in published["assets"]]}, indent=2))
