import pytest

from synology_manager.dsm import DsmError
from synology_manager.models import nfs_rules, share


def nfs(client: str = "192.0.2.0/24") -> dict[str, object]:
    return {
        "client": client,
        "privilege": "rw",
        "root_squash": "root",
        "async": True,
        "insecure": False,
        "crossmnt": False,
        "security_flavor": {
            "sys": True,
            "kerberos": False,
            "kerberos_integrity": False,
            "kerberos_privacy": False,
        },
    }


@pytest.mark.parametrize("quota", list(range(30)))
def test_share_quota_normalization(quota: int) -> None:
    observed = share(
        {
            "name": "data",
            "vol_path": "/volume1",
            "desc": "",
            "quota_value": str(quota),
            "share_quota_status": "v1",
        }
    )
    assert observed.quota_mib == quota


@pytest.mark.parametrize(
    "field",
    ["client", "privilege", "root_squash", "async", "insecure", "crossmnt", "security_flavor"],
)
def test_malformed_nfs_rules_fail_closed(field: str) -> None:
    value = nfs()
    value.pop(field)
    with pytest.raises(DsmError):
        nfs_rules([value])


def test_nfs_canonical_order_is_stable() -> None:
    assert nfs_rules([nfs("198.51.100.2/24"), nfs("192.0.2.1/24")]) == nfs_rules(
        [nfs("192.0.2.1/24"), nfs("198.51.100.2/24")]
    )
