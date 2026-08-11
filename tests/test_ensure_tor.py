import unittest
from pathlib import Path

from scripts import ensure_tor


BRIDGE_ONE = (
    "obfs4 203.0.113.10:443 "
    "0123456789ABCDEF0123456789ABCDEF01234567 "
    "cert=AbCdEf0123456789+/== iat-mode=0"
)
BRIDGE_TWO = (
    "obfs4 [2001:db8::10]:8443 "
    "89ABCDEF0123456789ABCDEF0123456789ABCDEF "
    "cert=ZyXwVu9876543210+/== iat-mode=1"
)


class BootstrapArgs:
    pool = Path("/nonexistent/ruthenium-obfs4-bridges")
    torrc = Path("/nonexistent/torrc")
    fetch_timeout = 1
    bridge_timeout = 1
    curl_timeout = 1


class EnsureTorBootstrapTest(unittest.TestCase):
    def bootstrap(self, pool, attempts, fetched=None):
        """Run bootstrap() with the pool, bridge attempts and BridgeDB stubbed."""
        calls = []
        outcomes = list(attempts)

        def fake_load_pool(path):
            return list(pool)

        def fake_try_bridges(candidates, known, args):
            calls.append(("try", list(candidates)))
            return outcomes.pop(0)

        def fake_fetch(timeout):
            calls.append(("fetch", timeout))
            if fetched is None:
                raise AssertionError("BridgeDB must not be contacted")
            return list(fetched)

        def fake_save_pool(path, bridges):
            calls.append(("save", list(bridges)))

        originals = (
            ensure_tor.load_pool,
            ensure_tor.try_bridges,
            ensure_tor.fetch_obfs4_bridges,
            ensure_tor.save_pool,
        )
        ensure_tor.load_pool = fake_load_pool
        ensure_tor.try_bridges = fake_try_bridges
        ensure_tor.fetch_obfs4_bridges = fake_fetch
        ensure_tor.save_pool = fake_save_pool
        try:
            result = ensure_tor.bootstrap(BootstrapArgs())
        finally:
            (
                ensure_tor.load_pool,
                ensure_tor.try_bridges,
                ensure_tor.fetch_obfs4_bridges,
                ensure_tor.save_pool,
            ) = originals
        return result, calls

    def test_a_working_cached_bridge_never_contacts_bridgedb(self):
        result, calls = self.bootstrap([BRIDGE_ONE], attempts=[True])
        self.assertTrue(result)
        self.assertEqual([("try", [BRIDGE_ONE])], calls)

    def test_bridgedb_is_contacted_only_after_every_cached_bridge_fails(self):
        result, calls = self.bootstrap(
            [BRIDGE_ONE], attempts=[False, True], fetched=[BRIDGE_ONE, BRIDGE_TWO]
        )
        self.assertTrue(result)
        self.assertEqual(
            [
                ("try", [BRIDGE_ONE]),
                ("fetch", 1),
                ("save", [BRIDGE_ONE, BRIDGE_TWO]),
                ("try", [BRIDGE_TWO]),
            ],
            calls,
        )

    def test_an_empty_pool_goes_straight_to_bridgedb(self):
        result, calls = self.bootstrap([], attempts=[True], fetched=[BRIDGE_TWO])
        self.assertTrue(result)
        self.assertEqual(
            [("fetch", 1), ("save", [BRIDGE_TWO]), ("try", [BRIDGE_TWO])], calls
        )

    def test_unreachable_bridgedb_reports_instead_of_crashing(self):
        def fake_load_pool(path):
            return []

        def fake_fetch(timeout):
            raise OSError("connection refused")

        originals = (ensure_tor.load_pool, ensure_tor.fetch_obfs4_bridges)
        ensure_tor.load_pool = fake_load_pool
        ensure_tor.fetch_obfs4_bridges = fake_fetch
        try:
            with self.assertRaisesRegex(SystemExit, "could not obtain obfs4 bridges"):
                ensure_tor.bootstrap(BootstrapArgs())
        finally:
            ensure_tor.load_pool, ensure_tor.fetch_obfs4_bridges = originals


class EnsureTorTest(unittest.TestCase):
    def test_extracts_and_deduplicates_obfs4_lines(self):
        document = f"<div>{BRIDGE_ONE}<br>{BRIDGE_TWO}<br>{BRIDGE_ONE}</div>"
        self.assertEqual(
            [BRIDGE_ONE, BRIDGE_TWO], ensure_tor.extract_obfs4_bridges(document)
        )

    def test_rejects_invalid_address(self):
        invalid = BRIDGE_ONE.replace("203.0.113.10", "999.0.0.1")
        with self.assertRaises(ValueError):
            ensure_tor.extract_obfs4_bridges(invalid)

    def test_torrc_enforces_bridge_and_socks_auth_isolation(self):
        torrc = ensure_tor.render_torrc(BRIDGE_ONE)
        self.assertIn("UseBridges 1", torrc)
        self.assertIn("ClientTransportPlugin obfs4", torrc)
        self.assertIn(f"Bridge {BRIDGE_ONE}", torrc)
        self.assertIn("SocksPort 127.0.0.1:9050 IsolateSOCKSAuth", torrc)

    def test_github_publisher_is_fail_closed_and_uses_remote_dns(self):
        repository_root = Path(__file__).resolve().parents[1]
        firewall = (repository_root / "infra/ruthenium-publisher.nft").read_text()
        wrapper = (repository_root / "scripts/with_tor.sh").read_text()
        self.assertIn('meta skuid "ruthenium-publisher"', firewall)
        self.assertIn("ip daddr != 127.0.0.0/8 reject", firewall)
        self.assertIn("ip6 daddr != ::1 reject", firewall)
        self.assertIn("socks5h://", wrapper)
        self.assertIn('get("IsTor") is True', wrapper)
        self.assertIn("RUTHENIUM_TOR_VERIFIED=1", wrapper)
        self.assertIn('TOR_SOCKS_HOST="127.0.0.1"', wrapper)
        self.assertIn('TOR_SOCKS_PORT="9050"', wrapper)
        self.assertNotIn("${TOR_SOCKS_HOST:-", wrapper)
        self.assertNotIn("${TOR_SOCKS_PORT:-", wrapper)
        self.assertIn("/usr/bin/curl --disable", wrapper)
        self.assertIn("/usr/bin/python3", wrapper)

    def test_github_preflight_requires_tor_and_hides_token_from_argv(self):
        repository_root = Path(__file__).resolve().parents[1]
        pipeline = (repository_root / ".gitlab-ci.yml").read_text()
        preflight = (repository_root / "scripts/github_preflight.sh").read_text()
        self.assertIn("github_preflight:", pipeline)
        self.assertIn("sudo /usr/local/sbin/ruthenium-ensure-tor", pipeline)
        self.assertIn("/usr/local/bin/ruthenium-with-tor", pipeline)
        self.assertIn("unset RUTHENIUM_GITHUB_TOKEN", pipeline)
        self.assertIn("^github_pat_[A-Za-z0-9_]+$", pipeline)
        self.assertIn("--config \"$AUTH_CONFIG\"", preflight)
        self.assertIn("/usr/bin/curl --disable", preflight)
        self.assertIn("/usr/bin/python3", preflight)
        self.assertNotIn("RUTHENIUM_GITHUB_TOKEN", preflight)
        self.assertIn("RUTHENIUM_TOR_VERIFIED", preflight)

    def test_tor_bootstrap_uses_fixed_system_executables(self):
        self.assertEqual(Path("/usr/bin/tor"), ensure_tor.TOR_PATH)
        self.assertEqual(Path("/usr/bin/curl"), ensure_tor.CURL_PATH)
        self.assertEqual(Path("/usr/bin/systemctl"), ensure_tor.SYSTEMCTL_PATH)


if __name__ == "__main__":
    unittest.main()
