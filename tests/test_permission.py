import unittest

from syntecxhub_scanner.permission import PermissionDenied, check_permission


class PermissionTests(unittest.TestCase):
    def test_localhost_always_allowed(self):
        check_permission("http://localhost:8080/", allow_public=False, assume_yes=False, confirm=None)
        check_permission("http://127.0.0.1/", allow_public=False, assume_yes=False, confirm=None)

    def test_public_host_refused_without_flag(self):
        with self.assertRaises(PermissionDenied):
            check_permission(
                "https://example.com/", allow_public=False, assume_yes=False, confirm=lambda _: "yes"
            )

    def test_public_host_allowed_with_flag_and_assume_yes(self):
        check_permission("https://example.com/", allow_public=True, assume_yes=True, confirm=None)

    def test_public_host_requires_typed_confirmation(self):
        check_permission("https://example.com/", allow_public=True, assume_yes=False, confirm=lambda _: "yes")
        with self.assertRaises(PermissionDenied):
            check_permission(
                "https://example.com/", allow_public=True, assume_yes=False, confirm=lambda _: "no"
            )

    def test_unparseable_url_refused(self):
        with self.assertRaises(PermissionDenied):
            check_permission("not a url", allow_public=True, assume_yes=True, confirm=None)


if __name__ == "__main__":
    unittest.main()
