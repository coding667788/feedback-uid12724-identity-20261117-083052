"""编码、规范化 JSON 与令牌封装层测试。"""

from __future__ import annotations

import unittest

from solution.encoding import (
    b64url_decode,
    b64url_encode,
    canonical_dumps,
    json_decode_checked,
)
from solution.errors import ErrorCode, TokenError
from solution.token import (
    ALGORITHM,
    TOKEN_TYPE,
    build_header,
    decode_token,
    encode_token,
    verify_signature,
)


class TestBase64Url(unittest.TestCase):
    def test_roundtrip_and_no_padding(self):
        for raw in (b"a", b"ab", b"abc", b"abcd", bytes(range(256))):
            encoded = b64url_encode(raw)
            self.assertNotIn("=", encoded)
            self.assertEqual(b64url_decode(encoded), raw)

    def test_rejects_padding_plus_slash_whitespace(self):
        bad_inputs = ["YWJj=", "YW/J", "YW+J", " YWJj", "YWJj ", "YWJj\n"]
        for bad in bad_inputs:
            with self.subTest(bad=bad):
                with self.assertRaises(TokenError) as ctx:
                    b64url_decode(bad)
                self.assertEqual(ctx.exception.code, ErrorCode.MALFORMED_TOKEN)

    def test_rejects_empty(self):
        with self.assertRaises(TokenError) as ctx:
            b64url_decode("")
        self.assertEqual(ctx.exception.code, ErrorCode.MALFORMED_TOKEN)


class TestCanonicalJson(unittest.TestCase):
    def test_deterministic_key_order_and_compact(self):
        obj = {"b": 1, "a": [1, 2], "c": {"z": 1, "y": 2}}
        self.assertEqual(canonical_dumps(obj), b'{"a":[1,2],"b":1,"c":{"y":2,"z":1}}')

    def test_reject_duplicate_keys(self):
        raw = b'{"aud":"a","aud":"b"}'
        with self.assertRaises(TokenError) as ctx:
            json_decode_checked(raw, what="test")
        self.assertEqual(ctx.exception.code, ErrorCode.DUPLICATE_JSON_KEY)
        self.assertEqual(ctx.exception.evidence["duplicate_key"], "aud")

    def test_nested_duplicate_detected(self):
        raw = b'{"outer":{"k":1,"k":2}}'
        with self.assertRaises(TokenError) as ctx:
            json_decode_checked(raw, what="test")
        self.assertEqual(ctx.exception.code, ErrorCode.DUPLICATE_JSON_KEY)


class TestTokenStructure(unittest.TestCase):
    def setUp(self):
        self.key = b"0123456789abcdef0123456789abcdef"
        self.header = build_header("t-acme", "k1")
        self.payload = {
            "iss": "acme-idp", "sub": "u1", "act": [], "aud": "acme-gateway",
            "scp": ["a:read"], "exp": 1_700_003_600, "jti": "j1", "root": "j1",
        }
        self.token = encode_token(self.header, self.payload, self.key)

    def test_three_segments_and_canonical_header(self):
        self.assertEqual(len(self.token.split(".")), 3)
        header, payload, signing_input, sig = decode_token(self.token)
        self.assertEqual(header["alg"], ALGORITHM)
        self.assertEqual(header["typ"], TOKEN_TYPE)
        self.assertEqual(header["tenant"], "t-acme")
        self.assertEqual(payload["jti"], "j1")
        self.assertEqual(len(sig), 32)

    def test_signature_roundtrip(self):
        _, _, signing_input, sig = decode_token(self.token)
        verify_signature(signing_input, sig, self.key)
        with self.assertRaises(TokenError) as ctx:
            verify_signature(signing_input, sig, b"x" * 32)
        self.assertEqual(ctx.exception.code, ErrorCode.BAD_SIGNATURE)

    def test_wrong_segment_count(self):
        for bad in ("a.b", "a.b.c.d", "a..c", ""):
            with self.subTest(bad=bad):
                with self.assertRaises(TokenError) as ctx:
                    decode_token(bad)
                self.assertEqual(ctx.exception.code, ErrorCode.MALFORMED_TOKEN)

    def test_reject_remote_key_header(self):
        header = dict(self.header)
        header["jku"] = "https://keys.invalid/x"
        token = encode_token(header, self.payload, self.key)
        with self.assertRaises(TokenError) as ctx:
            decode_token(token)
        self.assertEqual(ctx.exception.code, ErrorCode.INVALID_HEADER)
        self.assertIn("jku", ctx.exception.evidence["forbidden_keys"])

    def test_reject_unknown_algorithm(self):
        header = dict(self.header)
        header["alg"] = "RS256"
        token = encode_token(header, self.payload, self.key)
        with self.assertRaises(TokenError) as ctx:
            decode_token(token)
        self.assertEqual(ctx.exception.code, ErrorCode.UNKNOWN_ALGORITHM)

    def test_reject_extra_header_key(self):
        header = dict(self.header)
        header["custom"] = "x"
        token = encode_token(header, self.payload, self.key)
        with self.assertRaises(TokenError) as ctx:
            decode_token(token)
        self.assertEqual(ctx.exception.code, ErrorCode.INVALID_HEADER)

    def test_reject_bad_payload_shapes(self):
        base = dict(self.payload)
        bad_variants = [
            {"scp": []},
            {"scp": ["b", "a"]},          # 未排序
            {"scp": ["a", "a"]},          # 重复
            {"exp": True},                # bool 伪装整数
            {"exp": -1},
            {"act": ["svc", 3]},
            {"sub": ""},
            {"aud": 123},
        ]
        for change in bad_variants:
            with self.subTest(change=change):
                payload = dict(base)
                payload.update(change)
                token = encode_token(self.header, payload, self.key)
                with self.assertRaises(TokenError) as ctx:
                    decode_token(token)
                self.assertEqual(ctx.exception.code, ErrorCode.INVALID_CLAIM)

    def test_reject_missing_and_extra_claims(self):
        payload = dict(self.payload)
        del payload["root"]
        token = encode_token(self.header, payload, self.key)
        with self.assertRaises(TokenError) as ctx:
            decode_token(token)
        self.assertEqual(ctx.exception.code, ErrorCode.INVALID_CLAIM)
        self.assertIn("root", ctx.exception.evidence["missing"])

        payload = dict(self.payload)
        payload["admin"] = True
        token = encode_token(self.header, payload, self.key)
        with self.assertRaises(TokenError) as ctx:
            decode_token(token)
        self.assertIn("admin", ctx.exception.evidence["extra_keys"])

    def test_signature_covers_all_claims(self):
        # 篡改 aud 后不重签：结构仍可解码，但签名验证必须失败，
        # 证明 HMAC 绑定全部声明，不能只验签而忽略受众。
        token = encode_token(self.header, self.payload, self.key)
        h, p, _ = token.split(".")
        tampered = dict(self.payload)
        tampered["aud"] = "evil"
        p2 = b64url_encode(canonical_dumps(tampered))
        header, payload, signing_input, sig = decode_token(f"{h}.{p2}.{_}")
        self.assertEqual(payload["aud"], "evil")
        with self.assertRaises(TokenError) as sig_ctx:
            verify_signature(signing_input, sig, self.key)
        self.assertEqual(sig_ctx.exception.code, ErrorCode.BAD_SIGNATURE)


if __name__ == "__main__":
    unittest.main()
