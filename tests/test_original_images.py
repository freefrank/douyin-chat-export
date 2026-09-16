import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from backend import original_images


def test_resource_candidates_only_use_origin_urls():
    payload = {
        "resource_url": {
            "skey": "aa" * 32,
            "origin_url_list": ["https://origin.example/image"],
            "large_url_list": ["https://large.example/image"],
            "medium_url_list": ["https://medium.example/image"],
            "thumb_url_list": ["https://thumb.example/image"],
        }
    }
    resources = original_images._resource_candidates(payload)
    assert len(resources) == 1
    assert resources[0]["urls"] == ["https://origin.example/image"]


def test_decode_resource_accepts_plain_original_png():
    plain = b"\x89PNG\r\n\x1a\n" + b"payload"
    decoded, kind, ext = original_images._decode_resource(plain, "")
    assert decoded == plain
    assert kind == "image"
    assert ext == ".png"


def test_decode_resource_decrypts_aes_gcm_original():
    key = bytes(range(32))
    iv = bytes(range(12))
    plain = b"\xff\xd8\xff" + b"original-jpeg-payload"
    cipher = iv + AESGCM(key).encrypt(iv, plain, None)

    decoded, kind, ext = original_images._decode_resource(cipher, key.hex())
    assert decoded == plain
    assert kind == "image"
    assert ext == ".jpg"


def test_panel_injection_contains_original_image_controls():
    html = original_images.enhanced_panel_html()
    assert 'id="originalImageRecoverySection"' in html
    assert 'id="originalImageRecoverBtn"' in html
    assert "/panel/api/media/originals/recover" in html
    assert html.count('id="originalImageRecoverySection"') == 1
