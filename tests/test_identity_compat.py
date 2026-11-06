from identity_compat import evaluate


def snapshot(boot="unknown", target="x86/64", profile="generic", arch="x86_64"):
    return {"system": {"boot_mode": boot, "target": target, "profile": profile, "package_architecture": arch}}


def test_confirmed_efi_accepts_combined_efi():
    result = evaluate(snapshot("efi"), target="x86/64", profile="generic", architecture="x86_64", image_type="combined-efi")
    assert result["status"] == "compatible"


def test_confirmed_bios_blocks_efi_image():
    result = evaluate(snapshot("bios"), target="x86/64", profile="generic", architecture="x86_64", image_type="combined-efi")
    assert result["status"] == "incompatible"


def test_unknown_boot_never_infers_efi_from_x86_64():
    result = evaluate(snapshot("unknown"), target="x86/64", profile="generic", architecture="x86_64", image_type="combined-efi")
    assert result["status"] == "unknown"
    assert any("cannot be selected automatically" in item for item in result["unknown"])


def test_architecture_mismatch_is_incompatible():
    result = evaluate(snapshot("efi", arch="aarch64_cortex-a53"), target="x86/64", profile="generic", architecture="x86_64", image_type="combined-efi")
    assert result["status"] == "incompatible"

