def test_p1_c301_toctou_guard():
    import hashlib
    import inspect
    import pathlib
    import sys
    import tempfile
    
    root = pathlib.Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(root / "scripts"))
    sys.path.insert(0, str(root))
    
    import obsidia_governed_apply_v0 as G
    
    writer = G._C.atomic_replace_with_bytes
    
    print("=== P1-C301 — WRITER CONTRACT ===")
    print("FUNCTION=" + writer.__name__)
    print("SIGNATURE=" + str(inspect.signature(writer)))
    
    failures = []
    
    with tempfile.TemporaryDirectory(prefix="P1_C301_TOCTOU_") as tmp:
        target = pathlib.Path(tmp) / "synthetic_target.txt"
    
        original = b"ORIGINAL_SYNTHETIC_CONTENT"
        altered = b"CONCURRENT_SYNTHETIC_CHANGE"
        replacement = b"UNAUTHORIZED_SYNTHETIC_REPLACEMENT"
    
        target.write_bytes(original)
        expected_pre = hashlib.sha256(original).hexdigest()
    
        # Simule une modification après validation de la pré-image.
        target.write_bytes(altered)
    
        before = target.read_bytes()
    
        try:
            result = writer(target, replacement, expected_pre)
            error = None
        except Exception as exc:
            result = None
            error = type(exc).__name__
    
        after = target.read_bytes()
    
        print("\n=== P1-C301 — ADVERSARIAL CASE ===")
        print("CASE=TARGET_CHANGED_AFTER_PRECHECK")
        print("WRITER_RESULT=" + repr(result))
        print("WRITER_EXCEPTION=" + repr(error))
        print("DRIFTED_CONTENT_PRESERVED=" + str(after == before))
        print("UNAUTHORIZED_REPLACEMENT_APPLIED=" + str(after == replacement))
    
        if not isinstance(result, dict) or result.get("status") != "TARGET_PRECONDITION_MISMATCH":
            failures.append("EXPECTED_PRECONDITION_REJECTION_MISSING")
    
        if after != before:
            failures.append("WRITER_MODIFIED_DRIFTED_TARGET")
    
    print("\n=== P1-C301 — VERDICT ===")
    print("FAILURES=" + repr(failures))
    print("TARGET=TEMPORARY_SYNTHETIC_ONLY")
    print("FULL_GOVERNED_RUNTIME_TOCTOU=NOT_YET_TESTED")
    print("PRODUCTION_TARGET_MUTATION=False")
    print("KX108_AUTHORITY=UNCHANGED")
    print("RELEASE=HOLD")
    
    if failures:
        print("P1_C301_TOCTOU=HOLD")
        raise SystemExit(1)
    
    print("P1_C301_TOCTOU=PASS")
