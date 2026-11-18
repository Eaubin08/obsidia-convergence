# OBSIDIA G1/G2 — tests en racine assemblee, aucun lancement de service.
# Le CHECK prealable bloque plutot que lancer 111 erreurs de packaging.
$ErrorActionPreference = "Stop"

$assembly = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$required = @(
    "sigma\registry.py",
    "sigma\domains\tooling_build_agents.py",
    "sigma\domains\meta_agents.py",
    "tests\cli\test_governed_content_apply_c2_v0.py",
    "scripts\obsidia_candidate_patch_v1.py",
    "scripts\obsidia_bounded_mission_v0.py",
    "scripts\obsidia_mission_authority_v0.py",
    "scripts\obsidia_mission_authority_integration_v0.py",
    "scripts\obsidia_family_wiring_apply_bridge_v0.py"
)

foreach ($rel in $required) {
    if (-not (Test-Path -LiteralPath (Join-Path $assembly $rel) -PathType Leaf)) {
        Write-Host "HOLD_MISSING_DEPENDENCY=$rel"
        throw "G1_G2_DEPENDENCIES_INCOMPLETE"
    }
}

if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    throw "PY_LAUNCHER_NOT_FOUND"
}

$previousPythonPath = $env:PYTHONPATH
$env:PYTHONPATH = if ($previousPythonPath) { "$assembly;$previousPythonPath" } else { "$assembly" }

try {
    Push-Location $assembly
    Write-Host "G1_G2_TEST_ROOT=$assembly"
    Write-Host "MODE=LOCAL_TESTS_ONLY__NO_SERVER__NO_PRODUCTION_APPLY"
    py -3 -m pytest -q -p no:cacheprovider tests/integration tests/cli sigma/tests tests/test_kx108_k1_ticket_decision_binding.py
    $testExit = $LASTEXITCODE
    Write-Host "G1_G2_TEST_EXIT=$testExit"
    if ($testExit -ne 0) {
        throw "G1_G2_FUNCTIONAL_REGRESSION_HOLD"
    }
    Write-Host "G1_G2_IMPORTED_TESTS_PASS=True"
}
finally {
    Pop-Location
    $env:PYTHONPATH = $previousPythonPath
}
