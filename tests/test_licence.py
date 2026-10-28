# SPDX-License-Identifier: GPL-3.0-or-later
"""Vérifie la licence GPL-3.0-or-later du dépôt (issue #75)."""

import subprocess
import tomllib
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
SPDX = "SPDX-License-Identifier: GPL-3.0-or-later"
EXCLUS = ("docs/", ".github/", "src/oxo_hep_bridge.egg-info/")


def test_fichier_license_gplv3() -> None:
    texte = (RACINE / "LICENSE").read_text(encoding="utf-8")
    assert texte.lstrip().startswith("GNU GENERAL PUBLIC LICENSE")
    assert "Version 3, 29 June 2007" in texte


def test_pyproject_declare_gpl() -> None:
    with (RACINE / "pyproject.toml").open("rb") as fichier:
        projet = tomllib.load(fichier)["project"]
    assert projet["license"] == "GPL-3.0-or-later"


def test_entetes_spdx() -> None:
    fichiers = subprocess.run(
        ["git", "ls-files"], cwd=RACINE, capture_output=True, text=True, check=True
    ).stdout.split()
    manquants = []
    for nom in fichiers:
        if nom.startswith(EXCLUS) or not nom.endswith((".py", ".sh")):
            continue
        tete = (RACINE / nom).read_text(encoding="utf-8").splitlines()[:3]
        if not any(SPDX in ligne for ligne in tete):
            manquants.append(nom)
    assert manquants == []


def test_copyright_wireshark_conserve() -> None:
    texte = (RACINE / "src/oxo_hep_bridge/ua_opcode_names.py").read_text(encoding="utf-8")
    assert "Copyright 2012, Alcatel-Lucent Enterprise" in texte
    assert "Copyright 1998 Gerald Combs" in texte
