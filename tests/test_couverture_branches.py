# SPDX-License-Identifier: GPL-3.0-or-later
"""Branches restantes du seuil de couverture à 95 % (issue #62).

Chaque test exerce un chemin réel du code qui n'était parcouru par aucun
autre test (mesure du 21/10/2026 dans l'issue) ; aucun `pragma: no cover`.
"""

from __future__ import annotations

import runpy
import sys

import pytest

from oxo_hep_bridge.bridge import Bridge
from oxo_hep_bridge.config import Config
from oxo_hep_bridge.sdnotify import SdNotifier, WatchdogScheduler
from oxo_hep_bridge.semantics import extract_uaudp_fields
from oxo_hep_bridge.sender import _send_with_retry
from oxo_hep_bridge.tshark_source import TsharkEKSource


def test_iter_normalized_ignore_les_paquets_non_normalisables(fake_popen):
    """bridge.iter_normalized : un paquet que le normaliseur rejette (None)
    n'est pas émis, l'itération continue."""
    config = Config()
    config.capture.pcap = "tests/fixtures/ua3g_freeseating_ipv4.pcap"
    config.dry_run = True
    bridge = Bridge(config)
    bridge.normalize_packet = lambda flat: None  # type: ignore[method-assign]
    assert list(bridge.iter_normalized()) == []


def test_extract_uaudp_fields_ignore_les_champs_non_scalaires():
    """semantics.extract_uaudp_fields : un champ uaudp hors de la liste des
    scalaires est écarté, les autres sont conservés."""
    flat = {
        "uaudp_uaudp_opcode": 7,
        "uaudp_uaudp_champ_inconnu": "x",
        "ip_ip_src": "10.0.0.1",
    }
    assert extract_uaudp_fields(flat) == {"opcode": 7}


def test_build_cmd_sans_pcap_ni_interface():
    """tshark_source._build_cmd : si ni pcap ni interface ne sont renseignés
    (attributs vidés après construction), aucune option -r/-i n'est ajoutée."""
    source = TsharkEKSource(pcap="capture.pcap")
    source.pcap = None
    source.interface = None
    cmd = source._build_cmd()
    assert "-r" not in cmd
    assert "-i" not in cmd


class _NotifierRefusant(SdNotifier):
    """Notifier actif dont chaque ping watchdog échoue (retour False)."""

    def __init__(self) -> None:
        super().__init__(socket_path="unused")
        self.appels = 0

    @property
    def enabled(self) -> bool:
        return True

    def watchdog(self) -> bool:
        self.appels += 1
        return False


def test_watchdog_refuse_ne_compte_pas_d_envoi():
    """sdnotify.WatchdogScheduler._run : un ping refusé n'incrémente pas
    sent_count, la boucle continue."""
    notifier = _NotifierRefusant()
    scheduler = WatchdogScheduler(notifier, 0.02)
    scheduler.start()
    try:
        deadline = 200
        while notifier.appels < 2 and deadline:
            scheduler._stop_event.wait(0.01)
            deadline -= 1
    finally:
        scheduler.stop()
    assert notifier.appels >= 2
    assert scheduler.sent_count == 0


def test_send_with_retry_echec_final_sort_par_la_fin_de_boucle():
    """sender._send_with_retry : après la dernière tentative en échec, la
    fonction retourne (False, tentatives supplémentaires consommées)."""
    fermetures = []

    def send_once() -> None:
        raise OSError("refusé")

    ok, used = _send_with_retry(
        send_once=send_once,
        close=lambda: fermetures.append(1),
        host="127.0.0.1",
        port=9060,
        retries=1,
        retry_backoff=0.01,
        sleep=lambda _delay: None,
    )
    assert (ok, used) == (False, 1)
    assert len(fermetures) == 2


@pytest.mark.filterwarnings("ignore::RuntimeWarning")
def test_cli_executable_comme_module(monkeypatch, capsys):
    """cli : `python -m oxo_hep_bridge.cli --help` passe par le bloc
    `if __name__ == "__main__"` et sort avec le code 0."""
    monkeypatch.setattr(sys, "argv", ["oxo-hep-bridge", "--help"])
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("oxo_hep_bridge.cli", run_name="__main__")
    assert exc.value.code == 0
    assert "usage" in capsys.readouterr().out.lower()
