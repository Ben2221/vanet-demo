"""IEEE 802.11p radio parameters and the link-budget maths shared by both
backends (ns-3 and the built-in lite simulator).
"""

from __future__ import annotations

import math
from dataclasses import dataclass

C = 299_792_458.0

# 802.11p at 10 MHz: every OFDM timing is doubled compared to 20 MHz 802.11a
SLOT_S = 13e-6
SIFS_S = 32e-6
PREAMBLE_S = 40e-6          # 32 us preamble + 8 us SIGNAL
SYMBOL_S = 8e-6
# bytes added below the application payload: UDP 8 + IPv4 20 + LLC/SNAP 8
# + QoS MAC header 26 + FCS 4
L2_L4_OVERHEAD = 66
ACK_BYTES = 14

# EDCA access categories at 10 MHz (AIFSN, CWmin, CWmax) as in IEEE 802.11-2016
EDCA = {
    "AC_VO": (2, 3, 7),
    "AC_VI": (2, 7, 15),
    "AC_BE": (3, 15, 1023),
    "AC_BK": (7, 15, 1023),
}

# ns-3 mode name for each 10 MHz data rate
NS3_MODES = {
    3: "OfdmRate3MbpsBW10MHz", 4.5: "OfdmRate4_5MbpsBW10MHz", 6: "OfdmRate6MbpsBW10MHz",
    9: "OfdmRate9MbpsBW10MHz", 12: "OfdmRate12MbpsBW10MHz", 18: "OfdmRate18MbpsBW10MHz",
    24: "OfdmRate24MbpsBW10MHz", 27: "OfdmRate27MbpsBW10MHz",
}

# minimum SINR (dB) for a ~200 byte frame to decode with PER < 10 %, per data rate
SINR_MIN_DB = {3: 2.0, 4.5: 4.0, 6: 5.0, 9: 7.0, 12: 10.0, 18: 13.0, 24: 17.0, 27: 19.0}


@dataclass
class RadioConfig:
    frequency_hz: float = 5.9e9
    channel_width_mhz: int = 10
    data_rate_mbps: float = 6
    tx_power_dbm: float = 20.0
    rx_sensitivity_dbm: float = -85.0
    target_range_m: float = 400.0      # sets the path-loss exponent
    noise_figure_db: float = 7.0
    fading: str = "none"               # "none" or "nakagami"
    nakagami_m: float = 1.5            # m for the Nakagami fading option

    @property
    def wavelength(self) -> float:
        return C / self.frequency_hz

    @property
    def reference_loss_db(self) -> float:
        """Free-space loss at 1 m."""
        return 20 * math.log10(4 * math.pi / self.wavelength)

    @property
    def path_loss_exponent(self) -> float:
        """Exponent that puts the receive threshold exactly at target_range_m."""
        budget = self.tx_power_dbm - self.rx_sensitivity_dbm - self.reference_loss_db
        return budget / (10 * math.log10(self.target_range_m))

    @property
    def noise_dbm(self) -> float:
        return -174 + 10 * math.log10(self.channel_width_mhz * 1e6) + self.noise_figure_db

    @property
    def sinr_min_db(self) -> float:
        return SINR_MIN_DB.get(self.data_rate_mbps, 5.0)

    @property
    def ns3_mode(self) -> str:
        if self.data_rate_mbps not in NS3_MODES:
            raise ValueError(f"unsupported 802.11p rate {self.data_rate_mbps} Mb/s; choose from {sorted(NS3_MODES)}")
        return NS3_MODES[self.data_rate_mbps]

    def rx_power_dbm(self, distance_m: float) -> float:
        d = max(distance_m, 1.0)
        return self.tx_power_dbm - self.reference_loss_db - 10 * self.path_loss_exponent * math.log10(d)

    def airtime(self, app_bytes: int) -> float:
        """On-air duration of one frame carrying app_bytes of UDP payload."""
        bits = 16 + 8 * (app_bytes + L2_L4_OVERHEAD) + 6
        bits_per_symbol = self.data_rate_mbps * 1e6 * SYMBOL_S
        return PREAMBLE_S + SYMBOL_S * math.ceil(bits / bits_per_symbol)

    def ack_airtime(self) -> float:
        bits = 16 + 8 * ACK_BYTES + 6
        return PREAMBLE_S + SYMBOL_S * math.ceil(bits / (self.data_rate_mbps * 1e6 * SYMBOL_S))

    def as_table(self) -> dict:
        return {
            "standard": "IEEE 802.11p (WIFI_STANDARD_80211p)",
            "frequency_GHz": self.frequency_hz / 1e9,
            "channel_width_MHz": self.channel_width_mhz,
            "data_rate_Mbps": self.data_rate_mbps,
            "tx_power_dBm": self.tx_power_dbm,
            "rx_sensitivity_dBm": self.rx_sensitivity_dbm,
            "path_loss": "log-distance",
            "reference_loss_dB@1m": round(self.reference_loss_db, 2),
            "path_loss_exponent": round(self.path_loss_exponent, 3),
            "nominal_range_m": self.target_range_m,
            "fading": self.fading if self.fading == "none" else f"nakagami m={self.nakagami_m}",
            "noise_floor_dBm": round(self.noise_dbm, 1),
        }
