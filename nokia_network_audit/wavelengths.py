from __future__ import annotations

from .models import OpticalChannel, frequency_to_wavelength_nm


# Confirmed against a live PSS-8: ``show interface sfdc8b *`` on a card in slot
# 1/10 lists exactly these eight channels, as AIDs 1/10/9290 through 1/10/9360
# labelled ITU#29..ITU#36. Note this plan is specific to the *B* variant --
# SFDC8A/C/D/E cover different bands (the EPT guide references channel 9370 on
# an SFDC8C), so it must not be reused for them.
#
# This table is only a fallback for a transcript that captured the card but not
# its interface listing; when the listing is present the parser takes the
# channels the card itself reports.
SFDC8B_FREQUENCIES_THZ = (
    192.90,
    193.00,
    193.10,
    193.20,
    193.30,
    193.40,
    193.50,
    193.60,
)


def sfdc8b_channels(slot: str) -> dict[str, OpticalChannel]:
    channels: dict[str, OpticalChannel] = {}
    for port_number, frequency in enumerate(SFDC8B_FREQUENCIES_THZ, start=1):
        # Nokia represents 193.30 THz as the channel port label ``9330``.
        port_label = int(round((frequency - 100.0) * 100))
        channel_id = f"{slot}/{port_label:04d}"
        channels[channel_id] = OpticalChannel(
            channel_id=channel_id,
            port_number=port_number,
            frequency_thz=frequency,
            wavelength_nm=frequency_to_wavelength_nm(frequency),
        )
    return channels
