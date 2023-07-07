from .proto import dml

MSG_CHARACTERSELECTED = dml.Layout(
    (
        ("IP", dml.Type.STR),
        ("TCPPort", dml.Type.INT),
        ("UDPPort", dml.Type.INT),
        ("Key", dml.Type.STR),
        ("UserID", dml.Type.GID),
        ("CharID", dml.Type.GID),
        ("ZoneID", dml.Type.GID),
        ("ZoneName", dml.Type.STR),
        ("Location", dml.Type.STR),
        ("Slot", dml.Type.INT),
        ("PrepPhase", dml.Type.INT),
        ("Error", dml.Type.INT),
        ("LoginServer", dml.Type.STR),
    )
)

MSG_SERVERTRANSFER = dml.Layout(
    (
        ("IP", dml.Type.STR),
        ("TCPPort", dml.Type.INT),
        ("UDPPort", dml.Type.INT),
        ("Key", dml.Type.INT),
        ("UserID", dml.Type.GID),
        ("CharID", dml.Type.GID),
        ("ZoneName", dml.Type.STR),
        ("ZoneID", dml.Type.GID),
        ("Location", dml.Type.STR),
        ("Slot", dml.Type.INT),
        ("SessionID", dml.Type.GID),
        ("SessionSlot", dml.Type.INT),
        ("TargetPlayerID", dml.Type.GID),
        ("FallbackIP", dml.Type.STR),
        ("FallbackTCPPort", dml.Type.INT),
        ("FallbackUDPPort", dml.Type.INT),
        ("FallbackKey", dml.Type.INT),
        ("FallbackZone", dml.Type.STR),
        ("FallbackZoneID", dml.Type.GID),
        ("TransitionID", dml.Type.INT),
    )
)
