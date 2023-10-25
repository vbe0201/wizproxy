from wizproxy.proto import Frame, SocketAddress, dml

from . import Context, Direction, Plugin, listen

MSG_CHARACTERSELECTED = dml.Layout(
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

MSG_SERVERTRANSFER = dml.Layout(
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

MSG_CONNECTIONSTATS = dml.Layout(
    ("ServerHostname", dml.Type.STR),
    ("ServerPort", dml.Type.INT),
    ("ConnectMS", dml.Type.INT),
    ("Timeouts", dml.Type.INT),
    ("Errors", dml.Type.INT),
)


class Builtin(Plugin):
    """
    Core functionality of the proxy, modeled as a built-in plugin.

    This does the crypto handshake for successful proxying and handles
    redirects of the client to other shards.
    """

    @listen(Direction.SERVER_TO_CLIENT, opcode=0)
    async def patch_session_offer(self, ctx: Context, frame: Frame):
        ctx.session.session_offer(frame)

    @listen(Direction.CLIENT_TO_SERVER, opcode=5)
    async def patch_session_accept(self, ctx: Context, frame: Frame):
        ctx.session.session_accept(frame)

    @listen(Direction.SERVER_TO_CLIENT, service_id=7, order=3)
    async def redirect_character_selected(self, ctx: Context, frame: Frame):
        msg = MSG_CHARACTERSELECTED.decode(frame.payload)

        # Extract the server that should be proxied and check validity.
        socket = SocketAddress(msg["IP"], msg["TCPPort"])
        if not socket.ip and not socket.port:
            return

        # Spawn a shard to proxy the new server connection.
        shard = await ctx.spawn_shard(socket)

        # Fix up the client packet to make it connect to the shard.
        msg["IP"] = shard.ip
        msg["TCPPort"] = shard.port

        frame.payload = MSG_CHARACTERSELECTED.encode(msg)

    @listen(Direction.SERVER_TO_CLIENT, service_id=5, order=221)
    async def redirect_server_transfer(self, ctx: Context, frame: Frame):
        msg = MSG_SERVERTRANSFER.decode(frame.payload)

        # Spawn a new shard to proxy the server connection.
        addr = SocketAddress(msg["IP"], msg["TCPPort"])
        shard = await ctx.spawn_shard(addr)
        fallback = ctx.shard_addr

        # Fix up the client packet to make it connect to the shard.
        # Use the current shard's socket as the fallback just in case.
        msg["IP"] = shard.ip
        msg["TCPPort"] = shard.port
        msg["FallbackIP"] = fallback.ip
        msg["FallbackTCPPort"] = fallback.port

        frame.payload = MSG_SERVERTRANSFER.encode(msg)

    @listen(Direction.CLIENT_TO_SERVER, service_id=53, order=67)
    async def patch_connection_stats(self, ctx: Context, frame: Frame):
        msg = MSG_CONNECTIONSTATS.decode(frame.payload)

        # Client reports the host it is connected to to the server every now and then.
        # We need to spoof the address here or the server sees that we're proxying.
        remote = ctx.remote_addr
        msg["ServerHostname"] = remote.ip
        msg["ServerPort"] = remote.port

        frame.payload = MSG_CONNECTIONSTATS.encode(msg)
