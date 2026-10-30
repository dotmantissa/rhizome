# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
from genlayer import *

class RuntimeProbe(gl.Contract):
    owner: Address
    counters: TreeMap[str, u64]
    history: DynArray[str]

    def __init__(self):
        self.owner = gl.message.sender_address
        self.counters["initialized"] = u64(1)
        self.history.append("initialized")

    @gl.public.view
    def identity(self) -> dict:
        return {"owner": str(self.owner), "datetime": gl.message_raw["datetime"], "chain_id": int(gl.message.chain_id), "initialized": int(self.counters["initialized"])}
