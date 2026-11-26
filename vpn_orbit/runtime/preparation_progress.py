"""The limited phase vocabulary shared by Broker, Worker and the queue."""

from ..errors import Denied
from .protocol import fields
from .vps_preparation import PHASES


PREPARATION_STEPS = (*PHASES, "access")
PREPARATION_STAGES = ("CHECKING", "DISPATCHING", "VERIFIED")


def preparation_position(value):
    fields(value, ("phase", "stage"))
    phase, stage = value["phase"], value["stage"]
    if (phase not in PREPARATION_STEPS or stage not in PREPARATION_STAGES
            or (phase == "access" and stage == "DISPATCHING")):
        raise Denied("VPS_PREPARATION_PROGRESS_INVALID")
    return PREPARATION_STEPS.index(phase), PREPARATION_STAGES.index(stage)
