from typing import List, Optional
from uuid import UUID
from enum import Enum
from pydantic import BaseModel, Field, root_validator


class PhysicalNodeType(str, Enum):
    PROCESS_CELL = "ProcessCell"
    UNIT = "Unit"
    EQUIPMENT_MODULE = "EquipmentModule"
    CONTROL_MODULE = "ControlModule"


class PhysicalNode(BaseModel):
    id: UUID = Field(..., description="A unique identifier for this node (UUID recommended).")
    name: str = Field(..., min_length=1, description="A human-readable name for the node.")
    type: PhysicalNodeType = Field(..., description="The ISA-88 type of this node.")
    binding: Optional[str] = Field(
        None, description="The firmware tag or I/O address this node is bound to. ONLY valid for 'ControlModule' type."
    )
    children: Optional[List["PhysicalNode"]] = Field(None, description="An array of child nodes nested under this node.")

    @root_validator(pre=False)
    def validate_node_constraints(cls, values):
        node_type = values.get("type")
        binding = values.get("binding")
        children = values.get("children")

        if node_type == PhysicalNodeType.CONTROL_MODULE:
            if binding is None:
                raise ValueError("ControlModule type must have a 'binding'.")
            if children is not None:
                raise ValueError("ControlModule type must not have 'children'.")
        elif binding is not None:
            # For ProcessCell, Unit, EquipmentModule, binding must not exist
            raise ValueError(f"{node_type.value} type must not have a 'binding'.")
        return values


# Forward reference for recursive model
PhysicalNode.update_forward_refs()
