from typing import List, Optional, Union, Dict, Any
from uuid import UUID
from enum import Enum
from pydantic import BaseModel, Field


class LogicOperator(str, Enum):
    AND = "AND"
    OR = "OR"


class ComparisonOperator(str, Enum):
    EQ = "=="
    NE = "!="
    GT = ">"
    GE = ">="
    LT = "<"
    LE = "<="


class PhaseState(str, Enum):
    IDLE = "IDLE"
    RUNNING = "RUNNING"
    COMPLETE = "COMPLETE"
    HELD = "HELD"
    STOPPED = "STOPPED"
    ABORTED = "ABORTED"


class TagCondition(BaseModel):
    tag: str = Field(
        ..., description="The unique system tag of the process variable to check (e.g., 'BR101.TEMP.PV')."
    )
    op: ComparisonOperator = Field(..., description="The comparison operator.")
    value: Union[str, float, bool] = Field(..., description="The value to compare the tag against.")

    class Config:
        extra = "forbid"  # Ensures no additional properties


class DelayCondition(BaseModel):
    type: str = Field("delay", const=True, description="Indicates this is a delay condition.")
    value: str = Field(
        ..., pattern=r"^(\d+)(s|m|h)$", description="The duration of the delay (e.g., '30s', '15m', '1h')."
    )

    class Config:
        extra = "forbid"


class PhaseStateCondition(BaseModel):
    type: str = Field("phase_state", const=True, description="Indicates this is a phase state condition.")
    phase_id: str = Field(..., description="The 'id' of the step whose phase state to check.")
    state: PhaseState = Field(..., description="The ISA-88 state to check for.")

    class Config:
        extra = "forbid"


# Union type for condition items
ConditionItem = Union[TagCondition, DelayCondition, PhaseStateCondition]


class TransitionCondition(BaseModel):
    logic: LogicOperator = Field(..., description="The logical operator to apply to the array of conditions.")
    conditions: List[ConditionItem] = Field(
        ..., description="An array of individual conditions that make up the transition logic."
    )


class StepDefinition(BaseModel):
    id: str = Field(..., description="A unique identifier for this step within the recipe.")
    phase: str = Field(..., description="The name of the Equipment Phase to execute for this step.")
    parameters: Dict[str, Any] = Field(
        {}, description="An object of key-value pairs representing the parameters to pass to the phase."
    )
    transitionTo: Union[str, List[str]] = Field(
        ..., description="The 'id' of the next step to transition to. Can be an array of ids for parallel branches."
    )
    transitionCondition: TransitionCondition = Field(
        ..., description="The logical condition that must be met to complete this step and move to the next."
    )


class RecipeModel(BaseModel):
    id: UUID = Field(..., description="A unique identifier for this recipe (UUID recommended).")
    name: str = Field(..., min_length=1, description="A human-readable name for the recipe.")
    version: str = Field(
        ...,
        pattern=r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$",
        description="The version of this recipe, following semantic versioning (e.g., '1.0.0').",
    )
    startStep: str = Field(..., description="The 'id' of the first step to be executed when the recipe starts.")
    steps: List[StepDefinition] = Field(
        ..., min_items=1, description="An array of all steps that make up the recipe procedure."
    )
