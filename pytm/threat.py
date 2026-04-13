"""Threat model - represents possible threats in the system."""

from __future__ import annotations

import ast
import sys
from types import CodeType
from typing import Any, ClassVar, Tuple, Union, List
from collections.abc import Iterable

import builtins

from pydantic import (
    BaseModel,
    Field,
    ConfigDict,
    field_validator,
    model_validator,
    PrivateAttr,
)

from .enums import Classification, TLSVersion


class _ConditionValidator(ast.NodeVisitor):
    """Validate threat conditions to ensure they only use safe constructs."""

    SAFE_CALL_NAMES: ClassVar[set[str]] = {"any", "all", "len", "min", "max", "sum"}
    ALLOWED_TARGET_METHODS: ClassVar[set[str]] = {
        "oneOf",
        "crosses",
        "enters",
        "exits",
        "inside",
        "checkTLSVersion",
        "hasDataLeaks",
    }
    _ALLOWED_NODES: ClassVar[tuple[type[ast.AST], ...]] = (
        ast.Expression,
        ast.BoolOp,
        ast.BinOp,
        ast.UnaryOp,
        ast.Compare,
        ast.Name,
        ast.Load,
        ast.Constant,
        ast.Attribute,
        ast.Call,
        ast.Subscript,
        ast.List,
        ast.Tuple,
        ast.Set,
        ast.Dict,
        ast.ListComp,
        ast.GeneratorExp,
        ast.comprehension,
        ast.IfExp,
        ast.And,
        ast.Or,
        ast.Not,
        ast.Eq,
        ast.NotEq,
        ast.Lt,
        ast.LtE,
        ast.Gt,
        ast.GtE,
        ast.Is,
        ast.IsNot,
        ast.In,
        ast.NotIn,
        ast.Add,
        ast.Sub,
        ast.Mult,
        ast.Div,
        ast.Mod,
        ast.Pow,
        ast.USub,
        ast.UAdd,
        ast.BitAnd,
        ast.BitOr,
        ast.BitXor,
        ast.FloorDiv,
        ast.Slice,
    )

    def __init__(self, allowed_names: set[str]) -> None:
        super().__init__()
        self.allowed_names = allowed_names | {"target", "True", "False", "None"}

    def visit(self, node: ast.AST) -> Any:  # type: ignore[override]
        if not isinstance(node, self._ALLOWED_NODES):
            raise ValueError(
                f"Unsupported syntax in threat condition: {type(node).__name__}"
            )
        return super().visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> Any:  # noqa: D401
        if isinstance(node.attr, str) and node.attr.startswith("__"):
            raise ValueError(
                "Access to dunder attributes is not permitted in threat conditions"
            )
        return self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:  # noqa: D401
        if node.keywords:
            raise ValueError("Keyword arguments are not permitted in threat conditions")

        func = node.func
        if isinstance(func, ast.Name):
            if func.id not in self.SAFE_CALL_NAMES:
                raise ValueError(
                    f"Call to '{func.id}' is not permitted in threat conditions"
                )
        elif isinstance(func, ast.Attribute):
            chain = self._attribute_chain(func)
            if chain[-1] not in self.ALLOWED_TARGET_METHODS:
                raise ValueError(
                    f"Call to target method '{chain[-1]}' is not permitted"
                )
        else:
            raise ValueError("Unsupported call target in threat condition")

        return self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> Any:  # noqa: D401
        if (
            isinstance(node.ctx, ast.Load)
            and node.id not in self.allowed_names
            and node.id not in self.SAFE_CALL_NAMES
        ):
            # Allow names introduced by comprehensions; they will fail at runtime if undefined.
            return
        return None

    @staticmethod
    def _attribute_chain(node: ast.Attribute) -> List[str]:
        chain: List[str] = [node.attr]
        current = node.value
        while isinstance(current, ast.Attribute):
            if isinstance(current.attr, str) and current.attr.startswith("__"):
                raise ValueError(
                    "Access to dunder attributes is not permitted in threat conditions"
                )
            chain.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            chain.append(current.id)
        else:
            raise ValueError(
                "Only attribute access on names is permitted in threat conditions"
            )
        chain.reverse()
        return chain


class Threat(BaseModel):
    """Represents a possible threat.

    Attributes:
        id (str): Threat identifier (SID)
        description (str): Description of the threat
        condition (str): A Python expression that should evaluate to a boolean True or False
        details (str): Detailed information about the threat
        likelihood (str): Likelihood of the threat occurring
        severity (str): Severity level of the threat
        mitigations (str): Possible mitigations for the threat
        prerequisites (str): Prerequisites for the threat
        example (str): Example of the threat
        references (str): References for the threat
        target (Tuple): Target classes for this threat
    """

    model_config = ConfigDict(
        extra="allow", validate_assignment=True, arbitrary_types_allowed=True
    )

    id: str = Field(description="Threat identifier (SID)")
    description: str = Field(default="", description="Description of the threat")
    condition: str = Field(
        default="True",
        description="A Python expression that should evaluate to a boolean True or False",
    )
    details: str = Field(
        default="", description="Detailed information about the threat"
    )
    likelihood: str = Field(
        default="", description="Likelihood of the threat occurring"
    )
    severity: str = Field(default="", description="Severity level of the threat")
    mitigations: str = Field(
        default="", description="Possible mitigations for the threat"
    )
    prerequisites: str = Field(default="", description="Prerequisites for the threat")
    example: str = Field(default="", description="Example of the threat")
    references: str = Field(default="", description="References for the threat")
    target: Tuple = Field(default=(), description="Target classes for this threat")

    _compiled_condition: CodeType | None = PrivateAttr(default=None)
    _eval_globals: ClassVar[dict[str, Any] | None] = None
    _SAFE_BUILTINS: ClassVar[dict[str, Any]] = {
        name: getattr(builtins, name) for name in _ConditionValidator.SAFE_CALL_NAMES
    }

    @model_validator(mode="before")
    @classmethod
    def _normalize_input(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data

        # Map legacy field names from the threats.json format
        if "SID" in data:
            data.setdefault("id", data.pop("SID"))
        if "Likelihood Of Attack" in data:
            data.setdefault("likelihood", data.pop("Likelihood Of Attack"))

        # Normalise target to a tuple
        target = data.get("target", "Element")
        if isinstance(target, str) or not isinstance(target, Iterable):
            target = (target,)
        else:
            target = tuple(target)

        # Resolve target name strings to actual Python classes
        resolved = []
        for name in target:
            if isinstance(name, type):
                resolved.append(name)
            else:
                klass = getattr(sys.modules.get("pytm"), name, None)
                resolved.append(klass if klass is not None else name)
        data["target"] = tuple(resolved)

        return data

    def model_post_init(self, __context: Any) -> None:  # noqa: D401
        if not self.condition:
            self._compiled_condition = None
            return

        try:
            tree = ast.parse(self.condition, mode="eval")
            validator = _ConditionValidator(self._allowed_global_names())
            validator.visit(tree)
            self._compiled_condition = compile(
                tree, filename=f"<Threat {self.id}>", mode="eval"
            )
        except ValueError as exc:  # pragma: no cover - defensive, surfaced via tests
            raise ValueError(f"Invalid condition for threat {self.id}: {exc}") from exc
        except SyntaxError as exc:  # noqa: D401
            raise ValueError(
                f"Invalid syntax in condition for threat {self.id}: {exc}"
            ) from exc

    def _safeset(self, attr: str, value) -> None:
        """Safely set an attribute value."""
        try:
            setattr(self, attr, value)
        except (ValueError, TypeError):
            pass

    def __repr__(self):
        return (
            f"<{self.__module__}.{type(self).__name__}({self.id}) at {hex(id(self))}>"
        )

    def __str__(self):
        return f"{type(self).__name__}({self.id})"

    @classmethod
    def _build_eval_globals(cls) -> dict[str, Any]:
        if cls._eval_globals is None:
            import pytm

            globals_dict: dict[str, Any] = {
                "__builtins__": cls._SAFE_BUILTINS,
                "Actor": pytm.Actor,
                "Asset": pytm.Asset,
                "Boundary": pytm.Boundary,
                "Dataflow": pytm.Dataflow,
                "Datastore": pytm.Datastore,
                "DatastoreType": pytm.DatastoreType,
                "Element": pytm.Element,
                "ExternalEntity": pytm.ExternalEntity,
                "Lambda": pytm.Lambda,
                "Process": pytm.Process,
                "Server": pytm.Server,
                "SetOfProcesses": pytm.SetOfProcesses,
                "TM": pytm.TM,
                "TLSVersion": pytm.TLSVersion,
                "Classification": pytm.Classification,
                "Action": pytm.Action,
                "Lifetime": pytm.Lifetime,
            }

            # Expose safe builtins as globals as well for convenience
            globals_dict.update(cls._SAFE_BUILTINS)
            cls._eval_globals = globals_dict

        return cls._eval_globals

    @classmethod
    def _allowed_global_names(cls) -> set[str]:
        globals_dict = cls._build_eval_globals()
        return {key for key in globals_dict.keys() if key != "__builtins__"}

    def apply(self, target):
        """Apply the threat condition to a target."""
        # Check if target matches any of the target types
        if self.target:
            target_matches = False
            for target_type in self.target:
                if isinstance(target_type, str):
                    # String comparison for backward compatibility
                    if target_type == type(target).__name__:
                        target_matches = True
                        break
                elif isinstance(target_type, type):
                    # Class type comparison
                    if isinstance(target, target_type):
                        target_matches = True
                        break

            if not target_matches:
                return False

        if self._compiled_condition is None:
            return False

        try:
            globals_dict = dict(self._build_eval_globals())
            locals_dict = {"target": target}
            return bool(eval(self._compiled_condition, globals_dict, locals_dict))
        except Exception:
            return False
