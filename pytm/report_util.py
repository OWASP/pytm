"""Utilities used by report templates."""

from __future__ import annotations

from typing import Any, List


class ReportUtils:
    """Helper methods exposed to Jinja-style templates via :class:`SuperFormatter`."""

    @staticmethod
    def getParentName(element: Any) -> str:
        """Return the parent boundary name for *element* or an empty string."""
        from pytm import Boundary  # Local import to avoid circular dependency

        if not isinstance(element, Boundary):
            return (
                f"ERROR: getParentName method is not valid for {type(element).__name__}"
            )

        parent = element.inBoundary
        return parent.name if parent is not None else ""

    @staticmethod
    def getNamesOfParents(element: Any) -> List[str] | str:
        """Return a list of parent boundary names for *element*."""
        from pytm import Boundary

        if not isinstance(element, Boundary):
            return f"ERROR: getNamesOfParents method is not valid for {type(element).__name__}"

        return [parent.name for parent in element.parents()]

    @staticmethod
    def getInScopeFindings(element: Any) -> list:
        """Return only findings that belong to an in-scope element and target an in-scope element."""
        from pytm import Element

        if not isinstance(element, Element):
            return []

        if not element.inScope:
            return []

        in_scope_findings = []
        for finding in element.findings:
            target = getattr(finding, "element", None)
            if target is not None and getattr(target, "inScope", False):
                in_scope_findings.append(finding)

        return in_scope_findings

    @staticmethod
    def getFindingCount(element: Any) -> str:
        """Return the count of findings for *element* as a string."""
        from pytm import Element

        if not isinstance(element, Element):
            return f"ERROR: getFindingCount method is not valid for {type(element).__name__}"

        return str(len(list(element.findings)))

    @staticmethod
    def getElementType(element: Any) -> str:
        """Return the class name for *element*."""
        from pytm import Element

        if not isinstance(element, Element):
            return f"ERROR: getElementType method is not valid for {type(element).__name__}"

        return element.__class__.__name__

    @staticmethod
    def getThreatId(obj: Any) -> str:
        from pytm import Finding

        if isinstance(obj, Finding):
            return obj.threat_id
        return ""

    @staticmethod
    def getFindingDescription(obj: Any) -> str:
        from pytm import Finding

        if isinstance(obj, Finding):
            return obj.description
        return ""

    @staticmethod
    def getFindingTarget(obj: Any) -> Any:
        from pytm import Finding

        if isinstance(obj, Finding):
            return obj.target
        return ""

    @staticmethod
    def getFindingSeverity(obj: Any) -> str:
        from pytm import Finding

        if isinstance(obj, Finding):
            return obj.severity
        return ""

    @staticmethod
    def getFindingMitigations(obj: Any) -> str:
        from pytm import Finding

        if isinstance(obj, Finding):
            return obj.mitigations
        return ""

    @staticmethod
    def getFindingReferences(obj: Any) -> str:
        from pytm import Finding

        if isinstance(obj, Finding):
            return obj.references
        return ""

    @staticmethod
    def getFindingExample(obj: Any) -> str:
        from pytm import Finding

        if isinstance(obj, Finding):
            return obj.example
        return ""
