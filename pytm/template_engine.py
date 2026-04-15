# shamelessly lifted from https://makina-corpus.com/blog/metier/2016/the-worlds-simplest-python-template-engine
# but modified to include support to call methods which return lists, to call external utility methods, use
# if operator with methods and added a not operator.

from __future__ import annotations

import string
from collections.abc import Iterable
from functools import lru_cache
from typing import Any, Callable


class SuperFormatter(string.Formatter):
    """Lightweight formatter with helpers for reports and templates."""

    def format_field(
        self, value: Any, format_spec: str
    ) -> Any:  # noqa: D401 - same semantics as base
        if not format_spec:
            return super().format_field(value, format_spec)

        if format_spec.startswith("repeat"):
            return self._format_repeat(value, format_spec)

        if format_spec.startswith("call:"):
            return self._format_call(value, format_spec)

        if format_spec.startswith("if") or format_spec.startswith("not"):
            return self._format_conditional(value, format_spec)

        return super().format_field(value, format_spec)

    def _format_repeat(self, value: Any, format_spec: str) -> str:
        """Handle the custom repeat operator."""
        template = format_spec.partition(":")[2]
        if isinstance(value, dict):
            iterable: Iterable[Any] = value.items()
        elif isinstance(value, Iterable) and not isinstance(value, (str, bytes)):
            iterable = value
        else:
            iterable = []
        return "".join(self.format(template, item=item) for item in iterable)

    def _format_call(self, value: Any, format_spec: str) -> Any:
        """Evaluate callable values or report utility helpers."""
        _, _, remainder = format_spec.partition(":")

        if callable(value):
            result = value()
            template = remainder
        else:
            method_name, _, template = remainder.partition(":")
            result = self.call_util_method(method_name, value)

        if isinstance(result, list) and template:
            return "".join(self.format(template, item=item) for item in result)
        return result

    def _format_conditional(self, value: Any, format_spec: str) -> str:
        """Render content conditionally based on truthiness of *value*."""
        _, _, template = format_spec.partition(":")
        result = value() if callable(value) else value
        if format_spec.startswith("if"):
            return template if result else ""
        return template if not result else ""

    def call_util_method(self, method_name: str, obj: Any) -> Any:
        """Invoke a helper method from :mod:`pytm.report_util`."""
        method = self._resolve_report_method(method_name)
        return method(obj)

    @staticmethod
    @lru_cache(maxsize=None)
    def _resolve_report_method(method_name: str) -> Callable[[Any], Any]:
        from pytm.report_util import ReportUtils

        return getattr(ReportUtils, method_name)
