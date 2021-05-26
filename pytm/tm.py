import sys
import os
import random
import json
import errno

from datetime import datetime
from collections import Counter, defaultdict
from itertools import combinations
from textwrap import indent
from collections.abc import Iterable
from pydal import DAL, Field
from functools import lru_cache
from shutil import rmtree

from .template_engine import SuperFormatter

from pytm.asset import Asset
from pytm.data import Data
from pytm.datastore import Datastore
from pytm.dataflow import Dataflow
from pytm.server import Server
from pytm.externalentity import ExternalEntity
from pytm.process import Process
from pytm.serverlessfunc import ServerlessFunc
from pytm.element import Element, varElement
from pytm.helper import (
    var,
    varString,
    varInt,
    varBool,
    varAction,
    Action,
    _match_responses,
    _sort,
    _apply_defaults,
    _get_elements_and_boundaries,
    _sort_elem,
    encode_threat_data,
    get_args,
    Logger,
    serialize,
    to_serializable,
    _describe_classes,
)

from pytm.boundary import Boundary
from pytm.actor import Actor


class varFindings(var):
    def __set__(self, instance, value):
        for i, e in enumerate(value):
            if not isinstance(e, Finding):
                raise ValueError(
                    "expecting a list of Findings, item number {} is a {}".format(
                        i, type(e)
                    )
                )
        super().__set__(instance, list(value))


class Threat:
    """Represents a possible threat"""

    id = varString("", required=True)
    description = varString("")
    condition = varString(
        "",
        doc="""a Python expression that should evaluate
to a boolean True or False""",
    )
    details = varString("")
    severity = varString("")
    mitigations = varString("")
    example = varString("")
    references = varString("")
    target = ()

    def __init__(self, **kwargs):
        self.id = kwargs["SID"]
        self.description = kwargs.get("description", "")
        self.condition = kwargs.get("condition", "True")
        target = kwargs.get("target", "Element")
        if not isinstance(target, str) and isinstance(target, Iterable):
            target = tuple(target)
        else:
            target = (target,)
        self.target = tuple(getattr(sys.modules[__name__], x) for x in target)
        self.details = kwargs.get("details", "")
        self.severity = kwargs.get("severity", "")
        self.mitigations = kwargs.get("mitigations", "")
        self.example = kwargs.get("example", "")
        self.references = kwargs.get("references", "")

    def _safeset(self, attr, value):
        try:
            setattr(self, attr, value)
        except ValueError:
            pass

    def __repr__(self):
        return "<{0}.{1}({2}) at {3}>".format(
            self.__module__, type(self).__name__, self.id, hex(id(self))
        )

    def __str__(self):
        return "{0}({1})".format(type(self).__name__, self.id)

    def apply(self, target):
        if not isinstance(target, self.target):
            return None
        return eval(self.condition)


class Finding:
    """Represents a Finding - the element in question
    and a description of the finding"""

    element = varElement(None, required=True, doc="Element this finding applies to")
    target = varString("", doc="Name of the element this finding applies to")
    description = varString("", required=True, doc="Threat description")
    details = varString("", required=True, doc="Threat details")
    severity = varString("", required=True, doc="Threat severity")
    mitigations = varString("", required=True, doc="Threat mitigations")
    example = varString("", required=True, doc="Threat example")
    id = varInt("", required=True, doc="Finding ID")
    threat_id = varString("", required=True, doc="Threat ID")
    references = varString("", required=True, doc="Threat references")
    condition = varString("", required=True, doc="Threat condition")
    response = varString(
        "",
        required=False,
        doc="""Describes how this threat matching this particular asset or dataflow is being handled.
Can be one of:
* mitigated - there were changes made in the modeled system to reduce the probability of this threat ocurring or the impact when it does,
* transferred - users of the system are required to mitigate this threat,
* avoided - this asset or dataflow is removed from the system,
* accepted - no action is taken as the probability and/or impact is very low
""",
    )
    cvss = varString("", required=False, doc="The CVSS score and/or vector")

    def __init__(
        self,
        *args,
        **kwargs,
    ):
        if args:
            element = args[0]
        else:
            element = kwargs.pop("element", Element("invalid"))

        self.target = element.name
        self.element = element
        attrs = [
            "description",
            "details",
            "severity",
            "mitigations",
            "example",
            "references",
            "condition",
        ]
        threat = kwargs.pop("threat", None)
        if threat:
            kwargs["threat_id"] = getattr(threat, "id")
            for a in attrs:
                # copy threat attrs into kwargs to allow to override them in next step
                kwargs[a] = getattr(threat, a)

        threat_id = kwargs.get("threat_id", None)
        for f in element.overrides:
            if f.threat_id != threat_id:
                continue
            for i in dir(f.__class__):
                attr = getattr(f.__class__, i)
                if (
                    i in ("element", "target")
                    or i.startswith("_")
                    or callable(attr)
                    or not isinstance(attr, var)
                ):
                    continue
                if f in attr.data:
                    kwargs[i] = attr.data[f]
            break

        for k, v in kwargs.items():
            setattr(self, k, v)

    def _safeset(self, attr, value):
        try:
            setattr(self, attr, value)
        except ValueError:
            pass

    def __repr__(self):
        return "<{0}.{1}({2}) at {3}>".format(
            self.__module__, type(self).__name__, self.id, hex(id(self))
        )

    def __str__(self):
        return f"{self.target}: {self.description}\n{self.details}\n{self.severity}"


class TM:
    """Describes the threat model administratively,
    and holds all details during a run"""

    _flows = []
    _elements = []
    _actors = []
    _assets = []
    _threats = []
    _boundaries = []
    _data = []
    _threatsExcluded = []
    _sf = None
    _duplicate_ignored_attrs = "name", "note", "order", "response", "responseTo"
    name = varString("", required=True, doc="Model name")
    description = varString("", required=True, doc="Model description")
    threatsFile = varString(
        os.path.dirname(__file__) + "/threatlib/threats.json",
        onSet=lambda i, v: i._init_threats(),
        doc="JSON file with custom threats",
    )
    isOrdered = varBool(False, doc="Automatically order all Dataflows")
    mergeResponses = varBool(False, doc="Merge response edges in DFDs")
    ignoreUnused = varBool(False, doc="Ignore elements not used in any Dataflow")
    findings = varFindings([], doc="threats found for elements of this model")
    onDuplicates = varAction(
        Action.NO_ACTION,
        doc="""How to handle duplicate Dataflow
with same properties, except name and notes""",
    )

    def __init__(self, name, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.name = name
        self._sf = SuperFormatter()
        self._add_threats()
        # make sure generated diagrams do not change, makes sense if they're commited
        random.seed(0)

    @classmethod
    def reset(cls):
        cls._flows = []
        cls._elements = []
        cls._actors = []
        cls._assets = []
        cls._threats = []
        cls._boundaries = []
        cls._data = []

    def _init_threats(self):
        TM._threats = []
        self._add_threats()

    def _add_threats(self):
        with open(self.threatsFile, "r", encoding="utf8") as threat_file:
            threats_json = json.load(threat_file)

        for i in threats_json:
            TM._threats.append(Threat(**i))

    def resolve(self):
        finding_count = 0
        findings = []
        elements = defaultdict(list)
        for e in TM._elements:
            if not e.inScope:
                continue

            override_ids = set(f.threat_id for f in e.overrides)
            # if element is a dataflow filter out overrides from source and sink
            # because they will be always applied there anyway
            try:
                override_ids -= set(
                    f.threat_id for f in e.source.overrides + e.sink.overrides
                )
            except AttributeError:
                pass

            for t in TM._threats:
                if not t.apply(e) and t.id not in override_ids:
                    continue

                finding_count += 1
                f = Finding(e, id=finding_count, threat=t)
                findings.append(f)
                elements[e].append(f)
        self.findings = findings
        for e, findings in elements.items():
            e.findings = findings

    def check(self):
        if self.description is None:
            raise ValueError(
                """Every threat model should have at least
a brief description of the system being modeled."""
            )

        TM._flows = _match_responses(_sort(TM._flows, self.isOrdered))

        self._check_duplicates(TM._flows)

        _apply_defaults(TM._flows, TM._data)

        for e in TM._elements:
            top = Counter(f.threat_id for f in e.overrides).most_common(1)
            if not top:
                continue
            threat_id, count = top[0]
            if count != 1:
                raise ValueError(
                    f"Finding {threat_id} have more than one override in {e}"
                )

        if self.ignoreUnused:
            TM._elements, TM._boundaries = _get_elements_and_boundaries(TM._flows)

        result = True
        for e in TM._elements:
            if not e.check():
                result = False

        if self.ignoreUnused:
            # cannot rely on user defined order if assets are re-used in multiple models
            TM._elements = _sort_elem(TM._elements)

        return result

    def _check_duplicates(self, flows):
        if self.onDuplicates == Action.NO_ACTION:
            return

        index = defaultdict(list)
        for e in flows:
            key = (e.source, e.sink)
            index[key].append(e)

        for flows in index.values():
            for left, right in combinations(flows, 2):
                left_attrs = left._attr_values()
                right_attrs = right._attr_values()
                for a in self._duplicate_ignored_attrs:
                    del left_attrs[a], right_attrs[a]
                if left_attrs != right_attrs:
                    continue
                if self.onDuplicates == Action.IGNORE:
                    right._is_drawn = True
                    continue

                raise ValueError(
                    "Duplicate Dataflow found between {} and {}: "
                    "{} is same as {}".format(
                        left.source,
                        left.sink,
                        left,
                        right,
                    )
                )

    def _dfd_template(self):
        return """digraph tm {{
    graph [
        fontname = Arial;
        fontsize = 14;
    ]
    node [
        fontname = Arial;
        fontsize = 14;
        rankdir = lr;
    ]
    edge [
        shape = none;
        arrowtail = onormal;
        fontname = Arial;
        fontsize = 12;
    ]
    labelloc = "t";
    fontsize = 20;
    nodesep = 1;

{edges}
}}"""

    def dfd(self, **kwargs):
        if "levels" in kwargs:
            levels = kwargs["levels"]
            if not isinstance(kwargs["levels"], Iterable):
                kwargs["levels"] = [levels]
            kwargs["levels"] = set(levels)

        edges = []
        # since boundaries can be nested sort them by level and start from top
        parents = set(b.inBoundary for b in TM._boundaries if b.inBoundary)

        # TODO boundaries should not be drawn if they don't contain elements matching requested levels
        # or contain only empty boundaries
        boundary_levels = defaultdict(set)
        max_level = 0
        for b in TM._boundaries:
            if b in parents:
                continue
            boundary_levels[0].add(b)
            for i, p in enumerate(b.parents()):
                i = i + 1
                boundary_levels[i].add(p)
                if i > max_level:
                    max_level = i

        for i in range(max_level, -1, -1):
            for b in sorted(boundary_levels[i], key=lambda b: b.name):
                edges.append(b.dfd(**kwargs))

        if self.mergeResponses:
            for e in TM._flows:
                if e.response is not None:
                    e.response._is_drawn = True
        kwargs["mergeResponses"] = self.mergeResponses
        for e in TM._elements:
            if not e._is_drawn and not isinstance(e, Boundary) and e.inBoundary is None:
                edges.append(e.dfd(**kwargs))

        return self._dfd_template().format(
            edges=indent("\n".join(filter(len, edges)), "    ")
        )

    def _seq_template(self):
        return """@startuml
{participants}

{messages}
@enduml"""

    def seq(self):
        participants = []
        for e in TM._elements:
            if isinstance(e, Actor):
                participants.append(
                    'actor {0} as "{1}"'.format(e._uniq_name(), e.display_name())
                )
            elif isinstance(e, Datastore):
                participants.append(
                    'database {0} as "{1}"'.format(e._uniq_name(), e.display_name())
                )
            elif not isinstance(e, Dataflow) and not isinstance(e, Boundary):
                participants.append(
                    'entity {0} as "{1}"'.format(e._uniq_name(), e.display_name())
                )

        messages = []
        for e in TM._flows:
            message = "{0} -> {1}: {2}".format(
                e.source._uniq_name(), e.sink._uniq_name(), e.display_name()
            )
            note = ""
            if e.note != "":
                note = "\nnote left\n{}\nend note".format(e.note)
            messages.append("{}{}".format(message, note))

        return self._seq_template().format(
            participants="\n".join(participants), messages="\n".join(messages)
        )

    def report(self, template_path):
        with open(template_path) as file:
            template = file.read()

        threats = encode_threat_data(TM._threats)
        findings = encode_threat_data(self.findings)

        data = {
            "tm": self,
            "dataflows": TM._flows,
            "threats": threats,
            "findings": findings,
            "elements": TM._elements,
            "assets": TM._assets,
            "actors": TM._actors,
            "boundaries": TM._boundaries,
            "data": TM._data,
        }

        return self._sf.format(template, **data)

    def process(self):
        self.check()
        result = get_args()
        Logger.basicConfig(level=Logger.INFO, format="%(levelname)s: %(message)s")

        if result.debug:
            Logger.setLevel(Logger.DEBUG)

        if result.seq is True:
            print(self.seq())

        if result.dfd is True:
            print(self.dfd(levels=(result.levels or set())))

        if (
            result.report is not None
            or result.json is not None
            or result.sqldump is not None
            or result.stale_days is not None
        ):
            self.resolve()

        if result.sqldump is not None:
            self.sqlDump(result.sqldump)

        if result.json:
            with open(result.json, "w", encoding="utf8") as f:
                json.dump(self, f, default=to_serializable)

        if result.report is not None:
            print(self.report(result.report))

        if result.exclude is not None:
            TM._threatsExcluded = result.exclude.split(",")

        if result.describe is not None:
            _describe_classes(result.describe.split())

        if result.list is True:
            [print("{} - {}".format(t.id, t.description)) for t in TM._threats]

        if result.stale_days is not None:
            print(self._stale(result.stale_days))

    def _stale(self, days):
        try:
            base_path = os.path.dirname(sys.argv[0])
            tm_mtime = datetime.fromtimestamp(
                os.stat(base_path + f"/{sys.argv[0]}").st_mtime
            )
        except os.error as err:
            sys.stderr.write(f"{sys.argv[0]} - {err}\n")
            sys.stderr.flush()
            return "[ERROR]"

        print(f"Checking for code {days} days older than this model.")

        for e in TM._elements:

            for src in e.sourceFiles:
                try:
                    src_mtime = datetime.fromtimestamp(
                        os.stat(base_path + f"/{src}").st_mtime
                    )
                except os.error as err:
                    sys.stderr.write(f"{sys.argv[0]} - {err}\n")
                    sys.stderr.flush()
                    continue

                age = (src_mtime - tm_mtime).days

                # source code is older than model by more than the speficied delta
                if (age) >= days:
                    print(f"This model is {age} days older than {base_path}/{src}.")
                elif age <= -days:
                    print(
                        f"Model script {sys.argv[0]}"
                        + " is only "
                        + str(-1 * age)
                        + " days newer than source code file "
                        + f"{base_path}/{src}"
                    )

        return ""

    def sqlDump(self, filename):
        try:
            rmtree("./sqldump")
            os.mkdir("./sqldump")
        except OSError as e:
            if e.errno != errno.ENOENT:
                raise
            else:
                os.mkdir("./sqldump")

        db = DAL("sqlite://" + filename, folder="sqldump")

        for klass in (
            Asset,
            Server,
            ExternalEntity,
            Dataflow,
            Datastore,
            Actor,
            Process,
            Boundary,
            TM,
            Threat,
            ServerlessFunc,
            Data,
            Finding,
        ):
            self.get_table(db, klass)

        for e in TM._threats + TM._data + TM._elements + self.findings + [self]:
            table = self.get_table(db, e.__class__)
            row = {}
            for k, v in serialize(e).items():
                if k == "id":
                    k = "SID"
                row[k] = ", ".join(str(i) for i in v) if isinstance(v, list) else v
            db[table].bulk_insert([row])

        db.close()

    @lru_cache(maxsize=None)
    def get_table(self, db, klass):
        name = klass.__name__
        fields = [
            Field("SID" if i == "id" else i)
            for i in dir(klass)
            if not i.startswith("_") and not callable(getattr(klass, i))
        ]
        return db.define_table(name, fields)
