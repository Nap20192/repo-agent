"""The ADK 2.9 dev-UI "builder" serializes every agent field (google.adk.cli.utils.graph_serialization) and FastAPI
then JSON-dumps the result: a raw dict of BaseAgents (our specialists) carries callbacks and breaks the page."""

from typing import Any

from google.adk.apps import App
from google.adk.cli.utils.graph_serialization import serialize_app_info
from pydantic import TypeAdapter

from tests.fakes import FakeRun, FakeVerifier, _scan


def test_builder_serialization_survives_specialists_and_callables():
    run = FakeRun()
    graph = _scan(run, specialists={"taint": FakeVerifier(name="taint", store=run)})
    info = serialize_app_info(App(name="fullscan", root_agent=graph))
    TypeAdapter(Any).dump_json(info)  # what the /dev/apps/{app}/build_graph endpoint does; must not raise
    assert info["root_agent"]["name"] == "scan_v2" and "verifier" in info["root_agent"]
