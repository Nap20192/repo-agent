"""The ADK 2.9 dev-UI "builder" serializes the root node graph (google.adk.cli.utils.graph_serialization) and FastAPI
then JSON-dumps the result: the Workflow root must survive that (a raw dict of BaseAgents once broke the page)."""

from typing import Any

from google.adk.apps import App
from google.adk.cli.utils.graph_serialization import serialize_app_info
from pydantic import TypeAdapter

from tests.fakes import FakeRun, _workflow, fake_verifier_node


def test_builder_serialization_survives_specialists_and_callables():
    run = FakeRun()
    wf = _workflow(run, critic=fake_verifier_node(run, "critic"), model=fake_verifier_node(run, "model"))
    info = serialize_app_info(App(name="fullscan", root_agent=wf))
    TypeAdapter(Any).dump_json(info)  # what the /dev/apps/{app}/build_graph endpoint does; must not raise
    assert info["root_agent"]["name"] == "scan"
