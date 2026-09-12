"""Domain consultant: skeleton extractors (pure), deterministic consult over a DomainMap, the DomainModeler stage."""

import json
from pathlib import Path

from scanner.adapter.domain import consult, extract
from scanner.app.pipeline_v3 import build_workflow
from scanner.core.domain import DomainMap, Entity, Rule
from tests.fakes import FakeRun, _run, fake_stage_node, fake_verifier_node, notes_of

IDOR = Path(__file__).resolve().parent.parent / "samples" / "08-idor-go"


def test_go_structs_sqlc_and_migrations(tmp_path):
    (tmp_path / "m.go").write_text('package m\n\ntype Order struct {\n\tID     string `json:"id" db:"id"`\n\tUserID string `json:"user_id" db:"user_id"`\n}\n')
    (tmp_path / "q.sql").write_text("-- name: GetOrder :one\nSELECT * FROM orders WHERE id = $1;\n")
    (tmp_path / "001.sql").write_text("CREATE TABLE invoices (\n  id serial,\n  account_id int,\n  total int\n);\n")
    sk = extract(tmp_path)
    ents = {e.name: e for e in sk.entities}
    assert ents["Order"].fields == ["ID", "UserID"] and ents["Order"].owner_field == "UserID" and ents["Order"].file == "m.go"
    assert ents["invoices"].owner_field == "account_id" and "GetOrder" in ents["Order"].queries


def test_django_sqlalchemy_prisma_mongoose(tmp_path):
    (tmp_path / "models.py").write_text("from django.db import models\nclass Post(models.Model):\n    title = models.CharField()\n    owner = models.ForeignKey(User)\n\nclass Tag(Base):\n    id = Column(Integer)\n    tenant_id = Column(Integer)\n")
    (tmp_path / "schema.prisma").write_text("model Invoice {\n  id Int\n  ownerId Int\n}\n")
    (tmp_path / "user.js").write_text('const MemoSchema = new Schema({ text: String, created_by: String });\nmongoose.model("Memo", MemoSchema);\n')
    ents = {e.name: e for e in extract(tmp_path).entities}
    assert ents["Post"].owner_field == "owner" and ents["Tag"].owner_field == "tenant_id"
    assert ents["Invoice"].owner_field == "ownerId" and ents["Memo"].owner_field == "created_by"


def test_guards_and_rule_candidates(tmp_path):
    (tmp_path / "v.py").write_text("@login_required\ndef dashboard(request):\n    pass\n")
    (tmp_path / "r.js").write_text('app.get("/admin", isAdmin, adminPage);\n')
    (tmp_path / "README.md").write_text("Orders are visible only to their owner.\nAnyone can list products.\n")
    sk = extract(tmp_path)
    assert [(g.name, g.file, g.wraps) for g in sk.guards] == [("isAdmin", "r.js", "adminPage"), ("login_required", "v.py", "dashboard")]
    assert [(c.file, c.line) for c in sk.rule_candidates] == [("README.md", 1)]


def test_idor_sample_flags_handler_without_owner_check():
    sk = extract(IDOR)
    assert {e.name: e.owner_field for e in sk.entities} == {"Order": "UserID"}
    texts = [c.text for c in sk.rule_candidates]
    assert any("getOrder" in t and "Order" in t and "UserID" in t for t in texts)
    assert not any("getMyOrder" in t for t in texts)  # the safe neighbour compares order.UserID


def test_consult_over_map():
    m = DomainMap(entities=[Entity(name="Order", fields=["ID", "UserID"], owner_field="UserID", symbol="Order", file="main.go", line=9)],
                  rules=[Rule(id="r1", statement="Order is visible only to Order.UserID", entity="Order", symbol="getMyOrder")])
    out = consult(m, "who may read an Order?")
    assert out["ref"] == "domain:Order" and out["entity"]["owner_field"] == "UserID" and out["rules"][0]["ref"] == "domain:r1"
    assert consult(m, "r1")["rules"][0]["statement"].startswith("Order is visible")
    assert consult(m, "Unicorn")["status"] == "error"


def test_domain_stage_between_architect_and_threat_modeler(tmp_path):
    (tmp_path / "m.go").write_text('package m\ntype Order struct {\n\tUserID string `db:"user_id"`\n}\n')
    run = FakeRun()
    arch = fake_stage_node(run, "architect", {"entities": [{"name": "orders"}]})
    dm = fake_stage_node(run, "domain_map", {"entities": [{"name": "Order", "owner_field": "UserID"}],
                                                "rules": [{"id": "r1", "statement": "s", "entity": "Order", "symbol": "getMyOrder"}]})
    tm = fake_stage_node(run, "threat_model", {"intent": "production", "threats": []})  # notes keyed by artifact name
    wf = build_workflow(store=run, target=str(tmp_path), verifier=fake_verifier_node(run), has_anchor=lambda i: run.anchor(i) is not None,
                        has_symbol=lambda s: s == "getMyOrder", entry_points_fn=list,  # grounding keeps the rule
                        architect=arch, domain_modeler=dm, threat_modeler=tm, max_rounds=1, max_parallel=1)
    _run(wf)
    seen = {ref: json.loads(t[5:]) for t, ref in notes_of(run) if t.startswith("seen:")}
    assert seen["domain_map"]["architecture_model"]["entities"] == [{"name": "orders"}]
    assert seen["domain_map"]["skeleton"]["entities"][0]["owner_field"] == "UserID"
    assert run.artifact("domain_map")["rules"][0]["id"] == "r1"
    assert seen["threat_model"]["domain_map"]["rules"][0]["symbol"] == "getMyOrder"
