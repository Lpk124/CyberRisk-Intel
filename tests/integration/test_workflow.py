from cyberrisk_intel.analytics.graph import neighborhood
from cyberrisk_intel.analytics.landscape import overview_metrics
from cyberrisk_intel.db.models import Policy
from cyberrisk_intel.retrieval.index import rebuild_index
from cyberrisk_intel.retrieval.search import hybrid_search
from cyberrisk_intel.services.report import build_report
from cyberrisk_intel.services.seed import seed_demo


def test_seed_index_search_graph_report(session) -> None:
    seed_demo(session)
    session.flush()
    first_metrics = overview_metrics(session)
    seed_demo(session)
    session.flush()
    assert overview_metrics(session)["events"] == first_metrics["events"]

    assert rebuild_index(session) > 0
    results = hybrid_search(session, "供应链")
    assert results
    assert all(result.entity_type for result in results)

    policy = session.query(Policy).first()
    graph = neighborhood(session, "policy", policy.id, depth=2)
    assert graph.number_of_nodes() >= 1

    report = build_report(session, "attack-vulnerability-trends")
    assert "公开样本不代表真实事件发生率" in report
    assert "数据快照" in report
