from cyberrisk_intel.db.models import Policy, ReviewRecord, Source
from cyberrisk_intel.services.review import set_review_status


def test_review_is_audited(session) -> None:
    source = Source(
        name="Official",
        url="https://example.test/source",
        publisher="Example",
        source_type="official",
        region="CN",
    )
    session.add(source)
    session.flush()
    policy = Policy(
        title="Test Policy",
        issuer="Example",
        summary="A sufficiently long summary.",
        source_id=source.id,
        review_status="pending_review",
    )
    session.add(policy)
    session.flush()
    set_review_status(session, "policy", policy.id, "published", comment="checked")
    session.flush()
    assert policy.review_status == "published"
    record = session.query(ReviewRecord).one()
    assert record.previous_status == "pending_review"
    assert record.comment == "checked"
