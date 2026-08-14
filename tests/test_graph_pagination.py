import pytest

from himmelblau_mdm.clients.graph import GraphClient


@pytest.mark.asyncio
async def test_graph_pagination_collects_every_page():
    graph = object.__new__(GraphClient)
    responses = {
        "start": {"value": [{"id": "one"}], "@odata.nextLink": "next"},
        "next": {"value": [{"id": "two"}]},
    }

    async def request_json(_method, path, **_kwargs):
        return responses[path]

    graph.request_json = request_json
    assert await graph.collect("start") == [{"id": "one"}, {"id": "two"}]
