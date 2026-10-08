"""Helpers to wire AirflowReadClient / AirflowAdapter to FAKE AIRFLOW (DEMO) in-process."""

from fastapi.testclient import TestClient

from adapters.airflow.adapter import AirflowAdapter
from adapters.airflow.client import AirflowReadClient, AirflowReadConfig
from demo.fake_airflow.app import create_app
from demo.fake_airflow.state import FakeAirflowState, load_scenario
from tests.factories import T0

HERO_DAG = "sales_etl"
HERO_RUN = "scheduled__2026-10-08T00:00:00+00:00"


def fake_client(state: FakeAirflowState) -> AirflowReadClient:
    http = TestClient(create_app(state), base_url="http://fake-airflow")
    return AirflowReadClient(AirflowReadConfig(base_url="http://fake-airflow"), http=http)


def hero(down: bool = False, demo: bool = False) -> tuple[AirflowAdapter, FakeAirflowState]:
    state = load_scenario("hero_transient_network", down=down)
    adapter = AirflowAdapter(fake_client(state), demo=demo, clock=lambda: T0.replace(day=9, hour=1))
    return adapter, state
