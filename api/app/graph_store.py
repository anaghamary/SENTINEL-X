from neo4j import GraphDatabase

from app.config import NEO4J_DATABASE, NEO4J_PASSWORD, NEO4J_URI, NEO4J_USERNAME


class GraphStore:
    def __init__(self) -> None:
        self._driver = None
        if NEO4J_URI:
            if not NEO4J_PASSWORD:
                raise RuntimeError("NEO4J_PASSWORD is required when NEO4J_URI is configured")
            self._driver = GraphDatabase.driver(
                NEO4J_URI,
                auth=(NEO4J_USERNAME, NEO4J_PASSWORD),
                connection_timeout=5,
                max_connection_lifetime=300,
            )

    @property
    def enabled(self) -> bool:
        return self._driver is not None

    def verify(self) -> None:
        if self._driver is None:
            return
        self._driver.verify_connectivity()

    def close(self) -> None:
        if self._driver is not None:
            self._driver.close()
            self._driver = None

    def ensure_schema(self) -> None:
        if self._driver is None:
            return
        with self._driver.session(database=NEO4J_DATABASE) as session:
            session.run(
                "CREATE CONSTRAINT sentinel_case_id IF NOT EXISTS "
                "FOR (c:Case) REQUIRE c.case_id IS UNIQUE"
            ).consume()
            session.run(
                "CREATE CONSTRAINT sentinel_entity_id IF NOT EXISTS "
                "FOR (e:Entity) REQUIRE e.entity_id IS UNIQUE"
            ).consume()

    def upsert_case(self, case_id: int, case_number: str, title: str) -> None:
        if self._driver is None:
            return
        with self._driver.session(database=NEO4J_DATABASE) as session:
            session.run(
                """
                MERGE (c:Case {case_id: $case_id})
                SET c.case_number = $case_number, c.title = $title
                """,
                case_id=case_id,
                case_number=case_number,
                title=title,
            ).consume()

    def upsert_case_entity(
        self,
        case_id: int,
        case_number: str,
        case_title: str,
        entity_id: int,
        entity_type: str,
        display_value: str,
        link_id: int,
        link_status: str,
        reason: str,
    ) -> None:
        if self._driver is None:
            return
        with self._driver.session(database=NEO4J_DATABASE) as session:
            session.run(
                """
                MERGE (c:Case {case_id: $case_id})
                SET c.case_number = $case_number, c.title = $case_title
                MERGE (e:Entity {entity_id: $entity_id})
                SET e.kind = $entity_type, e.value = $display_value
                MERGE (c)-[r:HAS_ENTITY {link_id: $link_id}]->(e)
                SET r.status = $link_status, r.reason = $reason
                """,
                case_id=case_id,
                case_number=case_number,
                case_title=case_title,
                entity_id=entity_id,
                entity_type=entity_type,
                display_value=display_value,
                link_id=link_id,
                link_status=link_status,
                reason=reason,
            ).consume()

    def set_link_status(self, link_id: int, status: str) -> None:
        if self._driver is None:
            return
        with self._driver.session(database=NEO4J_DATABASE) as session:
            session.run(
                """
                MATCH ()-[r:HAS_ENTITY {link_id: $link_id}]->()
                SET r.status = $status
                """,
                link_id=link_id,
                status=status,
            ).consume()

    def case_graph(self, case_ids: list[int]) -> dict:
        if self._driver is None:
            return {"nodes": [], "edges": []}
        with self._driver.session(database=NEO4J_DATABASE) as session:
            result = session.run(
                """
                MATCH (c:Case)
                WHERE c.case_id IN $case_ids
                OPTIONAL MATCH (c)-[r:HAS_ENTITY]->(e:Entity)
                RETURN c, r, e
                """,
                case_ids=case_ids,
            )
            cases: dict[int, dict] = {}
            entities: dict[int, dict] = {}
            edges: dict[int, dict] = {}
            for row in result:
                case = dict(row["c"])
                case_id = int(case["case_id"])
                cases[case_id] = {
                    "data": {
                        "id": f"case-{case_id}",
                        "label": case["case_number"],
                        "kind": "case",
                        "title": case["title"],
                    }
                }
                if row["e"] is None or row["r"] is None:
                    continue
                entity = dict(row["e"])
                relationship = dict(row["r"])
                entity_id = int(entity["entity_id"])
                link_id = int(relationship["link_id"])
                entities[entity_id] = {
                    "data": {
                        "id": f"entity-{entity_id}",
                        "label": entity["value"],
                        "kind": entity["kind"],
                    }
                }
                edges[link_id] = {
                    "data": {
                        "id": f"link-{link_id}",
                        "source": f"case-{case_id}",
                        "target": f"entity-{entity_id}",
                        "label": str(relationship["status"]).lower(),
                        "status": relationship["status"],
                        "link_id": link_id,
                        "reason": relationship.get("reason", ""),
                    }
                }
            return {"nodes": list(cases.values()) + list(entities.values()), "edges": list(edges.values())}


graph_store = GraphStore()
