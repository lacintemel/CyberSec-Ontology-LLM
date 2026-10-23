import requests
from neo4j import GraphDatabase

# 1. Bağlantı URI'sini 'bolt://' olarak güncelledik
NEO4J_URI = "bolt://127.0.0.1:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "Temel1975"  # Buraya kendi Neo4j şifreni yaz

STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

class STIXIngestor:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def process_stix_bundle(self, bundle):
        objects = bundle.get("objects", [])
        print(f"Toplam {len(objects)} STIX nesnesi işleniyor...")

        threat_actors = []
        malwares = []
        indicators = []
        relationships = []

        # 1. Verileri RAM'de gruplayalım
        for obj in objects:
            obj_type = obj.get("type")
            obj_id = obj.get("id")
            name = obj.get("name", "Bilinmeyen")

            if obj_type == "intrusion-set":
                threat_actors.append({"id": obj_id, "name": name})
            elif obj_type == "malware":
                malwares.append({"id": obj_id, "name": name})
            elif obj_type == "attack-pattern":
                indicators.append({"id": obj_id, "name": name})
            elif obj_type == "relationship":
                rel_type = obj.get("relationship_type").upper().replace("-", "_")
                relationships.append({
                    "source_id": obj.get("source_ref"),
                    "target_id": obj.get("target_ref"),
                    "rel_type": rel_type
                })

        # 2. Neo4j'ye Toplu (UNWIND) Veri Aktarımı
        with self.driver.session() as session:
            print("ThreatActor düğümleri aktarılıyor...")
            session.run("""
                UNWIND $batch AS row
                MERGE (t:ThreatActor {id: row.id}) SET t.name = row.name
            """, batch=threat_actors)

            print("Malware düğümleri aktarılıyor...")
            session.run("""
                UNWIND $batch AS row
                MERGE (m:Malware {id: row.id}) SET m.name = row.name
            """, batch=malwares)

            print("Indicator düğümleri aktarılıyor...")
            session.run("""
                UNWIND $batch AS row
                MERGE (i:Indicator {id: row.id}) SET i.name = row.name
            """, batch=indicators)

            print("İlişkiler bağlanıyor...")
            # İlişki tiplerini dinamik bağlamak için hafif bir döngü
            for rel in relationships:
                query = f"""
                MATCH (a {{id: $source_id}})
                MATCH (b {{id: $target_id}})
                MERGE (a)-[r:{rel['rel_type']}]->(b)
                """
                session.run(query, source_id=rel["source_id"], target_id=rel["target_id"])

if __name__ == "__main__":
    print("MITRE ATT&CK STIX verisi indiriliyor...")
    response = requests.get(STIX_URL)
    stix_data = response.json()

    ingestor = STIXIngestor(NEO4J_URI, NEO4J_USER, NEO4J_PASS)
    ingestor.process_stix_bundle(stix_data)
    ingestor.close()
    print("ETL Aktarımı Başarıyla Tamamlandı!")