from pathlib import Path

from rdflib import Graph


ontology_file = Path(__file__).parent / "ontology/uco/master/uco.ttl"

g = Graph()
g.parse(ontology_file, format="turtle")

print(f"Toplam Üçlü (Triple) Sayısı: {len(g)}")

# Tüm sınıfları (Classes) listeleme
for s, p, o in g.triples((None, None, None)):
    if "owl#Class" in str(o):
        print(s)
