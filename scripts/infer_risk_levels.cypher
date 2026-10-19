
MERGE (:RiskLevel {name: 'CRITICAL'})
MERGE (:RiskLevel {name: 'HIGH'})
MERGE (:RiskLevel {name: 'MEDIUM'})
MERGE (:RiskLevel {name: 'LOW'});

MATCH (:Vulnerability)-[r:INFERRED_RISK_LEVEL]->(:RiskLevel)
DELETE r;

MATCH (v:Vulnerability)
WHERE v.cvssScore IS NOT NULL
  AND v.cvssScore > 0
  AND v.cvssScore <= 10

WITH v,
     CASE
       WHEN v.cvssScore >= 9.0 THEN 'CRITICAL'
       WHEN v.cvssScore >= 7.0 THEN 'HIGH'
       WHEN v.cvssScore >= 4.0 THEN 'MEDIUM'
       ELSE 'LOW'
     END AS inferredLevel

MATCH (r:RiskLevel {name: inferredLevel})
MERGE (v)-[:INFERRED_RISK_LEVEL]->(r);
