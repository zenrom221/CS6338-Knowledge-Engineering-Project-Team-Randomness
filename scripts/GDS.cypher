// Project the CVE-Product graph
CALL gds.graph.project(
  'cve_product_graph',
  ['Vulnerability', 'Product'],
  { AFFECTS_PRODUCT: { orientation: 'UNDIRECTED' } }
);

// Louvain community detection
CALL gds.louvain.stream('cve_product_graph')
YIELD nodeId, communityId
RETURN communityId, collect(gds.util.asNode(nodeId).cveID)[0..5] AS sample_cves
ORDER BY size(collect(nodeId)) DESC
LIMIT 10;