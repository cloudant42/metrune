-- Development tokens are re-created by the API only when METRUNE_ENV is not
-- production. This keeps fresh production databases free of known credentials
-- while allowing existing development databases to keep their local workflow.
DELETE FROM dashboard_tokens
WHERE token_hash = '78e35941c163d606f0a3f1820de4eae3a43381b5603df86772bdd11168d2e434';

DELETE FROM enrollment_tokens
WHERE token_hash = '18daf9c40bec25b9eadfaad2a5b487d38c61716c60000ff4f61e981ba1462c26';
