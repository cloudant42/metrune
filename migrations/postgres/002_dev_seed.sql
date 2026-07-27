INSERT INTO organizations(id, name)
VALUES ('00000000-0000-0000-0000-000000000001', 'Acme Engineering')
ON CONFLICT (id) DO NOTHING;

-- Local dashboard token: met_dashboard_dev. Replace it outside local development.
INSERT INTO dashboard_tokens(id, organization_id, token_hash, name, role)
VALUES (
  '00000000-0000-0000-0000-000000000003',
  '00000000-0000-0000-0000-000000000001',
  '78e35941c163d606f0a3f1820de4eae3a43381b5603df86772bdd11168d2e434',
  'Local dashboard',
  'admin'
)
ON CONFLICT (id) DO NOTHING;

-- Local development token: met_enroll_dev. Replace it outside local development.
INSERT INTO enrollment_tokens(id, organization_id, token_hash, name, team_key)
VALUES (
  '00000000-0000-0000-0000-000000000002',
  '00000000-0000-0000-0000-000000000001',
  '18daf9c40bec25b9eadfaad2a5b487d38c61716c60000ff4f61e981ba1462c26',
  'Local development',
  'engineering'
)
ON CONFLICT (id) DO NOTHING;
