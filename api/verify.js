export default function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { password } = req.body || {};
  const correct = process.env.AAR_PASSWORD;

  if (!correct) {
    return res.status(500).json({ error: 'Server misconfigured' });
  }

  if (password === correct) {
    return res.status(200).json({ success: true });
  }

  return res.status(401).json({ success: false });
}
