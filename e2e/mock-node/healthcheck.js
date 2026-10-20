require('http').get('http://localhost:8545/health', (res) => {
  let data = '';
  res.on('data', (chunk) => { data += chunk; });
  res.on('end', () => {
    process.exit(res.statusCode === 200 ? 0 : 1);
  });
}).on('error', () => {
  process.exit(1);
});
