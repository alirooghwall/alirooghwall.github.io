const express = require('express');
const app = express();

app.get('/', (req, res) => {
  res.send('Hello World from test server!');
});

app.listen(3000, () => {
  console.log('Test server running on port 3000');
});