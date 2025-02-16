#!/usr/bin/env node

import express from 'express'
import proxy from './api/proxy.js'

const app = express()

app.all('*', (req, res) => {
  proxy(req, res)
})

app.set('port', process.env.PORT || 5023)

app.listen(app.get('port'), function () {
  console.log('Proxy server listening on port ' + app.get('port'))
})