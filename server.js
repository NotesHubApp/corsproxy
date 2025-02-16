#!/usr/bin/env node

import express from 'express'
import proxy from './api/proxy.js'

const app = express()

app.all('*', (req, res) => {
  proxy(req, res)
})

const PORT = process.env.PORT || 5023

app.listen(PORT, function () {
  console.log(`Proxy server listening on port ${PORT}`)
})