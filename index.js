#!/usr/bin/env node
'use strict';
const ldap = require('ldapjs')
const AWS = require('aws-sdk')
const crypto = require('crypto')
const hash = crypto.createHash('sha256')

hash.update(Array.from('0123456789').map(a=>Math.floor(Math.random() * 100)).join(''))
var secret = hash.digest('hex')

console.log ( 'using secret:', secret )

AWS.config.update({region: process.env.AWS_REGION})

var iam = new AWS.IAM({apiVersion: '2010-05-08'})

var server = ldap.createServer()

const domain = process.env.DOMAIN.split('.').map( dc => 'dc=' + dc.toLowerCase() ).join(',')

function authorize(req, res, next) {
    if (!req.connection.ldap.bindDN.equals('cn=root'))
        return next(new ldap.InsufficientAccessRightsError())

    return next()
}
  /*
server.bind('cn=root', function(req, res, next) {
    if (req.dn.toString() !== 'cn=root' || req.credentials !== secret)
        return next(new ldap.InvalidCredentialsError())

    res.end()
    return next()
}) */

function getUsers (req, res, next) {
  if (! process.env.GROUP) {
    return next()
  }
  if (!req.users) {
    req.users = {}
  }
  let opts = { GroupName: process.env.GROUP_NAME }
  if (req.marker) {
    opts.Marker = req.marker
  }
  iam.getGroup(opts, (err, data ) => {
    let uid = 68000 // more than 16bit max
    data.Users
      .sort((a,b) => a.CreateDate > b.CreateDate) //new users last, only a problem when someone gets deleted
      .forEach ( user => {
        let username = user.Path.replace(/\//g,'')
        if ( username.length ) {
          req.users[username] = {
            dn: 'cn=' + username + ',ou=users,' + domain,
            attributes: {
              cn: username,
              name: user.UserName,
              path: user.Path,
              uri: user.Arn,
              shell: '/bin/bash',
              homedirectory: '/home/' + username,
              uid: uid++, 
              gid: process.env.DEFAULT_GID || 500,
              objectclass: 'unixUser'
            }
          }
        }
      })
    if (data.IsTruncated) {
      req.marker = data.Marker
      getUsers (req, res, next)
    } else {
      next()
    }
  })
}

server.search(domain, getUsers, function(req, res, next) {
  if (!req.users) {
    return next(new ldap.InsufficientAccessRightsError())
  }
  Object.keys(req.users).forEach(function(k) {
    if (req.filter.matches(req.users[k].attributes))
      res.send(req.users[k])
  })

  res.end()
})
 
server.listen(process.env.PORT || 1389, function() {
  console.log('ldapjs listening at ' + server.url)
})
